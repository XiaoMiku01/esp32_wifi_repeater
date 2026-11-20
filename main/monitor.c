/*
 * 流量记录与拦截，见 monitor.h
 *
 * 并发：所有表由 s_lock 保护。转发钩子运行在 lwIP tcpip 线程，持锁时间只做 O(1) 查表；
 * HTTP 读取时持锁把数据序列化到缓冲区（不在锁内做网络发送）。
 * 大表放 PSRAM；连接表用哈希桶（内部 RAM）定位。
 */
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_cpu.h"
#include "esp_clk_tree.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "lwip/pbuf.h"
#include "lwip/ip4.h"
#include "lwip/inet.h"
#include "lwip/prot/ip.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/inet_chksum.h"
#include "lwip/tcpip.h"
#include "monitor.h"

static const char *TAG = "monitor";

#define CLIENT_MAX      32
#define FLOW_MAX        256
#define FLOW_BUCKETS    512             /* 2 的幂 */
#define DNSLOG_MAX      400
#define IPMAP_MAX       512
#define BLOCKIP_MAX     256
#define ASM_SLOTS       4
#define ASM_CAP         2048            /* TLS ClientHello 重组上限 */
#define LIVE_BUF        (192 * 1024)    /* 256 条连接 × 含 URL 的 JSON */
#define URL_MAX         200
#define NVS_NS          "monblock"      /* 旧版本保存黑名单的命名空间，开机时清除 */

typedef struct {
    bool used, online, has_mac;
    uint8_t mac[6];
    uint32_t ip;                        /* 网络字节序 */
    char host[33];
    uint32_t first, last_join, last_seen;
    uint64_t up, down, last_up, last_down;
    uint32_t rup, rdown, dns;
} client_t;

typedef struct {
    bool used, blocked, closing, inspected, seq_valid;
    uint8_t proto, dom_src;             /* dom_src：0 无，1 DNS，2 SNI，3 HTTP Host */
    int8_t asm_slot;
    int16_t next;
    uint16_t cport, rport;              /* 主机字节序 */
    uint32_t id, cip, rip;              /* IP 为网络字节序 */
    uint32_t first, last;
    uint64_t up, down, last_up, last_down;
    uint32_t rup, rdown;
    uint32_t c_next, c_ack;             /* 用于构造发给客户端的 RST */
    char domain[MON_NAME_MAX + 1];
    char method[8];                     /* HTTP（80 端口）最近一次请求 */
    char url[URL_MAX + 1];
    uint16_t reqs;                      /* 该连接上的 HTTP 请求数 */
} flow_t;

typedef struct {
    uint32_t id, t, cip;
    uint16_t qtype;
    uint8_t res, nans;
    uint32_t ans[4];
    char name[MON_NAME_MAX + 1];
} dnslog_t;

typedef struct {
    uint32_t ip, t;
    char name[MON_NAME_MAX + 1];
} ipmap_t;

typedef struct {
    char name[MON_NAME_MAX + 1];
} block_name_t;

typedef struct {
    int16_t flow;
    uint16_t len, need;
    uint8_t segs;
    uint8_t buf[ASM_CAP];
} asm_t;

static SemaphoreHandle_t s_lock;
static bool s_ready;
static volatile bool s_enabled = true;
static uint32_t s_ap_net, s_ap_mask;
static struct netif *s_ap_lwip;

static client_t *s_clients;
static flow_t *s_flows;
static int16_t s_buckets[FLOW_BUCKETS];
static uint32_t s_flow_seq;
static dnslog_t *s_dns;
static uint32_t s_dns_seq;
static ipmap_t *s_ipmap;
static uint32_t s_blockip[BLOCKIP_MAX];
static int s_n_blockip;
static block_name_t s_block[MON_BLOCK_MAX];
static uint32_t s_block_hits[MON_BLOCK_MAX];
static int s_n_block;
static asm_t *s_asm;
static uint8_t s_scratch[ASM_CAP];

/* 性能统计。周期计数器每个核各一个，tcpip 线程未绑核，
 * 跨核迁移的样本无效（会出现接近 2^32 的差值），按核号比较后丢弃 */
static uint64_t s_perf_pkts, s_perf_cycles, s_perf_last_pkts, s_perf_samples;
static uint32_t s_perf_max, s_perf_pps;

static inline uint32_t now_s(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000000);
}

static void *ps_calloc(size_t n, size_t sz)
{
    void *p = heap_caps_calloc(n, sz, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    return p ? p : calloc(n, sz);
}

static void ip_str(uint32_t ip_be, char *out)
{
    const uint8_t *b = (const uint8_t *)&ip_be;
    sprintf(out, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

/* 域名规范化：小写，只保留 [a-z0-9-_.]，去结尾点；非法返回 false */
static bool clean_name(const char *in, size_t n, char *out)
{
    while (n && in[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > MON_NAME_MAX) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        char c = (char)tolower((unsigned char)in[i]);
        if (!(isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.')) {
            return false;
        }
        out[i] = c;
    }
    out[n] = '\0';
    return out[0] != '.';
}

/* 名称是否命中黑名单（等于或为其子域名），返回下标或 -1；持锁调用 */
static int block_index(const char *name)
{
    size_t nl = strlen(name);
    for (int i = 0; i < s_n_block; i++) {
        size_t bl = strlen(s_block[i].name);
        if (nl == bl && strcmp(name, s_block[i].name) == 0) {
            return i;
        }
        if (nl > bl && name[nl - bl - 1] == '.' && strcmp(name + nl - bl, s_block[i].name) == 0) {
            return i;
        }
    }
    return -1;
}

/* ---------- IP -> 域名 ---------- */

static const char *ipmap_get(uint32_t ip)
{
    for (int i = 0; i < IPMAP_MAX; i++) {
        if (s_ipmap[i].ip == ip && s_ipmap[i].name[0]) {
            return s_ipmap[i].name;
        }
    }
    return NULL;
}

static void ipmap_set(uint32_t ip, const char *name)
{
    int slot = 0;
    for (int i = 0; i < IPMAP_MAX; i++) {
        if (s_ipmap[i].ip == ip) {
            slot = i;
            break;
        }
        if (s_ipmap[i].t < s_ipmap[slot].t) {
            slot = i;
        }
    }
    s_ipmap[slot].ip = ip;
    s_ipmap[slot].t = now_s() + 1;      /* +1：区分从未使用的 0 */
    strlcpy(s_ipmap[slot].name, name, sizeof(s_ipmap[slot].name));
}

/* ---------- 黑名单 IP 集合 ---------- */

static bool blockip_has(uint32_t ip)
{
    for (int i = 0; i < s_n_blockip; i++) {
        if (s_blockip[i] == ip) {
            return true;
        }
    }
    return false;
}

static void blockip_rebuild(void)
{
    s_n_blockip = 0;
    for (int i = 0; i < IPMAP_MAX && s_n_blockip < BLOCKIP_MAX; i++) {
        if (s_ipmap[i].name[0] && block_index(s_ipmap[i].name) >= 0 && !blockip_has(s_ipmap[i].ip)) {
            s_blockip[s_n_blockip++] = s_ipmap[i].ip;
        }
    }
}

/* ---------- 客户端 ---------- */

static client_t *client_alloc(void)
{
    client_t *victim = NULL;
    for (int i = 0; i < CLIENT_MAX; i++) {
        if (!s_clients[i].used) {
            victim = &s_clients[i];
            break;
        }
        if (!s_clients[i].online && (!victim || s_clients[i].last_seen < victim->last_seen)) {
            victim = &s_clients[i];
        }
    }
    if (victim) {
        memset(victim, 0, sizeof(*victim));
        victim->used = true;
        victim->first = victim->last_seen = now_s();
    }
    return victim;
}

static client_t *client_by_ip(uint32_t ip, bool create)
{
    for (int i = 0; i < CLIENT_MAX; i++) {
        if (s_clients[i].used && s_clients[i].ip == ip) {
            return &s_clients[i];
        }
    }
    if (!create) {
        return NULL;
    }
    client_t *c = client_alloc();
    if (c) {
        c->ip = ip;
        c->online = true;
    }
    return c;
}

static client_t *client_by_mac(const uint8_t mac[6], bool create)
{
    for (int i = 0; i < CLIENT_MAX; i++) {
        if (s_clients[i].used && s_clients[i].has_mac && memcmp(s_clients[i].mac, mac, 6) == 0) {
            return &s_clients[i];
        }
    }
    if (!create) {
        return NULL;
    }
    client_t *c = client_alloc();
    if (c) {
        memcpy(c->mac, mac, 6);
        c->has_mac = true;
    }
    return c;
}

void monitor_on_join(const uint8_t mac[6])
{
    if (!s_ready) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_t *c = client_by_mac(mac, true);
    if (c) {
        c->online = true;
        c->last_join = c->last_seen = now_s();
    }
    xSemaphoreGive(s_lock);
}

void monitor_on_leave(const uint8_t mac[6])
{
    if (!s_ready) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_t *c = client_by_mac(mac, false);
    if (c) {
        c->online = false;
        c->last_seen = now_s();
        c->rup = c->rdown = 0;
    }
    xSemaphoreGive(s_lock);
}

void monitor_on_ip(const uint8_t mac[6], uint32_t ip, const char *hostname)
{
    if (!s_ready) return;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    client_t *c = client_by_mac(mac, true);
    if (c) {
        /* 先有流量后有 DHCP 事件时，合并按 IP 建立的条目 */
        for (int i = 0; i < CLIENT_MAX; i++) {
            client_t *o = &s_clients[i];
            if (o != c && o->used && o->ip == ip) {
                if (!o->has_mac) {
                    c->up += o->up; c->down += o->down; c->dns += o->dns;
                    c->last_up += o->last_up; c->last_down += o->last_down;
                    if (o->first < c->first) c->first = o->first;
                    o->used = false;
                } else {
                    o->ip = 0;      /* IP 换给了新设备 */
                }
            }
        }
        c->ip = ip;
        c->online = true;
        c->last_seen = now_s();
        if (hostname && hostname[0]) {
            size_t o = 0;
            for (const char *p = hostname; *p && o < sizeof(c->host) - 1; p++) {
                unsigned char ch = (unsigned char)*p;
                c->host[o++] = (isalnum(ch) || ch == '-' || ch == '_' || ch == '.') ? ch : '_';
            }
            c->host[o] = '\0';
        }
    }
    xSemaphoreGive(s_lock);
}

/* ---------- 连接表 ---------- */

static inline uint32_t flow_hash(uint32_t cip, uint32_t rip, uint16_t cp, uint16_t rp, uint8_t pr)
{
    uint32_t h = cip * 2654435761u ^ rip * 2246822519u ^ (((uint32_t)cp << 16) | rp) * 3266489917u ^ pr;
    return (h ^ (h >> 15)) & (FLOW_BUCKETS - 1);
}

static flow_t *flow_find(uint32_t cip, uint32_t rip, uint16_t cp, uint16_t rp, uint8_t pr)
{
    for (int16_t i = s_buckets[flow_hash(cip, rip, cp, rp, pr)]; i >= 0; i = s_flows[i].next) {
        flow_t *f = &s_flows[i];
        if (f->cip == cip && f->rip == rip && f->cport == cp && f->rport == rp && f->proto == pr) {
            return f;
        }
    }
    return NULL;
}

static void flow_free(int idx)
{
    flow_t *f = &s_flows[idx];
    int16_t *pp = &s_buckets[flow_hash(f->cip, f->rip, f->cport, f->rport, f->proto)];
    while (*pp >= 0) {
        if (*pp == idx) {
            *pp = f->next;
            break;
        }
        pp = &s_flows[*pp].next;
    }
    if (f->asm_slot >= 0) {
        s_asm[f->asm_slot].flow = -1;
    }
    f->used = false;
}

static flow_t *flow_create(uint32_t cip, uint32_t rip, uint16_t cp, uint16_t rp, uint8_t pr)
{
    int slot = -1, oldest = -1;
    for (int i = 0; i < FLOW_MAX; i++) {
        if (!s_flows[i].used) {
            slot = i;
            break;
        }
        /* 表满时优先淘汰已关闭的，其次最久未活动的 */
        if (oldest < 0 || (s_flows[i].closing && !s_flows[oldest].closing) ||
            (s_flows[i].closing == s_flows[oldest].closing && s_flows[i].last < s_flows[oldest].last)) {
            oldest = i;
        }
    }
    if (slot < 0) {
        slot = oldest;
        flow_free(slot);
    }
    flow_t *f = &s_flows[slot];
    memset(f, 0, sizeof(*f));
    f->used = true;
    f->asm_slot = -1;
    f->id = ++s_flow_seq;
    f->cip = cip; f->rip = rip; f->cport = cp; f->rport = rp; f->proto = pr;
    f->first = f->last = now_s();
    uint32_t h = flow_hash(cip, rip, cp, rp, pr);
    f->next = s_buckets[h];
    s_buckets[h] = (int16_t)slot;
    return f;
}

/* ---------- RST ---------- */

typedef struct {
    uint32_t cip, rip, seq, ack;
    uint16_t cport, rport;
} rst_t;

static void send_rst_cb(void *arg)
{
    rst_t *r = arg;
    struct pbuf *p = pbuf_alloc(PBUF_IP, TCP_HLEN, PBUF_RAM);
    if (p) {
        struct tcp_hdr *th = (struct tcp_hdr *)p->payload;
        memset(th, 0, TCP_HLEN);
        th->src = lwip_htons(r->rport);
        th->dest = lwip_htons(r->cport);
        th->seqno = lwip_htonl(r->seq);
        th->ackno = lwip_htonl(r->ack);
        TCPH_HDRLEN_FLAGS_SET(th, 5, TCP_RST | TCP_ACK);
        ip4_addr_t src = { .addr = r->rip }, dst = { .addr = r->cip };
        ip_addr_t s4 = IPADDR4_INIT(r->rip), d4 = IPADDR4_INIT(r->cip);
        th->chksum = ip_chksum_pseudo(p, IP_PROTO_TCP, p->tot_len, &s4, &d4);
        ip4_output_if(p, &src, &dst, 64, 0, IP_PROTO_TCP, s_ap_lwip);
        pbuf_free(p);
    }
    free(r);
}

/* 向客户端发 RST 断开 TCP 连接（远端发来的包随后被丢弃）；持锁调用 */
static void queue_rst(flow_t *f)
{
    if (f->proto != IP_PROTO_TCP || !f->seq_valid || f->closing || !s_ap_lwip) {
        return;
    }
    rst_t *r = malloc(sizeof(*r));
    if (!r) return;
    *r = (rst_t) { .cip = f->cip, .rip = f->rip, .cport = f->cport, .rport = f->rport,
                   .seq = f->c_ack, .ack = f->c_next };
    if (tcpip_try_callback(send_rst_cb, r) != ERR_OK) {
        free(r);
        return;
    }
    f->closing = true;
}

static void mark_blocked(flow_t *f)
{
    if (f->blocked) return;
    f->blocked = true;
    int bi = f->domain[0] ? block_index(f->domain) : -1;
    if (bi >= 0) s_block_hits[bi]++;
    queue_rst(f);
}

/* ---------- 载荷识别：TLS SNI / HTTP Host ---------- */

/* 0 找到，1 数据不够，-1 不是 ClientHello 或无 SNI */
static int parse_sni(const uint8_t *d, size_t n, char *out)
{
    if (n < 6) return 1;
    if (d[0] != 0x16 || d[5] != 0x01) return -1;
    size_t p = 5 + 4 + 2 + 32;
    if (p + 1 > n) return 1;
    p += 1 + d[p];                                  /* session id */
    if (p + 2 > n) return 1;
    p += 2 + ((d[p] << 8) | d[p + 1]);              /* cipher suites */
    if (p + 1 > n) return 1;
    p += 1 + d[p];                                  /* compression */
    if (p + 2 > n) return 1;
    size_t end = p + 2 + ((d[p] << 8) | d[p + 1]);
    p += 2;
    while (p + 4 <= end) {
        if (p + 4 > n) return 1;
        uint16_t type = (d[p] << 8) | d[p + 1], len = (d[p + 2] << 8) | d[p + 3];
        if (type == 0) {
            size_t q = p + 4 + 2;
            if (q + 3 > n) return 1;
            if (d[q] != 0) return -1;
            size_t nl = (d[q + 1] << 8) | d[q + 2];
            q += 3;
            if (q + nl > n) return 1;
            return clean_name((const char *)d + q, nl, out) ? 0 : -1;
        }
        p += 4 + len;
    }
    return p > n ? 1 : -1;
}

static bool parse_host(const uint8_t *d, size_t n, char *out)
{
    for (size_t i = 0; i + 7 < n; i++) {
        if (d[i] == '\n' && strncasecmp((const char *)d + i + 1, "host:", 5) == 0) {
            size_t s = i + 6;
            while (s < n && (d[s] == ' ' || d[s] == '\t')) s++;
            size_t e = s;
            while (e < n && d[e] != '\r' && d[e] != '\n' && d[e] != ':') e++;
            return clean_name((const char *)d + s, e - s, out);
        }
    }
    return false;
}

/* ---------- HTTP 请求行 -> 完整 URL ---------- */

static const char *const s_http_methods[] = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", NULL
};

/* 数据以 HTTP 方法开头则返回方法长度（含空格），否则 0 */
static int http_method_len(const uint8_t *d, size_t n)
{
    for (int i = 0; s_http_methods[i]; i++) {
        size_t l = strlen(s_http_methods[i]);
        if (n >= l && memcmp(d, s_http_methods[i], l) == 0) {
            return (int)l;
        }
    }
    return 0;
}

/* 追加到 URL：保留可见 ASCII，空白、非 ASCII、引号与反斜杠转成 %XX（JSON 安全）；返回是否截断 */
static bool url_append(char *out, size_t cap, size_t *o, const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c > 0x20 && c < 0x7f && c != '"' && c != '\\') {
            if (*o + 1 >= cap) return true;
            out[(*o)++] = (char)c;
        } else {
            if (*o + 3 >= cap) return true;
            *o += snprintf(out + *o, cap - *o, "%%%02X", c);
        }
    }
    out[*o] = '\0';
    return false;
}

/* 解析 HTTP 请求的首行与 Host 头，得到方法与完整 URL（http://host/path?query）。
 * 请求行须在本段内完整；Host 头缺失时用 "?" 代替；超长 URL 以 "..." 结尾 */
static bool parse_http_req(const uint8_t *d, size_t n, char *method, size_t mcap, char *url, size_t ucap)
{
    int ml = http_method_len(d, n);
    if (!ml || (size_t)ml > mcap) {
        return false;
    }
    memcpy(method, d, ml - 1);
    method[ml - 1] = '\0';
    size_t le = ml;
    while (le < n && d[le] != '\r' && d[le] != '\n') le++;
    if (le >= n) {
        return false;                               /* 请求行不完整 */
    }
    size_t ts = ml, te = ts;
    while (te < le && d[te] != ' ') te++;
    if (te == ts) {
        return false;
    }
    const char *target = (const char *)d + ts;
    size_t tlen = te - ts;

    /* Host 头（保留端口） */
    const char *host = "?";
    size_t hlen = 1;
    for (size_t i = le; i + 6 < n; i++) {
        if (d[i] == '\n' && strncasecmp((const char *)d + i + 1, "host:", 5) == 0) {
            size_t a = i + 6, b;
            while (a < n && (d[a] == ' ' || d[a] == '\t')) a++;
            b = a;
            while (b < n && d[b] != '\r' && d[b] != '\n') b++;
            while (b > a && (d[b - 1] == ' ' || d[b - 1] == '\t')) b--;
            if (b > a) {
                host = (const char *)d + a;
                hlen = b - a;
            }
            break;
        }
    }

    size_t o = 0;
    bool cut;
    url[0] = '\0';
    if (tlen >= 7 && strncasecmp(target, "http://", 7) == 0) {
        cut = url_append(url, ucap, &o, target, tlen);            /* 代理形式，已是完整 URL */
    } else {
        cut = url_append(url, ucap, &o, "http://", 7) ||
              url_append(url, ucap, &o, host, hlen) ||
              (target[0] != '/' && url_append(url, ucap, &o, "/", 1)) ||
              url_append(url, ucap, &o, target, tlen);
    }
    if (cut && ucap > 4) {
        strcpy(url + (o < ucap - 4 ? o : ucap - 4), "...");
    }
    return true;
}

static void set_domain(flow_t *f, const char *name, uint8_t src)
{
    strlcpy(f->domain, name, sizeof(f->domain));
    f->dom_src = src;
    ipmap_set(f->rip, name);
    if (block_index(name) >= 0) {
        mark_blocked(f);
        if (!blockip_has(f->rip) && s_n_blockip < BLOCKIP_MAX) {
            s_blockip[s_n_blockip++] = f->rip;
        }
    }
}

static void asm_release(flow_t *f)
{
    if (f->asm_slot >= 0) {
        s_asm[f->asm_slot].flow = -1;
        f->asm_slot = -1;
    }
}

/* 客户端发往远端的 TCP 数据段；持锁调用 */
static void inspect(flow_t *f, struct pbuf *p, uint16_t off, uint16_t plen)
{
    char name[MON_NAME_MAX + 1];
    if (f->rport == 80) {
        /* 不置 inspected：持久连接上的每个请求都要识别。先只读 8 字节判断是否为请求开头 */
        uint8_t head[8];
        uint16_t hn = pbuf_copy_partial(p, head, plen < sizeof(head) ? plen : sizeof(head), off);
        if (!http_method_len(head, hn) && hn >= 3) {
            return;                                 /* 请求体等后续数据 */
        }
        uint16_t n = pbuf_copy_partial(p, s_scratch, plen < 1024 ? plen : 1024, off);
        char method[sizeof(f->method)];
        if (parse_http_req(s_scratch, n, method, sizeof(method), f->url, sizeof(f->url))) {
            strlcpy(f->method, method, sizeof(f->method));
            f->reqs++;
        }
        if ((f->dom_src != 3 || !f->domain[0]) && parse_host(s_scratch, n, name)) {
            set_domain(f, name, 3);
        }
        return;
    }
    if (f->rport != 443) {
        f->inspected = true;
        return;
    }
    if (f->asm_slot < 0) {
        uint16_t n = pbuf_copy_partial(p, s_scratch, plen < ASM_CAP ? plen : ASM_CAP, off);
        int r = parse_sni(s_scratch, n, name);
        if (r == 0) {
            set_domain(f, name, 2);
        }
        if (r != 1) {
            f->inspected = true;
            return;
        }
        /* ClientHello 跨多个 TCP 段：放入重组缓冲 */
        for (int i = 0; i < ASM_SLOTS; i++) {
            if (s_asm[i].flow < 0) {
                asm_t *a = &s_asm[i];
                a->flow = (int16_t)(f - s_flows);
                a->need = 5 + ((s_scratch[3] << 8) | s_scratch[4]);
                if (a->need > ASM_CAP) a->need = ASM_CAP;
                memcpy(a->buf, s_scratch, n);
                a->len = n;
                a->segs = 1;
                f->asm_slot = (int8_t)i;
                return;
            }
        }
        f->inspected = true;                        /* 无空闲重组缓冲，放弃 */
        return;
    }
    asm_t *a = &s_asm[f->asm_slot];
    uint16_t room = ASM_CAP - a->len;
    uint16_t n = pbuf_copy_partial(p, a->buf + a->len, plen < room ? plen : room, off);
    a->len += n;
    a->segs++;
    int r = parse_sni(a->buf, a->len, name);
    if (r == 0) {
        set_domain(f, name, 2);
    }
    if (r != 1 || a->len >= a->need || a->segs >= 6) {
        asm_release(f);
        f->inspected = true;
    }
}

/* ---------- 转发钩子 ---------- */

int monitor_ip4_canforward(struct pbuf *p, uint32_t dest_host_order)
{
    (void)dest_host_order;
    if (!s_ready || !s_enabled || p->len < IP_HLEN) {
        return -1;
    }
    int core0 = xPortGetCoreID();
    uint32_t c0 = esp_cpu_get_cycle_count();
    const struct ip_hdr *iph = (const struct ip_hdr *)p->payload;
    if (IPH_V(iph) != 4) {
        return -1;
    }
    uint32_t src = iph->src.addr, dst = iph->dest.addr;
    bool up = (src & s_ap_mask) == s_ap_net, down = (dst & s_ap_mask) == s_ap_net;
    if (up == down) {
        return -1;
    }
    uint16_t hl = IPH_HL_BYTES(iph);
    uint16_t iplen = lwip_ntohs(IPH_LEN(iph));
    uint8_t proto = IPH_PROTO(iph);
    bool first_frag = (lwip_ntohs(IPH_OFFSET(iph)) & IP_OFFMASK) == 0;
    uint16_t sport = 0, dport = 0;
    const struct tcp_hdr *th = NULL;
    if (first_frag && (proto == IP_PROTO_TCP || proto == IP_PROTO_UDP) && p->len >= hl + 4) {
        const uint8_t *l4 = (const uint8_t *)p->payload + hl;
        sport = (l4[0] << 8) | l4[1];
        dport = (l4[2] << 8) | l4[3];
        if (proto == IP_PROTO_TCP && p->len >= hl + TCP_HLEN) {
            th = (const struct tcp_hdr *)l4;
        }
    }
    uint32_t cip = up ? src : dst, rip = up ? dst : src;
    uint16_t cport = up ? sport : dport, rport = up ? dport : sport;

    int verdict = -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t now = now_s();
    client_t *c = client_by_ip(cip, true);
    if (c) {
        c->last_seen = now;
        if (up) c->up += iplen; else c->down += iplen;
    }
    flow_t *f = flow_find(cip, rip, cport, rport, proto);
    if (!f) {
        f = flow_create(cip, rip, cport, rport, proto);
        const char *nm = ipmap_get(rip);
        if (nm) {
            strlcpy(f->domain, nm, sizeof(f->domain));
            f->dom_src = 1;
        }
        if (blockip_has(rip) || (f->domain[0] && block_index(f->domain) >= 0)) {
            f->blocked = true;
            int bi = f->domain[0] ? block_index(f->domain) : -1;
            if (bi >= 0) s_block_hits[bi]++;
        }
    }
    f->last = now;
    if (up) f->up += iplen; else f->down += iplen;
    if (th) {
        uint8_t fl = TCPH_FLAGS(th);
        int plen = (int)iplen - hl - TCPH_HDRLEN_BYTES(th);
        if (plen < 0) plen = 0;
        if (fl & (TCP_FIN | TCP_RST)) f->closing = true;
        if (up) {
            f->c_next = lwip_ntohl(th->seqno) + plen + ((fl & TCP_SYN) ? 1 : 0) + ((fl & TCP_FIN) ? 1 : 0);
            if (fl & TCP_ACK) {
                f->c_ack = lwip_ntohl(th->ackno);
                f->seq_valid = true;
            }
            if (plen > 0 && !f->inspected && !f->blocked) {
                inspect(f, p, hl + TCPH_HDRLEN_BYTES(th), (uint16_t)plen);
            }
        }
    }
    if (f->blocked) {
        verdict = 0;
    }
    xSemaphoreGive(s_lock);

    uint32_t dt = esp_cpu_get_cycle_count() - c0;
    s_perf_pkts++;
    if (xPortGetCoreID() == core0) {
        s_perf_samples++;
        s_perf_cycles += dt;
        if (dt > s_perf_max) s_perf_max = dt;
    }
    return verdict;
}

/* ---------- 定时：速率与过期 ---------- */

static void tick_cb(void *arg)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t now = now_s();
    s_perf_pps = (uint32_t)(s_perf_pkts - s_perf_last_pkts);
    s_perf_last_pkts = s_perf_pkts;
    for (int i = 0; i < CLIENT_MAX; i++) {
        client_t *c = &s_clients[i];
        if (!c->used) continue;
        c->rup = (uint32_t)(c->up - c->last_up);
        c->rdown = (uint32_t)(c->down - c->last_down);
        c->last_up = c->up;
        c->last_down = c->down;
    }
    for (int i = 0; i < FLOW_MAX; i++) {
        flow_t *f = &s_flows[i];
        if (!f->used) continue;
        f->rup = (uint32_t)(f->up - f->last_up);
        f->rdown = (uint32_t)(f->down - f->last_down);
        f->last_up = f->up;
        f->last_down = f->down;
        uint32_t idle = now - f->last;
        if ((f->closing && idle > 15) || (f->proto == IP_PROTO_TCP && idle > 300) ||
            (f->proto != IP_PROTO_TCP && idle > 60)) {
            flow_free(i);
        }
    }
    xSemaphoreGive(s_lock);
}

/* ---------- DNS ---------- */

bool monitor_is_blocked(const char *name)
{
    if (!s_ready) return false;
    char n[MON_NAME_MAX + 1];
    if (!clean_name(name, strlen(name), n)) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool b = block_index(n) >= 0;
    xSemaphoreGive(s_lock);
    return b;
}

uint32_t monitor_dns_query(uint32_t client_ip, const char *name, uint16_t qtype,
                           mon_dns_result_t res, uint32_t local_ip)
{
    if (!s_ready) return 0;
    char n[MON_NAME_MAX + 1];
    if (!clean_name(name, strlen(name), n)) {
        strlcpy(n, "(无效域名)", sizeof(n));
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t id = ++s_dns_seq;
    dnslog_t *e = &s_dns[id % DNSLOG_MAX];
    memset(e, 0, sizeof(*e));
    e->id = id;
    e->t = now_s();
    e->cip = client_ip;
    e->qtype = qtype;
    e->res = (uint8_t)res;
    strlcpy(e->name, n, sizeof(e->name));
    if (res == MON_DNS_LOCAL && (qtype == 1 || qtype == 255)) {
        e->ans[0] = local_ip;
        e->nans = 1;
    }
    if (res == MON_DNS_BLOCKED) {
        int bi = block_index(n);
        if (bi >= 0) s_block_hits[bi]++;
    }
    client_t *c = client_by_ip(client_ip, true);
    if (c) c->dns++;
    xSemaphoreGive(s_lock);
    return id;
}

void monitor_dns_answer(uint32_t log_id, const char *name, const uint32_t *ips, int n)
{
    if (!s_ready || n <= 0) return;
    char nm[MON_NAME_MAX + 1];
    bool ok = clean_name(name, strlen(name), nm);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    dnslog_t *e = &s_dns[log_id % DNSLOG_MAX];
    if (e->id == log_id) {
        e->nans = n < 4 ? n : 4;
        memcpy(e->ans, ips, e->nans * sizeof(uint32_t));
    }
    if (ok) {
        for (int i = 0; i < n; i++) ipmap_set(ips[i], nm);
    }
    xSemaphoreGive(s_lock);
}

/* ---------- 黑名单 ---------- */

/* 黑名单只存内存，重启后清空；清除旧版本写入 NVS 的黑名单 */
static void block_erase_old_nvs(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    if (nvs_erase_all(h) == ESP_OK) nvs_commit(h);
    nvs_close(h);
}

/* 重新判定所有连接是否拦截；新拦截的 TCP 连接发 RST */
static void reapply_flows(void)
{
    for (int i = 0; i < FLOW_MAX; i++) {
        flow_t *f = &s_flows[i];
        if (!f->used) continue;
        bool should = blockip_has(f->rip) || (f->domain[0] && block_index(f->domain) >= 0);
        if (should && !f->blocked) {
            mark_blocked(f);
        } else if (!should) {
            f->blocked = false;
        }
    }
}

esp_err_t monitor_block_add(const char *domain, const char **err_msg)
{
    char n[MON_NAME_MAX + 1];
    if (!domain || !clean_name(domain, strlen(domain), n) || !strchr(n, '.')) {
        *err_msg = "域名格式错误";
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_OK;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int i = 0;
    while (i < s_n_block && strcmp(s_block[i].name, n) != 0) i++;
    if (i == s_n_block) {
        if (s_n_block >= MON_BLOCK_MAX) {
            *err_msg = "黑名单已满（32 条）";
            err = ESP_ERR_NO_MEM;
        } else {
            strlcpy(s_block[s_n_block].name, n, sizeof(s_block[0].name));
            s_block_hits[s_n_block] = 0;
            s_n_block++;
            blockip_rebuild();
            reapply_flows();
            ESP_LOGI(TAG, "拉黑 %s", n);
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t monitor_block_del(const char *domain)
{
    char n[MON_NAME_MAX + 1];
    if (!domain || !clean_name(domain, strlen(domain), n)) return ESP_ERR_INVALID_ARG;
    esp_err_t err = ESP_ERR_NOT_FOUND;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_n_block; i++) {
        if (strcmp(s_block[i].name, n) == 0) {
            memmove(&s_block[i], &s_block[i + 1], sizeof(s_block[0]) * (s_n_block - i - 1));
            memmove(&s_block_hits[i], &s_block_hits[i + 1], sizeof(s_block_hits[0]) * (s_n_block - i - 1));
            s_n_block--;
            memset(&s_block[s_n_block], 0, sizeof(s_block[0]));
            blockip_rebuild();
            reapply_flows();
            ESP_LOGI(TAG, "解除拉黑 %s", n);
            err = ESP_OK;
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

/* ---------- JSON ---------- */

typedef struct {
    char *b;
    size_t len, cap;
} sb_t;

static void sb_printf(sb_t *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void sb_printf(sb_t *s, const char *fmt, ...)
{
    if (s->len >= s->cap) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s->b + s->len, s->cap - s->len, fmt, ap);
    va_end(ap);
    if (n > 0) s->len += (size_t)n < s->cap - s->len ? (size_t)n : s->cap - s->len - 1;
}

static bool sb_init(sb_t *s, size_t cap)
{
    s->b = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!s->b) s->b = malloc(cap);
    s->len = 0;
    s->cap = cap;
    return s->b != NULL;
}

static const char *flow_type(const flow_t *f, char *buf)
{
    if (f->proto == IP_PROTO_TCP) {
        switch (f->rport) {
        case 443: return "HTTPS";
        case 80: return "HTTP";
        case 853: return "DoT";
        case 53: return "DNS";
        case 22: return "SSH";
        }
        sprintf(buf, "TCP/%u", f->rport);
        return buf;
    }
    if (f->proto == IP_PROTO_UDP) {
        switch (f->rport) {
        case 443: return "QUIC";
        case 53: return "DNS";
        case 123: return "NTP";
        case 3478: return "STUN";
        }
        sprintf(buf, "UDP/%u", f->rport);
        return buf;
    }
    if (f->proto == IP_PROTO_ICMP) return "ICMP";
    sprintf(buf, "IP/%u", f->proto);
    return buf;
}

char *monitor_live_json(size_t *len)
{
    sb_t s;
    if (!sb_init(&s, LIVE_BUF)) return NULL;
    uint32_t mhz = 0;
    esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU, ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED, &mhz);
    mhz /= 1000000;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t avg = s_perf_samples ? (uint32_t)(s_perf_cycles / s_perf_samples) : 0;
    sb_printf(&s, "{\"uptime\":%lu,\"enabled\":%s,\"perf\":{\"pkts\":%llu,\"pps\":%lu,\"avg_cycles\":%lu,"
              "\"max_cycles\":%lu,\"cpu_mhz\":%lu},\"clients\":[",
              (unsigned long)now_s(), s_enabled ? "true" : "false", (unsigned long long)s_perf_pkts,
              (unsigned long)s_perf_pps, (unsigned long)avg, (unsigned long)s_perf_max, (unsigned long)mhz);
    bool first = true;
    char ip[16];
    for (int i = 0; i < CLIENT_MAX; i++) {
        client_t *c = &s_clients[i];
        if (!c->used) continue;
        ip_str(c->ip, ip);
        sb_printf(&s, "%s{\"mac\":\"", first ? "" : ",");
        if (c->has_mac) {
            sb_printf(&s, "%02x:%02x:%02x:%02x:%02x:%02x", c->mac[0], c->mac[1], c->mac[2], c->mac[3],
                      c->mac[4], c->mac[5]);
        }
        sb_printf(&s, "\",\"ip\":\"%s\",\"host\":\"%s\",\"online\":%s,\"first\":%lu,\"join\":%lu,\"seen\":%lu,"
                  "\"up\":%llu,\"down\":%llu,\"rup\":%lu,\"rdown\":%lu,\"dns\":%lu}",
                  c->ip ? ip : "", c->host, c->online ? "true" : "false", (unsigned long)c->first,
                  (unsigned long)c->last_join, (unsigned long)c->last_seen, (unsigned long long)c->up,
                  (unsigned long long)c->down, (unsigned long)c->rup, (unsigned long)c->rdown,
                  (unsigned long)c->dns);
        first = false;
    }
    sb_printf(&s, "],\"flows\":[");
    first = true;
    static const char *const src_name[] = { "", "dns", "sni", "host" };
    char rip[16], tbuf[12];
    for (int i = 0; i < FLOW_MAX; i++) {
        flow_t *f = &s_flows[i];
        if (!f->used) continue;
        ip_str(f->cip, ip);
        ip_str(f->rip, rip);
        sb_printf(&s, "%s{\"id\":%lu,\"cip\":\"%s\",\"cport\":%u,\"rip\":\"%s\",\"rport\":%u,\"type\":\"%s\","
                  "\"domain\":\"%s\",\"src\":\"%s\",\"first\":%lu,\"last\":%lu,\"up\":%llu,\"down\":%llu,"
                  "\"rup\":%lu,\"rdown\":%lu,\"state\":\"%s\",\"method\":\"%s\",\"url\":\"%s\",\"reqs\":%u}",
                  first ? "" : ",", (unsigned long)f->id, ip, f->cport, rip, f->rport, flow_type(f, tbuf),
                  f->domain, src_name[f->dom_src & 3], (unsigned long)f->first, (unsigned long)f->last,
                  (unsigned long long)f->up, (unsigned long long)f->down, (unsigned long)f->rup,
                  (unsigned long)f->rdown, f->blocked ? "blocked" : (f->closing ? "closed" : "open"),
                  f->method, f->url, f->reqs);
        first = false;
    }
    xSemaphoreGive(s_lock);
    sb_printf(&s, "]}");
    *len = s.len;
    return s.b;
}

char *monitor_dns_json(uint32_t since, size_t *len)
{
    sb_t s;
    if (!sb_init(&s, 64 * 1024)) return NULL;
    static const char *const res_name[] = { "forward", "local", "blocked", "filtered" };
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t last = s_dns_seq;
    uint32_t start = since + 1;
    if (last >= DNSLOG_MAX && start < last - DNSLOG_MAX + 1) start = last - DNSLOG_MAX + 1;
    if (last >= 300 && start < last - 299) start = last - 299;     /* 单次最多 300 条 */
    sb_printf(&s, "{\"last\":%lu,\"entries\":[", (unsigned long)last);
    char ip[16];
    for (uint32_t id = start; id <= last && id > 0; id++) {
        dnslog_t *e = &s_dns[id % DNSLOG_MAX];
        if (e->id != id) continue;
        ip_str(e->cip, ip);
        sb_printf(&s, "%s{\"id\":%lu,\"t\":%lu,\"cip\":\"%s\",\"name\":\"%s\",\"qtype\":%u,\"res\":\"%s\",\"ans\":[",
                  id == start ? "" : ",", (unsigned long)id, (unsigned long)e->t, ip, e->name, e->qtype,
                  res_name[e->res % 4]);
        for (int k = 0; k < e->nans; k++) {
            ip_str(e->ans[k], ip);
            sb_printf(&s, "%s\"%s\"", k ? "," : "", ip);
        }
        sb_printf(&s, "]}");
    }
    xSemaphoreGive(s_lock);
    sb_printf(&s, "]}");
    *len = s.len;
    return s.b;
}

char *monitor_block_json(size_t *len)
{
    sb_t s;
    if (!sb_init(&s, 8 * 1024)) return NULL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    sb_printf(&s, "{\"max\":%d,\"ips\":%d,\"list\":[", MON_BLOCK_MAX, s_n_blockip);
    for (int i = 0; i < s_n_block; i++) {
        sb_printf(&s, "%s{\"domain\":\"%s\",\"hits\":%lu}", i ? "," : "", s_block[i].name,
                  (unsigned long)s_block_hits[i]);
    }
    xSemaphoreGive(s_lock);
    sb_printf(&s, "]}");
    *len = s.len;
    return s.b;
}

void monitor_set_enabled(bool en)
{
    s_enabled = en;
    ESP_LOGI(TAG, "流量记录 %s", en ? "开启" : "关闭");
}

void monitor_reset_perf(void)
{
    s_perf_pkts = s_perf_cycles = s_perf_last_pkts = s_perf_samples = 0;
    s_perf_max = 0;
}

/* 合成包压测钩子开销：64 条连接，上下行交替。
 * 在绑定 core 1 的任务里运行（周期计数器按核独立），记录每个样本，报告中位数/p90/p99/最大值；
 * 结束后清除测试数据 */
#define BENCH_FLOWS   64
#define BENCH_ROUNDS  300
#define BENCH_N       (BENCH_FLOWS * BENCH_ROUNDS)

typedef struct {
    uint32_t *samples;
    SemaphoreHandle_t done;
} bench_ctx_t;

static void bench_task(void *arg)
{
    bench_ctx_t *ctx = arg;
    struct pbuf *p = pbuf_alloc(PBUF_RAW, IP_HLEN + TCP_HLEN + 64, PBUF_RAM);
    if (p) {
        struct ip_hdr *iph = (struct ip_hdr *)p->payload;
        struct tcp_hdr *th = (struct tcp_hdr *)((uint8_t *)p->payload + IP_HLEN);
        memset(p->payload, 0, p->len);
        IPH_VHL_SET(iph, 4, IP_HLEN / 4);
        IPH_LEN_SET(iph, lwip_htons(p->len));
        IPH_PROTO_SET(iph, IP_PROTO_TCP);
        TCPH_HDRLEN_FLAGS_SET(th, 5, TCP_ACK);
        uint32_t bench_cip = s_ap_net | lwip_htonl(250);
        int n = 0;
        for (int r = 0; r < BENCH_ROUNDS; r++) {
            for (int i = 0; i < BENCH_FLOWS; i++) {
                uint32_t rip = lwip_htonl(0xC6336400u | (uint32_t)(i + 1));   /* 198.51.100.x */
                bool up = (r + i) & 1;
                iph->src.addr = up ? bench_cip : rip;
                iph->dest.addr = up ? rip : bench_cip;
                th->src = lwip_htons(up ? 40000 + i : 443);
                th->dest = lwip_htons(up ? 443 : 40000 + i);
                th->seqno = lwip_htonl(r * 100);
                uint32_t c0 = esp_cpu_get_cycle_count();
                monitor_ip4_canforward(p, 0);
                ctx->samples[n++] = esp_cpu_get_cycle_count() - c0;
            }
        }
        pbuf_free(p);
    }
    xSemaphoreGive(ctx->done);
    vTaskDelete(NULL);
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

char *monitor_bench_json(size_t *len)
{
    bench_ctx_t ctx = {
        .samples = heap_caps_malloc(BENCH_N * sizeof(uint32_t), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT),
        .done = xSemaphoreCreateBinary(),
    };
    if (!ctx.samples || !ctx.done) {
        free(ctx.samples);
        if (ctx.done) vSemaphoreDelete(ctx.done);
        return NULL;
    }
    bool was = s_enabled;
    s_enabled = true;
    if (xTaskCreatePinnedToCore(bench_task, "mon_bench", 4096, &ctx, 5, NULL, 1) != pdPASS) {
        s_enabled = was;
        free(ctx.samples);
        vSemaphoreDelete(ctx.done);
        return NULL;
    }
    if (xSemaphoreTake(ctx.done, pdMS_TO_TICKS(30000)) != pdTRUE) {
        /* 任务仍可能在写 samples/ctx（ctx 在本栈上，因此继续等待直到完成） */
        xSemaphoreTake(ctx.done, portMAX_DELAY);
    }
    s_enabled = was;

    /* 清除测试数据 */
    uint32_t bench_cip = s_ap_net | lwip_htonl(250);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < FLOW_MAX; i++) {
        if (s_flows[i].used && s_flows[i].cip == bench_cip) flow_free(i);
    }
    for (int i = 0; i < CLIENT_MAX; i++) {
        if (s_clients[i].used && s_clients[i].ip == bench_cip) s_clients[i].used = false;
    }
    xSemaphoreGive(s_lock);

    sb_t s;
    if (!sb_init(&s, 512)) {
        free(ctx.samples);
        vSemaphoreDelete(ctx.done);
        return NULL;
    }
    uint64_t sum = 0;
    for (int i = 0; i < BENCH_N; i++) sum += ctx.samples[i];
    qsort(ctx.samples, BENCH_N, sizeof(uint32_t), cmp_u32);
    uint32_t hz = 0;
    esp_clk_tree_src_get_freq_hz(SOC_MOD_CLK_CPU, ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED, &hz);
    double mhz = hz / 1e6;
    double med = ctx.samples[BENCH_N / 2] / mhz, p90 = ctx.samples[BENCH_N * 90 / 100] / mhz;
    double p99 = ctx.samples[BENCH_N * 99 / 100] / mhz, mx = ctx.samples[BENCH_N - 1] / mhz;
    double mean = (double)sum / BENCH_N / mhz;
    sb_printf(&s, "{\"packets\":%d,\"flows\":%d,\"cpu_mhz\":%.0f,\"median_us\":%.2f,\"p90_us\":%.2f,"
              "\"p99_us\":%.2f,\"max_us\":%.1f,\"mean_us\":%.2f,\"max_pps_hook_only\":%.0f}",
              BENCH_N, BENCH_FLOWS, mhz, med, p90, p99, mx, mean, med > 0 ? 1e6 / med : 0);
    free(ctx.samples);
    vSemaphoreDelete(ctx.done);
    *len = s.len;
    return s.b;
}

/* ---------- 初始化 ---------- */

void monitor_init(esp_netif_t *ap)
{
    s_lock = xSemaphoreCreateMutex();
    /* 实测放内部 RAM 与 PSRAM 每包耗时相同（中位数均为 7.5 µs），放 PSRAM 省内部 RAM */
    s_clients = ps_calloc(CLIENT_MAX, sizeof(client_t));
    s_flows = ps_calloc(FLOW_MAX, sizeof(flow_t));
    s_dns = ps_calloc(DNSLOG_MAX, sizeof(dnslog_t));
    s_ipmap = ps_calloc(IPMAP_MAX, sizeof(ipmap_t));
    s_asm = ps_calloc(ASM_SLOTS, sizeof(asm_t));
    if (!s_lock || !s_clients || !s_flows || !s_dns || !s_ipmap || !s_asm) {
        ESP_LOGE(TAG, "内存不足，流量记录不可用");
        return;
    }
    for (int i = 0; i < FLOW_BUCKETS; i++) s_buckets[i] = -1;
    for (int i = 0; i < ASM_SLOTS; i++) s_asm[i].flow = -1;

    esp_netif_ip_info_t info;
    esp_netif_get_ip_info(ap, &info);
    s_ap_mask = info.netmask.addr;
    s_ap_net = info.ip.addr & info.netmask.addr;
    s_ap_lwip = esp_netif_get_netif_impl(ap);
    block_erase_old_nvs();

    const esp_timer_create_args_t targs = { .callback = tick_cb, .name = "mon_tick" };
    esp_timer_handle_t t;
    if (esp_timer_create(&targs, &t) == ESP_OK) {
        esp_timer_start_periodic(t, 1000000);
    }
    s_ready = true;
    ESP_LOGI(TAG, "流量记录已启动，黑名单 %d 条", s_n_block);
}
