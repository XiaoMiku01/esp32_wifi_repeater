/*
 * DNS 中继：监听 AP 地址 192.168.4.1:53，把客户端的查询转发给 STA 当前的上游 DNS，
 * 再把应答送回客户端。
 *
 * AP 的 DHCP 服务器默认把自身地址作为 DNS 下发，客户端无论何时连入
 * （包括上游尚未连上时），拿到的 DNS 都是可用的；上游 DNS 变化也无需客户端续租。
 *
 * 自定义解析：表中的域名不转发，直接应答指定 IPv4（A 记录；AAAA 等其他类型
 * 回空应答，让客户端回落到 IPv4）；不在表中的域名照常转发上游。
 * 表存 NVS（命名空间 dnsovr），可在配置页增删；首次启动预置 H2_SITE_DEFAULT_DOMAIN -> AP 地址。
 */
#include <string.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "repeater.h"

#define DNS_PORT      53
#define BUF_SIZE      1500
#define SLOTS         32
#define TIMEOUT_MS    5000

static const char *TAG = "dns";

typedef struct {
    bool used;
    uint16_t orig_id;
    uint16_t new_id;
    struct sockaddr_in client;
    TickType_t ts;
} slot_t;

#define LOCAL_TTL     60
#define OVR_NVS_NS    "dnsovr"
#define OVR_NVS_KEY   "table"
#define OVR_NVS_CNT   "count"

typedef struct {
    char name[DNS_OVR_NAME_MAX + 1];    /* 小写，不含结尾点 */
    uint32_t ip;                        /* 网络字节序；0 表示用 AP 自身地址 */
} override_t;

static override_t s_ovr[DNS_OVR_MAX];
static volatile int s_n_ovr;
static SemaphoreHandle_t s_ovr_lock;

static slot_t s_slots[SLOTS];
static esp_netif_t *s_ap, *s_sta;

static bool get_upstream(struct sockaddr_in *out)
{
    esp_netif_dns_info_t dns;
    for (int t = ESP_NETIF_DNS_MAIN; t <= ESP_NETIF_DNS_BACKUP; t++) {
        if (esp_netif_get_dns_info(s_sta, t, &dns) == ESP_OK &&
            dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr != 0) {
            memset(out, 0, sizeof(*out));
            out->sin_family = AF_INET;
            out->sin_port = htons(DNS_PORT);
            out->sin_addr.s_addr = dns.ip.u_addr.ip4.addr;
            return true;
        }
    }
    return false;
}

static slot_t *alloc_slot(TickType_t now)
{
    slot_t *oldest = &s_slots[0];
    for (int i = 0; i < SLOTS; i++) {
        slot_t *s = &s_slots[i];
        if (!s->used || now - s->ts > pdMS_TO_TICKS(TIMEOUT_MS)) {
            return s;
        }
        if (s->ts < oldest->ts) {
            oldest = s;
        }
    }
    return oldest;
}

/* 解析查询的问题段：只接受 QR=0、QDCOUNT=1、无压缩指针的标准查询。
 * 成功返回问题段结束偏移（含 QTYPE/QCLASS），name 为小写点分形式；失败返回 -1 */
static int parse_question(const uint8_t *p, int n, char *name, size_t cap, uint16_t *qtype)
{
    if (n < 12 || (p[2] & 0x80) || p[4] != 0 || p[5] != 1) {
        return -1;
    }
    int off = 12;
    size_t o = 0;
    bool done = false;
    while (off < n) {
        uint8_t l = p[off++];
        if (l == 0) {
            done = true;
            break;
        }
        if ((l & 0xC0) || off + l > n || o + l + 1 >= cap) {
            return -1;
        }
        if (o) {
            name[o++] = '.';
        }
        for (int i = 0; i < l; i++) {
            name[o++] = (char)tolower(p[off + i]);
        }
        off += l;
    }
    name[o] = '\0';
    if (!done || off + 4 > n) {
        return -1;
    }
    *qtype = (p[off] << 8) | p[off + 1];
    return off + 4;
}

static bool lookup_override(const char *name, uint32_t *ip)
{
    bool hit = false;
    xSemaphoreTake(s_ovr_lock, portMAX_DELAY);
    for (int i = 0; i < s_n_ovr; i++) {
        if (strcmp(s_ovr[i].name, name) == 0) {
            *ip = s_ovr[i].ip;
            hit = true;
            break;
        }
    }
    xSemaphoreGive(s_ovr_lock);
    return hit;
}

/* 在查询报文原地构造应答，返回应答长度 */
static int build_local_answer(uint8_t *p, int qend, uint16_t qtype, uint32_t ip)
{
    p[2] = 0x80 | (p[2] & 0x79) | 0x04;     /* QR=1，保留 OPCODE/RD，AA=1 */
    p[3] = 0x80;                            /* RA=1，RCODE=0 */
    p[6] = 0; p[7] = 0;                     /* ANCOUNT */
    p[8] = 0; p[9] = 0;                     /* NSCOUNT */
    p[10] = 0; p[11] = 0;                   /* ARCOUNT：丢弃查询里的 EDNS OPT */
    int off = qend;
    if (qtype == 1 /* A */ || qtype == 255 /* ANY */) {
        p[7] = 1;
        const uint8_t rr[] = {
            0xC0, 0x0C,                     /* 名称指针，指向问题段 */
            0x00, 0x01, 0x00, 0x01,         /* TYPE A，CLASS IN */
            0x00, 0x00, (LOCAL_TTL >> 8) & 0xff, LOCAL_TTL & 0xff,
            0x00, 0x04,
        };
        memcpy(p + off, rr, sizeof(rr));
        off += sizeof(rr);
        memcpy(p + off, &ip, 4);
        off += 4;
    }
    return off;
}

/* ---------- 自定义解析表 ---------- */

/* 规范化并校验域名：转小写、去结尾点；只允许字母数字 - _ .，标签 1-63 */
static const char *normalize_name(const char *in, char *out)
{
    size_t n = strlen(in);
    if (n && in[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > DNS_OVR_NAME_MAX) {
        return "域名长度需为 1-63";
    }
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        char c = (char)tolower((unsigned char)in[i]);
        if (c == '.') {
            if (label == 0) {
                return "域名格式错误（空标签）";
            }
            label = 0;
        } else if (isalnum((unsigned char)c) || c == '-' || c == '_') {
            label++;
        } else {
            return "域名只能包含字母、数字、-、_、.";
        }
        out[i] = c;
    }
    if (label == 0) {
        return "域名格式错误（空标签）";
    }
    out[n] = '\0';
    return NULL;
}

/* 持锁调用 */
static esp_err_t save_table(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(OVR_NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    /* 条数单独存；空表也写入，避免重启后重新预置默认项 */
    err = nvs_set_blob(h, OVR_NVS_KEY, s_ovr, sizeof(s_ovr));
    if (err == ESP_OK) {
        err = nvs_set_u8(h, OVR_NVS_CNT, (uint8_t)s_n_ovr);
    }
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

void dns_relay_load_overrides(void)
{
    s_ovr_lock = xSemaphoreCreateMutex();
    nvs_handle_t h;
    size_t len = sizeof(s_ovr);
    uint8_t cnt = 0;
    esp_err_t err = nvs_open(OVR_NVS_NS, NVS_READONLY, &h);
    if (err == ESP_OK) {
        err = nvs_get_u8(h, OVR_NVS_CNT, &cnt);
        if (err == ESP_OK) {
            err = nvs_get_blob(h, OVR_NVS_KEY, s_ovr, &len);
        }
        nvs_close(h);
    }
    if (err == ESP_OK && len == sizeof(s_ovr) && cnt <= DNS_OVR_MAX) {
        s_n_ovr = cnt;
        for (int i = 0; i < s_n_ovr; i++) {
            s_ovr[i].name[DNS_OVR_NAME_MAX] = '\0';
        }
        ESP_LOGI(TAG, "已加载 %d 条自定义解析", s_n_ovr);
    } else {
        /* 首次启动：预置 h2 站点域名解析到 AP */
        strlcpy(s_ovr[0].name, H2_SITE_DEFAULT_DOMAIN, sizeof(s_ovr[0].name));
        s_ovr[0].ip = 0;
        s_n_ovr = 1;
        ESP_LOGI(TAG, "无自定义解析配置，预置 %s -> AP", H2_SITE_DEFAULT_DOMAIN);
    }
}

esp_err_t dns_relay_set_override(const char *name, uint32_t ip, const char **err_msg)
{
    char norm[DNS_OVR_NAME_MAX + 1];
    const char *msg = normalize_name(name, norm);
    if (msg) {
        *err_msg = msg;
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_OK;
    xSemaphoreTake(s_ovr_lock, portMAX_DELAY);
    int i = 0;
    while (i < s_n_ovr && strcmp(s_ovr[i].name, norm) != 0) {
        i++;
    }
    if (i == s_n_ovr && s_n_ovr >= DNS_OVR_MAX) {
        *err_msg = "已达上限（16 条）";
        err = ESP_ERR_NO_MEM;
    } else {
        override_t old = s_ovr[i];
        int old_n = s_n_ovr;
        strlcpy(s_ovr[i].name, norm, sizeof(s_ovr[i].name));
        s_ovr[i].ip = ip;
        if (i == s_n_ovr) {
            s_n_ovr++;
        }
        err = save_table();
        if (err != ESP_OK) {
            s_ovr[i] = old;         /* 回滚 */
            s_n_ovr = old_n;
            *err_msg = "写入 NVS 失败";
        } else {
            *err_msg = NULL;
            ESP_LOGI(TAG, "自定义解析 %s -> " IPSTR "%s", norm, IP2STR((esp_ip4_addr_t *)&ip),
                     ip ? "" : "（AP 地址）");
        }
    }
    xSemaphoreGive(s_ovr_lock);
    return err;
}

esp_err_t dns_relay_del_override(const char *name)
{
    char norm[DNS_OVR_NAME_MAX + 1];
    if (normalize_name(name, norm)) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_ERR_NOT_FOUND;
    xSemaphoreTake(s_ovr_lock, portMAX_DELAY);
    for (int i = 0; i < s_n_ovr; i++) {
        if (strcmp(s_ovr[i].name, norm) == 0) {
            memmove(&s_ovr[i], &s_ovr[i + 1], sizeof(override_t) * (s_n_ovr - i - 1));
            s_n_ovr--;
            err = save_table();
            ESP_LOGI(TAG, "删除自定义解析 %s", norm);
            break;
        }
    }
    xSemaphoreGive(s_ovr_lock);
    return err;
}

bool dns_relay_get_override(const char *name, uint32_t *ip)
{
    char norm[DNS_OVR_NAME_MAX + 1];
    return normalize_name(name, norm) == NULL && lookup_override(norm, ip);
}

void dns_relay_foreach_override(void (*fn)(const char *name, uint32_t ip, void *arg), void *arg)
{
    xSemaphoreTake(s_ovr_lock, portMAX_DELAY);
    for (int i = 0; i < s_n_ovr; i++) {
        fn(s_ovr[i].name, s_ovr[i].ip, arg);
    }
    xSemaphoreGive(s_ovr_lock);
}

static void dns_relay_task(void *arg)
{
    static uint8_t buf[BUF_SIZE];
    uint16_t next_id = (uint16_t)esp_random();

    /* 只监听 AP 地址，不在上游局域网上充当 DNS 服务器 */
    esp_netif_ip_info_t ap_ip;
    esp_netif_get_ip_info(s_ap, &ap_ip);

    int lsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int usock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = ap_ip.ip.addr,
    };
    if (lsock < 0 || usock < 0 || bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "socket/bind 失败 errno=%d", errno);
        goto out;
    }
    ESP_LOGI(TAG, "DNS 中继已启动 " IPSTR ":53", IP2STR(&ap_ip.ip));

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsock, &rfds);
        FD_SET(usock, &rfds);
        if (select((lsock > usock ? lsock : usock) + 1, &rfds, NULL, NULL, NULL) <= 0) {
            continue;
        }
        TickType_t now = xTaskGetTickCount();

        /* 客户端查询 -> 上游 */
        if (FD_ISSET(lsock, &rfds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            int n = recvfrom(lsock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);

            /* 本地覆盖的域名直接应答，不依赖上游 */
            char qname[256];
            uint16_t qtype;
            int qend = s_n_ovr ? parse_question(buf, n, qname, sizeof(qname), &qtype) : -1;
            uint32_t ip;
            if (qend > 0 && qend + 16 <= (int)sizeof(buf) && lookup_override(qname, &ip)) {
                if (ip == 0) {
                    ip = ap_ip.ip.addr;
                }
                int len = build_local_answer(buf, qend, qtype, ip);
                sendto(lsock, buf, len, 0, (struct sockaddr *)&from, flen);
                ESP_LOGD(TAG, "本地应答 %s type=%u", qname, qtype);
                continue;
            }

            struct sockaddr_in up;
            if (n >= 12 && get_upstream(&up)) {
                slot_t *s = alloc_slot(now);
                s->used = true;
                s->orig_id = (buf[0] << 8) | buf[1];
                s->new_id = next_id++;
                s->client = from;
                s->ts = now;
                buf[0] = s->new_id >> 8;
                buf[1] = s->new_id & 0xff;
                sendto(usock, buf, n, 0, (struct sockaddr *)&up, sizeof(up));
            }
            /* 上游未连上时直接丢弃，客户端会超时重试 */
        }

        /* 上游应答 -> 客户端 */
        if (FD_ISSET(usock, &rfds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            int n = recvfrom(usock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n < 12 || from.sin_port != htons(DNS_PORT)) {
                continue;
            }
            uint16_t id = (buf[0] << 8) | buf[1];
            for (int i = 0; i < SLOTS; i++) {
                slot_t *s = &s_slots[i];
                if (s->used && s->new_id == id) {
                    buf[0] = s->orig_id >> 8;
                    buf[1] = s->orig_id & 0xff;
                    sendto(lsock, buf, n, 0, (struct sockaddr *)&s->client, sizeof(s->client));
                    s->used = false;
                    break;
                }
            }
        }
    }

out:
    if (lsock >= 0) close(lsock);
    if (usock >= 0) close(usock);
    vTaskDelete(NULL);
}

void dns_relay_start(esp_netif_t *ap, esp_netif_t *sta)
{
    s_ap = ap;
    s_sta = sta;
    xTaskCreate(dns_relay_task, "dns_relay", 4096, NULL, 5, NULL);
}
