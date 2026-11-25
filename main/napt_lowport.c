/*
 * 让源端口小于 1024 的 UDP 也能经 NAPT 转发
 *
 * ESP-IDF 的 lwIP NAPT（ip4_napt.c 的 ip_napt_forward）只给源端口 >= 1024 的 UDP 新建映射，
 * 小于 1024 的直接丢弃并回 ICMP 端口不可达。特斯拉车机的 NTP 对时用的就是低源端口
 * （实测 157、394、443），经本机永远收不到回包。
 *
 * 不改 IDF 源码：用链接器的 --wrap 包住 NAPT 的两个入口（见 main/CMakeLists.txt），
 *   上行：低源端口先换成一个临时的高端口（别名端口），再交给原来的 NAPT；
 *   下行：原来的 NAPT 把目的地址 / 端口还原成「客户端 + 别名端口」之后，再把别名端口换回原端口。
 * 两个入口都只在 tcpip 线程里调用，表不用加锁。
 */
#include <stdbool.h>
#include <stdint.h>
#include "lwip/opt.h"
#include "lwip/def.h"
#include "lwip/pbuf.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/ip4.h"
#include "lwip/udp.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/udp.h"

#if IP_NAPT

#define LOWPORT_SLOTS       16
#define LOWPORT_ALIAS_BASE  20000       /* 别名端口 20000 起，每个表项固定一个；避开常见的临时端口范围 */
#define LOWPORT_IDLE_MS     120000      /* 空闲这么久的表项可以被新会话复用 */

typedef struct {
    uint32_t cip;       /* 客户端地址，网络字节序；0 = 空 */
    uint16_t port;      /* 原源端口，网络字节序 */
    uint32_t last;      /* 最近一次收发，sys_now() */
} lowport_slot_t;

static lowport_slot_t s_slots[LOWPORT_SLOTS];

err_t __real_ip_napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp);
void __real_ip_napt_recv(struct pbuf *p, struct ip_hdr *iphdr);

/* 第一个分片且长度够时返回 UDP 头，否则 NULL（后续分片里没有 UDP 头） */
static struct udp_hdr *udp_of(struct pbuf *p, struct ip_hdr *iphdr)
{
    if (IPH_PROTO(iphdr) != IP_PROTO_UDP || (IPH_OFFSET(iphdr) & PP_HTONS(IP_OFFMASK)) != 0) {
        return NULL;
    }
    uint16_t hl = IPH_HL_BYTES(iphdr);
    if (p->len < hl + UDP_HLEN) {
        return NULL;
    }
    return (struct udp_hdr *)((uint8_t *)p->payload + hl);
}

/* 改源端口或目的端口，并按 RFC 1624 增量更新 UDP 校验和（校验和为 0 表示未启用，不动） */
static void set_port(struct udp_hdr *uh, bool dest, uint16_t newval)
{
    uint16_t old = dest ? uh->dest : uh->src;
    if (dest) {
        uh->dest = newval;
    } else {
        uh->src = newval;
    }
    if (uh->chksum != 0) {
        uint32_t sum = (uint16_t)~uh->chksum;
        sum += (uint16_t)~old;
        sum += newval;
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        uint16_t c = (uint16_t)~sum;
        uh->chksum = c ? c : 0xffff;        /* UDP 里 0 留给「未启用」 */
    }
}

static int slot_for(uint32_t cip, uint16_t port, uint32_t now)
{
    int free_i = -1, oldest = 0;
    for (int i = 0; i < LOWPORT_SLOTS; i++) {
        if (s_slots[i].cip == cip && s_slots[i].port == port) {
            return i;
        }
        if (s_slots[i].cip == 0 || now - s_slots[i].last > LOWPORT_IDLE_MS) {
            if (free_i < 0) {
                free_i = i;
            }
        } else if (now - s_slots[i].last > now - s_slots[oldest].last) {
            oldest = i;
        }
    }
    int i = free_i >= 0 ? free_i : oldest;      /* 表满：复用最久没用的 */
    s_slots[i].cip = cip;
    s_slots[i].port = port;
    return i;
}

err_t __wrap_ip_napt_forward(struct pbuf *p, struct ip_hdr *iphdr, struct netif *inp, struct netif *outp)
{
    if (inp->napt) {
        struct udp_hdr *uh = udp_of(p, iphdr);
        if (uh && uh->src != 0 && lwip_ntohs(uh->src) < 1024) {
            uint32_t now = sys_now();
            int i = slot_for(iphdr->src.addr, uh->src, now);
            s_slots[i].last = now;
            set_port(uh, false, lwip_htons(LOWPORT_ALIAS_BASE + i));
        }
    }
    return __real_ip_napt_forward(p, iphdr, inp, outp);
}

void __wrap_ip_napt_recv(struct pbuf *p, struct ip_hdr *iphdr)
{
    __real_ip_napt_recv(p, iphdr);      /* 命中映射时已把目的地址 / 端口还原为客户端 + 别名端口 */
    struct udp_hdr *uh = udp_of(p, iphdr);
    if (!uh) {
        return;
    }
    uint16_t dport = lwip_ntohs(uh->dest);
    if (dport < LOWPORT_ALIAS_BASE || dport >= LOWPORT_ALIAS_BASE + LOWPORT_SLOTS) {
        return;
    }
    lowport_slot_t *s = &s_slots[dport - LOWPORT_ALIAS_BASE];
    if (s->cip != 0 && s->cip == iphdr->dest.addr) {
        s->last = sys_now();
        set_port(uh, true, s->port);
    }
}

#endif /* IP_NAPT */
