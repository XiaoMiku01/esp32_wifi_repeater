/*
 * 流量记录与拦截（本次开机内，数据只存内存；黑名单存 NVS）
 *
 * - 客户端：AP 接入/离开、DHCP 分配的 IP 与主机名、累计流量、实时速率、DNS 查询数
 * - DNS 记录：经 DNS 中继的每条查询（客户端、域名、类型、结果、应答 IP）
 * - 连接：经本机转发的每条连接（5 元组），类型、域名（DNS 应答 / TLS SNI / HTTP Host）、
 *   实时上下行速率；由 lwIP 转发钩子 LWIP_HOOK_IP4_CANFORWARD 统计
 * - 黑名单：域名（含子域名）不再解析（NXDOMAIN）；已知 IP 与匹配的连接丢包，
 *   已建立的 TCP 连接向客户端发 RST 断开
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_netif.h"

#define MON_BLOCK_MAX   32
#define MON_NAME_MAX    63

void monitor_init(esp_netif_t *ap);

/* Wi-Fi / DHCP 事件 */
void monitor_on_join(const uint8_t mac[6]);
void monitor_on_leave(const uint8_t mac[6]);
void monitor_on_ip(const uint8_t mac[6], uint32_t ip, const char *hostname);

/* DNS 中继 */
typedef enum {
    MON_DNS_FORWARD = 0,    /* 转发上游 */
    MON_DNS_LOCAL,          /* 自定义解析，本地应答 */
    MON_DNS_BLOCKED,        /* 黑名单，回 NXDOMAIN */
} mon_dns_result_t;

bool monitor_is_blocked(const char *name);
/* 记录一条查询，返回记录 id（local 时 ip 为应答地址） */
uint32_t monitor_dns_query(uint32_t client_ip, const char *name, uint16_t qtype,
                           mon_dns_result_t res, uint32_t local_ip);
/* 上游应答：补充记录中的应答 IP，并学习 IP -> 域名 */
void monitor_dns_answer(uint32_t log_id, const char *name, const uint32_t *ips, int n);

/* 黑名单（存 NVS） */
esp_err_t monitor_block_add(const char *domain, const char **err_msg);
esp_err_t monitor_block_del(const char *domain);

/* JSON 输出，返回 malloc 的缓冲区，调用方 free */
char *monitor_live_json(size_t *len);
char *monitor_dns_json(uint32_t since, size_t *len);
char *monitor_block_json(size_t *len);
char *monitor_bench_json(size_t *len);

void monitor_set_enabled(bool en);
void monitor_reset_perf(void);

/* lwIP 钩子（见 main/lwip_hook/monitor_lwip_hook.h） */
struct pbuf;
int monitor_ip4_canforward(struct pbuf *p, uint32_t dest_host_order);
