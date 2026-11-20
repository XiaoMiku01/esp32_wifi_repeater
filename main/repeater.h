#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "esp_netif.h"

typedef struct {
    char sta_ssid[33];
    char sta_pass[65];
    char ap_ssid[33];
    char ap_pass[65];
    uint8_t ap_max_conn;
} repeater_cfg_t;

typedef struct {
    bool sta_connected;
    char sta_ip[16];
    char sta_gw[16];
    char ap_ip[16];
    int8_t rssi;
    uint8_t channel;
    int clients;
    uint32_t uptime_s;
    uint32_t free_heap;
} repeater_status_t;

typedef struct {
    char ssid[33];
    int8_t rssi;
    uint8_t channel;
    bool open;
} repeater_scan_item_t;

/* 配置（repeater_config.c） */
void repeater_cfg_load(repeater_cfg_t *cfg);
esp_err_t repeater_cfg_save(const repeater_cfg_t *cfg);
/* 校验，失败时返回错误描述，成功返回 NULL */
const char *repeater_cfg_validate(const repeater_cfg_t *cfg);

/* Wi-Fi（wifi_repeater.c） */
void repeater_get_cfg(repeater_cfg_t *out);
/* 校验并保存到 NVS，随后异步应用到 Wi-Fi（AP 客户端会被断开重连） */
esp_err_t repeater_set_cfg(const repeater_cfg_t *cfg, const char **err_msg);
void repeater_get_status(repeater_status_t *st);
/* 阻塞扫描周边网络，按信号强度降序、同名去重；返回条数，失败返回 -1 */
int repeater_scan(repeater_scan_item_t *out, int max);

/* 日志转发（web_log.c） */
void web_log_init(void);

/* DNS 中继（dns_relay.c） */
void dns_relay_start(esp_netif_t *ap, esp_netif_t *sta);
/* 自定义解析表（存 NVS）：ip 为网络字节序，0 表示 AP 地址 */
#define DNS_OVR_MAX       16
#define DNS_OVR_NAME_MAX  63
void dns_relay_load_overrides(void);    /* NVS 初始化之后、dns_relay_start 之前调用 */
esp_err_t dns_relay_set_override(const char *name, uint32_t ip, const char **err_msg);
esp_err_t dns_relay_del_override(const char *name);
void dns_relay_foreach_override(void (*fn)(const char *name, uint32_t ip, void *arg), void *arg);

/* Web 服务（web_server.c） */
esp_err_t web_server_start(void);

/* HTTP/2 站点（h2_test.c）：端口 443，证书为 main/certs2/ 下的该域名证书，
 * DNS 中继把该域名解析到 AP 地址 */
#define H2_SITE_DOMAIN  "www.aabbcc.com"
#define H2_SITE_PORT    443
esp_err_t h2_test_start(void);
