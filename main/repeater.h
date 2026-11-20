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

/* Web 服务（web_server.c） */
esp_err_t web_server_start(void);
