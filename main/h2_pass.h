/*
 * HTTPS 站点的临时 TLS 透传（概览页「车机专用功能」里的「恢复语音」开关，默认关闭，存 NVS）
 *
 * 站点域名（如 api-prd.vn.cloud.tesla.cn）被自定义解析到本机后，所有请求都由本机应答。
 * 有些接口必须由真实服务器处理（实测：车机语音要用 /mothership/vehicles/<VIN>/jwt_token 换令牌，
 * 本机回 404 时语音失效）。开启后：
 *   1. 请求路径命中 H2_PASS_TRIGGER_* 时本机不应答，拒绝该请求并关闭连接，客户端会重连重试；
 *   2. 此后 secs 秒内，443 端口新进来的连接不做本机 TLS，原样转发到站点域名的真实服务器（TLS 透传）；
 *   3. 窗口结束后新连接恢复由本机处理；透传中的连接在窗口结束后空闲即关闭（最多再留 H2_PASS_LINGER_MS）。
 * 自定义接口优先：路径同时命中自定义接口时照常由本机应答，不触发透传。
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "h2_server.h"

/* 触发条件：路径以 PREFIX 开头且以 SUFFIX 结尾（不区分大小写，不含查询串） */
#define H2_PASS_TRIGGER_PREFIX  "/mothership/vehicles/"
#define H2_PASS_TRIGGER_SUFFIX  "/jwt_token"

#define H2_PASS_SECS_DEFAULT    3
#define H2_PASS_SECS_MAX        60

typedef struct {
    bool enabled;
    uint8_t secs;           /* 透传窗口，1..H2_PASS_SECS_MAX 秒 */
    bool active;            /* 当前在透传窗口内 */
    uint8_t conns;          /* 正在透传的连接数 */
    uint32_t triggers;      /* 本次开机触发次数 */
    uint32_t relayed;       /* 本次开机透传的连接数 */
    uint32_t fc_hits;       /* 本次开机自定义接口命中 feature_configuration 的次数 */
    int32_t fc_ago_s;       /* 上次命中距今秒数；本次开机还没命中过为 -1 */
} h2_pass_info_t;

void h2_pass_load(void);                        /* NVS 初始化之后调用 */
void h2_pass_attach(h2_server_handle_t srv);    /* 站点服务启动后调用，挂上新连接钩子 */
void h2_pass_get(h2_pass_info_t *out);
esp_err_t h2_pass_set(bool enabled, int secs);  /* 立即生效并写入 NVS */
/* 请求未命中自定义接口时调用：命中触发路径且功能开启则开始透传窗口并拒绝该请求，返回 true */
bool h2_pass_try_trigger(h2_req_t *req);
/* 自定义接口命中时调用：请求路径含 H2_PASS_FEATURE_CFG 时记下命中时刻（只存内存），供概览页显示 */
#define H2_PASS_FEATURE_CFG     "feature_configuration"
void h2_pass_note_hit(const char *req_path);
