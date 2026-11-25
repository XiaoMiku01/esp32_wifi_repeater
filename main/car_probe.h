/*
 * 特斯拉车机联网检测的本机应答（概览页「车机专用功能」里的开关，默认开启，存 NVS）
 *
 * 车机连上热点后用两个明文 HTTP 请求判断能否上网：
 *   GET  http://connman.vn.cloud.tesla.cn/online/status.html   期望 200 且带 X-ConnMan-Status: online
 *   HEAD http://<www.baidu.cn 解析出的 IP>/                     接入时一次，之后每 10 分钟一次；百度实际回 403
 *
 * 开启后：DNS 中继把这两个域名解析到 CAR_PROBE_ALIAS_IP（优先于 DNS 黑名单，低于自定义解析），
 * Web 服务按真实服务器的样子回包。上游没连上时车机也会认为热点可上网。
 *
 * 不能解析到 AP 地址：车机不连内网地址（实测）。所以另挂一个只有地址的别名网卡，
 * 地址取 203.0.113.80（RFC 5737 文档保留网段，公网上不存在），客户端发往它的包经网关（本机）时
 * 被 lwIP 当作本机地址收下，80 / 443 端口的服务照常应答。与 410 棒子上 DNAT 的地址相同。
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#define CAR_PROBE_CONNMAN_HOST  "connman.vn.cloud.tesla.cn"
#define CAR_PROBE_CONNMAN_PATH  "/online/status.html"
#define CAR_PROBE_HEAD_HOST     "www.baidu.cn"

#define CAR_PROBE_ALIAS_IP       "203.0.113.80"
/* 配置页域名：始终解析到别名地址（与开关无关），车机浏览器打开 http://esp.lan/ 即配置页
 * （车机浏览器同样不连内网地址）。自定义解析里设了同名条目时以自定义为准 */
#define CAR_PROBE_ADMIN_HOST    "esp.lan"

/* 挂上别名网卡（与开关无关，始终挂）；AP 网卡建好之后调用 */
void car_probe_alias_start(void);
/* 别名地址，网络字节序 */
uint32_t car_probe_alias_addr(void);
void car_probe_load(void);              /* NVS 初始化之后调用 */
bool car_probe_enabled(void);
esp_err_t car_probe_set(bool on);       /* 立即生效并写入 NVS */
/* name 须为小写、不带结尾点：应解析到别名地址时返回 true（配置页域名，或开启时的探测域名） */
bool car_probe_dns_match(const char *name);
