/*
 * 注入 lwIP 的自定义钩子（经 ESP_IDF_LWIP_HOOK_FILENAME，仅对 lwip 组件生效，见 main/CMakeLists.txt）
 * LWIP_HOOK_IP4_CANFORWARD 在 ip4_forward 中、NAPT 转换之前调用：
 * 返回 -1 走默认判断，0 丢弃，1 允许转发
 */
#pragma once
#include <stdint.h>

struct pbuf;
int monitor_ip4_canforward(struct pbuf *p, uint32_t dest_host_order);

#define LWIP_HOOK_IP4_CANFORWARD(p, dest) monitor_ip4_canforward((p), (dest))
