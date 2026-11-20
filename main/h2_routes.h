#pragma once

#include <stdbool.h>
#include "esp_err.h"

#define H2_ROUTES_MAX       8
#define H2_ROUTE_PATH_MAX   64
#define H2_ROUTE_JSON_MAX   1024

/* 从 NVS 加载，须在 h2 站点和配置页启动前调用 */
void h2_routes_init(void);
/* 新增或覆盖；失败时 err_msg 给出原因 */
esp_err_t h2_routes_set(const char *path, const char *json, const char **err_msg);
esp_err_t h2_routes_del(const char *path);
/* 持锁调用 fn(json)，找不到返回 false；fn 内不要阻塞太久 */
bool h2_routes_with(const char *path, void (*fn)(const char *json, void *arg), void *arg);
/* 持锁遍历全部条目 */
void h2_routes_foreach(void (*fn)(const char *path, const char *json, void *arg), void *arg);
