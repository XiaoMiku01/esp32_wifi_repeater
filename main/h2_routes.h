#pragma once

#include <stdbool.h>
#include "esp_err.h"

#define H2_ROUTES_MAX       8
#define H2_ROUTE_PATH_MAX   64
#define H2_ROUTE_JSON_MAX   1024

/* 从 NVS 加载，须在 h2 站点和配置页启动前调用 */
void h2_routes_init(void);
/* 路径匹配：先按 h2_server 规则规范化（百分号解码、合并连续斜杠、去掉结尾斜杠），
 * 不区分大小写、不区分请求方法；按后缀整段匹配，/abc 命中 /abc、/a/abc、/b/abc，
 * 多条命中取最长的一条。保存时路径会被规范化，与已有路径等价时覆盖原条目 */
/* 新增或覆盖；失败时 err_msg 给出原因 */
esp_err_t h2_routes_set(const char *path, const char *json, const char **err_msg);
esp_err_t h2_routes_del(const char *path);
/* 新增或覆盖时 JSON 会被压缩（去掉字符串外的空白），md5 为压缩后 JSON 的小写 hex */
/* 按上述规则查找，持锁调用 fn(json, md5)，找不到返回 false；fn 内不要阻塞太久 */
bool h2_routes_with(const char *path, void (*fn)(const char *json, const char *md5, void *arg), void *arg);
/* 持锁遍历全部条目 */
void h2_routes_foreach(void (*fn)(const char *path, const char *json, void *arg), void *arg);
