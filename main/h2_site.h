#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "h2_server.h"

#define H2_SITE_CERT_MAX  8192      /* 证书链 PEM 上限（字节） */
#define H2_SITE_KEY_MAX   4096      /* 私钥 PEM 上限（字节） */

/* 从 NVS 加载域名、证书、私钥；缺失或无效时使用编译时内嵌的默认值。
 * 须在 NVS 初始化之后、h2_test_start 之前调用 */
void h2_site_load(void);

void h2_site_get_domain(char *out, size_t cap);
/* 当前证书/私钥（PEM，长度含结尾 '\0'），用于启动服务；指针在下一次修改前有效 */
void h2_site_get_cert(const uint8_t **cert, size_t *cert_len, const uint8_t **key, size_t *key_len);
/* h2 服务启动后登记，之后修改证书会热替换到该服务 */
void h2_site_set_server(h2_server_handle_t srv);

/* 修改站点：domain 必填；cert_pem 与 key_pem 要么都给（替换证书），要么都为 NULL（沿用当前证书）。
 * 证书/私钥解析失败或不配对时返回错误并写 err_msg；证书不含该域名时仍保存，warn 写入提示。
 * 域名变化时，DNS 自定义解析里旧域名的条目会改到新域名。 */
esp_err_t h2_site_update(const char *domain, const char *cert_pem, const char *key_pem,
                         const char **err_msg, char *warn, size_t warn_cap);
/* 清除网页配置，恢复内嵌的域名和证书 */
esp_err_t h2_site_reset(void);

/* 持锁回调当前域名与证书；使用内嵌证书时 cert/key 为 NULL（用于导出配置，含私钥） */
void h2_site_export(void (*fn)(const char *domain, const char *cert, const char *key, void *arg), void *arg);

/* 以 JSON 对象输出当前站点信息（不含私钥） */
int h2_site_info_json(char *out, size_t cap);
