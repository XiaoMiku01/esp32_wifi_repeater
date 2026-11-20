/*
 * DNS 黑名单（存 NVS，配置页修改）
 *
 * - 黑名单规则：不含通配符时精确匹配；* 匹配任意字符（含 .），? 匹配单个字符，不区分大小写
 *     example.com        只拦截 example.com
 *     *.example.com      拦截所有子域名（不含 example.com 本身）
 *     ads*.example.com   拦截 ads1.example.com、ads-cdn.example.com 等
 * - 例外：完整域名，命中例外的域名不受黑名单影响
 * - 被拦截的查询回 NXDOMAIN
 */
#pragma once

#include <stddef.h>
#include "esp_err.h"

#define DNSF_BLOCK_MAX  64
#define DNSF_ALLOW_MAX  32
#define DNSF_NAME_MAX   63

typedef enum {
    DNSF_NONE = 0,      /* 未命中，照常处理 */
    DNSF_BLOCK,         /* 命中黑名单 */
    DNSF_ALLOW,         /* 命中例外（即使同时匹配黑名单也放行） */
} dnsf_result_t;

void dns_filter_load(void);

/* name 须为小写、不带结尾点；rule 输出命中的规则，可为 NULL */
dnsf_result_t dns_filter_check(const char *name, char *rule, size_t rule_cap);

/* 整体替换两张表；文本按行分隔，忽略空行和 # 开头的行。失败时 err 给出原因（含行号），不做修改 */
esp_err_t dns_filter_set(const char *block_text, const char *allow_text, char *err, size_t err_cap);

/* {"block":[...],"allow":[...],"max_block":N,"max_allow":N}，malloc 的缓冲区，调用方 free */
char *dns_filter_json(size_t *len);
