/* DNS 黑名单与例外，见 dns_filter.h */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "esp_log.h"
#include "dns_filter.h"

#define NVS_NS "dnsfilter"

static const char *TAG = "dns_filter";

typedef char rule_t[DNSF_NAME_MAX + 1];

static rule_t s_block[DNSF_BLOCK_MAX];
static rule_t s_allow[DNSF_ALLOW_MAX];
static int s_n_block, s_n_allow;
static SemaphoreHandle_t s_lock;

/* 通配符匹配：* 任意长度（含 0），? 单个字符 */
static bool glob_match(const char *p, const char *s)
{
    const char *star = NULL, *ss = NULL;
    while (*s) {
        if (*p == '?' || *p == *s) {
            p++;
            s++;
        } else if (*p == '*') {
            star = p++;
            ss = s;
        } else if (star) {
            p = star + 1;
            s = ++ss;
        } else {
            return false;
        }
    }
    while (*p == '*') {
        p++;
    }
    return *p == '\0';
}

dnsf_result_t dns_filter_check(const char *name, char *rule, size_t rule_cap)
{
    if (!s_lock || !name || !name[0]) {
        return DNSF_NONE;
    }
    dnsf_result_t r = DNSF_NONE;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_n_allow; i++) {
        if (strcmp(s_allow[i], name) == 0) {
            r = DNSF_ALLOW;
            if (rule) strlcpy(rule, s_allow[i], rule_cap);
            break;
        }
    }
    for (int i = 0; r == DNSF_NONE && i < s_n_block; i++) {
        if (glob_match(s_block[i], name)) {
            r = DNSF_BLOCK;
            if (rule) strlcpy(rule, s_block[i], rule_cap);
        }
    }
    xSemaphoreGive(s_lock);
    return r;
}

/* 规范化一行：去首尾空白、转小写、去结尾点并校验。返回 NULL 表示合法，否则为错误原因 */
static const char *normalize(const char *in, size_t n, bool wildcard, char *out)
{
    while (n && isspace((unsigned char)*in)) {
        in++;
        n--;
    }
    while (n && isspace((unsigned char)in[n - 1])) {
        n--;
    }
    while (n && in[n - 1] == '.') {
        n--;
    }
    if (n == 0) {
        return "为空";
    }
    if (n > DNSF_NAME_MAX) {
        return "超过 63 个字符";
    }
    bool has_alnum = false;
    for (size_t i = 0; i < n; i++) {
        char c = (char)tolower((unsigned char)in[i]);
        if (isalnum((unsigned char)c)) {
            has_alnum = true;
        } else if (!(c == '-' || c == '_' || c == '.' || (wildcard && (c == '*' || c == '?')))) {
            return wildcard ? "只能包含字母、数字、- _ . 和通配符 * ?" : "只能包含字母、数字、- _ .（例外须为完整域名，不支持通配符）";
        }
        if (c == '.' && (i == 0 || in[i - 1] == '.')) {
            return "域名格式错误（空标签）";
        }
        out[i] = c;
    }
    out[n] = '\0';
    if (!has_alnum) {
        return "规则过于宽泛（须包含字母或数字）";
    }
    return NULL;
}

/* 解析多行文本到 dst，返回条数；出错返回 -1 并写 err */
static int parse_list(const char *text, rule_t *dst, int max, bool wildcard, const char *what,
                      char *err, size_t err_cap)
{
    int n = 0, line = 0;
    const char *p = text ? text : "";
    while (*p) {
        const char *e = strchr(p, '\n');
        size_t len = e ? (size_t)(e - p) : strlen(p);
        line++;
        const char *q = p;
        size_t ql = len;
        while (ql && isspace((unsigned char)*q)) {
            q++;
            ql--;
        }
        if (ql && *q != '#') {
            rule_t r;
            const char *msg = normalize(q, ql, wildcard, r);
            if (msg) {
                snprintf(err, err_cap, "%s第 %d 行：%s", what, line, msg);
                return -1;
            }
            bool dup = false;
            for (int i = 0; i < n; i++) {
                if (strcmp(dst[i], r) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                if (n >= max) {
                    snprintf(err, err_cap, "%s最多 %d 条", what, max);
                    return -1;
                }
                strcpy(dst[n++], r);
            }
        }
        p = e ? e + 1 : p + len;
    }
    return n;
}

static esp_err_t save(const rule_t *blk, int nb, const rule_t *alw, int na)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    err = nvs_set_blob(h, "block", blk, sizeof(s_block));
    if (err == ESP_OK) err = nvs_set_u8(h, "nblock", (uint8_t)nb);
    if (err == ESP_OK) err = nvs_set_blob(h, "allow", alw, sizeof(s_allow));
    if (err == ESP_OK) err = nvs_set_u8(h, "nallow", (uint8_t)na);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    return err;
}

void dns_filter_load(void)
{
    s_lock = xSemaphoreCreateMutex();
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    uint8_t nb = 0, na = 0;
    size_t lb = sizeof(s_block), la = sizeof(s_allow);
    if (nvs_get_u8(h, "nblock", &nb) == ESP_OK && nvs_get_u8(h, "nallow", &na) == ESP_OK &&
        nvs_get_blob(h, "block", s_block, &lb) == ESP_OK && nvs_get_blob(h, "allow", s_allow, &la) == ESP_OK &&
        lb == sizeof(s_block) && la == sizeof(s_allow) && nb <= DNSF_BLOCK_MAX && na <= DNSF_ALLOW_MAX) {
        s_n_block = nb;
        s_n_allow = na;
        for (int i = 0; i < s_n_block; i++) s_block[i][DNSF_NAME_MAX] = '\0';
        for (int i = 0; i < s_n_allow; i++) s_allow[i][DNSF_NAME_MAX] = '\0';
    } else {
        memset(s_block, 0, sizeof(s_block));
        memset(s_allow, 0, sizeof(s_allow));
    }
    nvs_close(h);
    ESP_LOGI(TAG, "DNS 黑名单 %d 条，例外 %d 条", s_n_block, s_n_allow);
}

esp_err_t dns_filter_set(const char *block_text, const char *allow_text, char *err, size_t err_cap)
{
    rule_t *nb = calloc(DNSF_BLOCK_MAX, sizeof(rule_t));
    rule_t *na = calloc(DNSF_ALLOW_MAX, sizeof(rule_t));
    if (!nb || !na) {
        free(nb);
        free(na);
        snprintf(err, err_cap, "内存不足");
        return ESP_ERR_NO_MEM;
    }
    int cb = parse_list(block_text, nb, DNSF_BLOCK_MAX, true, "黑名单", err, err_cap);
    int ca = cb < 0 ? -1 : parse_list(allow_text, na, DNSF_ALLOW_MAX, false, "例外", err, err_cap);
    if (cb < 0 || ca < 0) {
        free(nb);
        free(na);
        return ESP_ERR_INVALID_ARG;
    }
    /* 先写 NVS，成功后再替换内存中的表（失败时不做修改） */
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = save(nb, cb, na, ca);
    if (e == ESP_OK) {
        memcpy(s_block, nb, sizeof(s_block));
        memcpy(s_allow, na, sizeof(s_allow));
        s_n_block = cb;
        s_n_allow = ca;
    } else {
        snprintf(err, err_cap, "写入 NVS 失败");
    }
    xSemaphoreGive(s_lock);
    free(nb);
    free(na);
    if (e == ESP_OK) {
        ESP_LOGI(TAG, "DNS 黑名单已更新：%d 条，例外 %d 条", cb, ca);
    }
    return e;
}

char *dns_filter_json(size_t *len)
{
    size_t cap = (DNSF_BLOCK_MAX + DNSF_ALLOW_MAX) * (DNSF_NAME_MAX + 4) + 96;
    char *b = malloc(cap);
    if (!b) return NULL;
    size_t o = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    o += snprintf(b + o, cap - o, "{\"max_block\":%d,\"max_allow\":%d,\"block\":[", DNSF_BLOCK_MAX, DNSF_ALLOW_MAX);
    for (int i = 0; i < s_n_block; i++) {
        o += snprintf(b + o, cap - o, "%s\"%s\"", i ? "," : "", s_block[i]);   /* 规则字符集已校验，无需转义 */
    }
    o += snprintf(b + o, cap - o, "],\"allow\":[");
    for (int i = 0; i < s_n_allow; i++) {
        o += snprintf(b + o, cap - o, "%s\"%s\"", i ? "," : "", s_allow[i]);
    }
    o += snprintf(b + o, cap - o, "]}");
    xSemaphoreGive(s_lock);
    *len = o;
    return b;
}
