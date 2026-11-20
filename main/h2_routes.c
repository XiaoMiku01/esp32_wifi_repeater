/*
 * HTTP/2 站点的自定义接口：path -> 固定 JSON 应答
 * 存在 NVS（命名空间 h2routes，键 p<N>/j<N>），由配置页增删，h2 站点按表应答。
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "esp_log.h"
#include "esp_rom_md5.h"
#include <strings.h>
#include "h2_routes.h"
#include "h2_server.h"

#define NVS_NS  "h2routes"

static const char *TAG = "h2_routes";

typedef struct {
    char path[H2_ROUTE_PATH_MAX + 1];
    char *json;                 /* 压缩后的 JSON；NULL 表示空槽 */
    char md5[33];               /* md5(json) 小写 hex，应答头 X-Checksum */
} entry_t;

static entry_t s_tab[H2_ROUTES_MAX];
static SemaphoreHandle_t s_lock;

/* 与 h2_test.c 中的内置接口冲突的路径 */
static const char *const s_reserved[] = { "/", "/ping", "/status", "/headers", "/echo" };

/* 去掉字符串外的空白（空格、制表、换行、回车），原地进行，返回新长度。
 * 只做压缩，不校验 JSON 语法 */
static size_t json_minify(char *s)
{
    size_t o = 0;
    bool in_str = false, esc = false;
    for (size_t i = 0; s[i]; i++) {
        char c = s[i];
        if (in_str) {
            if (esc) {
                esc = false;
            } else if (c == '\\') {
                esc = true;
            } else if (c == '"') {
                in_str = false;
            }
        } else if (c == '"') {
            in_str = true;
        } else if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        s[o++] = c;
    }
    s[o] = '\0';
    return o;
}

static void md5_hex(const char *data, char out[33])
{
    md5_context_t ctx;
    uint8_t d[ESP_ROM_MD5_DIGEST_LEN];
    esp_rom_md5_init(&ctx);
    esp_rom_md5_update(&ctx, data, strlen(data));
    esp_rom_md5_final(d, &ctx);
    for (int i = 0; i < ESP_ROM_MD5_DIGEST_LEN; i++) {
        snprintf(out + i * 2, 3, "%02x", d[i]);
    }
}

static void key_names(int i, char *pk, char *jk)
{
    snprintf(pk, 8, "p%d", i);
    snprintf(jk, 8, "j%d", i);
}

void h2_routes_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        return;
    }
    int n = 0;
    for (int i = 0; i < H2_ROUTES_MAX; i++) {
        char pk[8], jk[8];
        key_names(i, pk, jk);
        size_t plen = sizeof(s_tab[i].path), jlen = 0;
        if (nvs_get_str(h, pk, s_tab[i].path, &plen) != ESP_OK ||
            nvs_get_str(h, jk, NULL, &jlen) != ESP_OK || jlen == 0) {
            s_tab[i].path[0] = '\0';
            continue;
        }
        s_tab[i].json = malloc(jlen);
        if (s_tab[i].json && nvs_get_str(h, jk, s_tab[i].json, &jlen) == ESP_OK) {
            json_minify(s_tab[i].json);     /* 兼容旧版本存的未压缩 JSON */
            h2_path_normalize(s_tab[i].path);
            md5_hex(s_tab[i].json, s_tab[i].md5);
            n++;
        } else {
            free(s_tab[i].json);
            s_tab[i].json = NULL;
            s_tab[i].path[0] = '\0';
        }
    }
    nvs_close(h);
    ESP_LOGI(TAG, "已加载 %d 个自定义接口", n);
}

static const char *validate(const char *path, const char *json)
{
    size_t pl = strlen(path);
    if (pl < 2 || pl > H2_ROUTE_PATH_MAX || path[0] != '/') {
        return "路径须以 / 开头，长度 2-64";
    }
    for (const char *p = path; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20 || c == 0x7f || c == '?' || c == '#' || c == '*') {
            return "路径不能包含空白、?、#、*";
        }
    }
    for (size_t i = 0; i < sizeof(s_reserved) / sizeof(s_reserved[0]); i++) {
        if (strcasecmp(path, s_reserved[i]) == 0) {
            return "该路径为内置接口，不能覆盖";
        }
    }
    size_t jl = strlen(json);
    if (jl == 0 || jl > H2_ROUTE_JSON_MAX) {
        return "JSON 不能为空，压缩后不超过 1024 字节";
    }
    return NULL;
}

/* 与 h2_server 路由相同的规则规范化：百分号解码、合并斜杠、去结尾斜杠；
 * 比较时不区分大小写 */
static bool norm_path(const char *in, char *out, size_t cap)
{
    if (strlen(in) >= cap) {
        return false;
    }
    strcpy(out, in);
    h2_path_normalize(out);
    return true;
}

esp_err_t h2_routes_set(const char *path_in, const char *json_in, const char **err_msg)
{
    char path[H2_ROUTE_PATH_MAX * 3 + 1];
    if (!norm_path(path_in, path, sizeof(path))) {
        *err_msg = "路径须以 / 开头，长度 2-64";
        return ESP_ERR_INVALID_ARG;
    }
    char *copy = strdup(json_in);
    if (!copy) {
        *err_msg = "内存不足";
        return ESP_ERR_NO_MEM;
    }
    json_minify(copy);
    const char *json = copy;
    const char *msg = validate(path, json);
    if (msg) {
        free(copy);
        *err_msg = msg;
        return ESP_ERR_INVALID_ARG;
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int slot = -1, free_slot = -1;
    for (int i = 0; i < H2_ROUTES_MAX; i++) {
        if (s_tab[i].json && strcasecmp(s_tab[i].path, path) == 0) {
            slot = i;
            break;
        }
        if (!s_tab[i].json && free_slot < 0) {
            free_slot = i;
        }
    }
    if (slot < 0) {
        slot = free_slot;
    }
    esp_err_t err = ESP_OK;
    if (slot < 0) {
        *err_msg = "已达上限（8 个）";
        err = ESP_ERR_NO_MEM;
    } else {
        nvs_handle_t h;
        char pk[8], jk[8];
        key_names(slot, pk, jk);
        err = nvs_open(NVS_NS, NVS_READWRITE, &h);
        if (err == ESP_OK) {
            err = nvs_set_str(h, pk, path);
            if (err == ESP_OK) err = nvs_set_str(h, jk, json);
            if (err == ESP_OK) err = nvs_commit(h);
            nvs_close(h);
        }
        if (err != ESP_OK) {
            *err_msg = err == ESP_ERR_NVS_NOT_ENOUGH_SPACE ? "NVS 空间不足" : "写入 NVS 失败";
        } else {
            free(s_tab[slot].json);
            strlcpy(s_tab[slot].path, path, sizeof(s_tab[slot].path));
            s_tab[slot].json = copy;
            md5_hex(copy, s_tab[slot].md5);
            copy = NULL;
            *err_msg = NULL;
            ESP_LOGI(TAG, "已保存 %s（%u 字节）", path, (unsigned)strlen(json));
        }
    }
    free(copy);
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t h2_routes_del(const char *path_in)
{
    char path[H2_ROUTE_PATH_MAX * 3 + 1];
    if (!norm_path(path_in, path, sizeof(path))) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t err = ESP_ERR_NOT_FOUND;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < H2_ROUTES_MAX; i++) {
        if (s_tab[i].json && strcasecmp(s_tab[i].path, path) == 0) {
            nvs_handle_t h;
            char pk[8], jk[8];
            key_names(i, pk, jk);
            err = nvs_open(NVS_NS, NVS_READWRITE, &h);
            if (err == ESP_OK) {
                nvs_erase_key(h, pk);
                nvs_erase_key(h, jk);
                err = nvs_commit(h);
                nvs_close(h);
            }
            free(s_tab[i].json);
            s_tab[i].json = NULL;
            s_tab[i].path[0] = '\0';
            ESP_LOGI(TAG, "已删除 %s", path);
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

/* 配置路径（以 '/' 开头）在请求路径中的位置 k 处出现，且其后是 '\0' 或 '/'，即为整段命中。
 * 起点必为 '/'，终点检查保证不会切在段中间：
 *   /abc 命中 /abc、/a/abc、/abc/x、/a/abc/x；不命中 /xabc、/abcx */
static bool contains_segments(const char *req, size_t rlen, const char *pat, size_t plen)
{
    for (size_t k = 0; k + plen <= rlen; k++) {
        if (req[k] == '/' && strncasecmp(req + k, pat, plen) == 0 &&
            (req[k + plen] == '\0' || req[k + plen] == '/')) {
            return true;
        }
    }
    return false;
}

/* 任意位置整段匹配；多条命中时取最长（最具体）的一条，因此完全相同的路径优先 */
bool h2_routes_with(const char *path,
                    void (*fn)(const char *matched, const char *json, const char *md5, void *arg), void *arg)
{
    size_t rlen = strlen(path);
    int best = -1;
    size_t best_len = 0;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < H2_ROUTES_MAX; i++) {
        if (!s_tab[i].json) {
            continue;
        }
        size_t plen = strlen(s_tab[i].path);
        if (plen > best_len && contains_segments(path, rlen, s_tab[i].path, plen)) {
            best = i;
            best_len = plen;
        }
    }
    if (best >= 0) {
        fn(s_tab[best].path, s_tab[best].json, s_tab[best].md5, arg);
    }
    xSemaphoreGive(s_lock);
    return best >= 0;
}

void h2_routes_foreach(void (*fn)(const char *path, const char *json, void *arg), void *arg)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < H2_ROUTES_MAX; i++) {
        if (s_tab[i].json) {
            fn(s_tab[i].path, s_tab[i].json, arg);
        }
    }
    xSemaphoreGive(s_lock);
}
