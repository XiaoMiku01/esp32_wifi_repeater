/*
 * HTTP/2 站点配置：域名、证书链、私钥
 *
 * - 默认值：编译时内嵌的 main/certs2/ 证书与 H2_SITE_DEFAULT_DOMAIN
 * - 网页修改后存 NVS（命名空间 h2site：domain / cert / key），启动时优先使用
 * - 修改证书时用 mbedTLS 校验：证书链可解析、私钥可解析、二者配对；
 *   证书 SAN 不含该域名只给出警告，仍然保存
 * - 证书热替换到运行中的 h2 服务，新连接生效
 */
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "nvs.h"
#include "esp_log.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "repeater.h"
#include "h2_site.h"

#define NVS_NS "h2site"

static const char *TAG = "h2_site";

extern const uint8_t builtin_cert_start[] asm("_binary_www_aabbcc_com_fullchain_pem_start");
extern const uint8_t builtin_cert_end[]   asm("_binary_www_aabbcc_com_fullchain_pem_end");
extern const uint8_t builtin_key_start[]  asm("_binary_www_aabbcc_com_key_start");
extern const uint8_t builtin_key_end[]    asm("_binary_www_aabbcc_com_key_end");

static SemaphoreHandle_t s_lock;
static char s_domain[DNS_OVR_NAME_MAX + 1];
static bool s_domain_custom;
static const uint8_t *s_cert, *s_key;   /* PEM，长度含结尾 '\0' */
static size_t s_cert_len, s_key_len;
static bool s_cert_custom;
/* 启动时交给 h2 服务的缓冲区：服务可能仍在用（握手中），永不释放 */
static const uint8_t *s_pinned_cert, *s_pinned_key;
static h2_server_handle_t s_srv;

/* ---------- 工具 ---------- */

static bool is_builtin(const uint8_t *p)
{
    return p == builtin_cert_start || p == builtin_key_start;
}

static void free_buf(const uint8_t *p)
{
    if (p && !is_builtin(p) && p != s_pinned_cert && p != s_pinned_key) {
        free((void *)p);
    }
}

static const char *normalize_domain(const char *in, char *out)
{
    size_t n = strlen(in);
    if (n && in[n - 1] == '.') {
        n--;
    }
    if (n == 0 || n > DNS_OVR_NAME_MAX) {
        return "域名长度需为 1-63";
    }
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        char c = (char)tolower((unsigned char)in[i]);
        if (c == '.') {
            if (!label) {
                return "域名格式错误（空标签）";
            }
            label = 0;
        } else if (isalnum((unsigned char)c) || c == '-' || c == '_') {
            label++;
        } else {
            return "域名只能包含字母、数字、-、_、.";
        }
        out[i] = c;
    }
    if (!label) {
        return "域名格式错误（空标签）";
    }
    out[n] = '\0';
    return NULL;
}

/* 证书 SAN 中的 dNSName 是否匹配域名（支持一级通配 *.example.com） */
static bool san_matches(const mbedtls_x509_crt *crt, const char *domain)
{
    for (const mbedtls_x509_sequence *cur = &crt->subject_alt_names; cur; cur = cur->next) {
        if (!cur->buf.p || (cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) != MBEDTLS_X509_SAN_DNS_NAME) {
            continue;
        }
        const char *name = (const char *)cur->buf.p;
        size_t len = cur->buf.len;
        if (len == strlen(domain) && strncasecmp(name, domain, len) == 0) {
            return true;
        }
        if (len > 2 && name[0] == '*' && name[1] == '.') {
            const char *dot = strchr(domain, '.');
            if (dot && strlen(dot) == len - 1 && strncasecmp(dot, name + 1, len - 1) == 0) {
                return true;
            }
        }
    }
    return false;
}

/* 解析并校验证书链 + 私钥；crt 由调用方 init/free */
static const char *check_pair(mbedtls_x509_crt *crt, const uint8_t *cert, size_t cert_len,
                              const uint8_t *key, size_t key_len)
{
    int ret = mbedtls_x509_crt_parse(crt, cert, cert_len);
    if (ret != 0) {
        ESP_LOGW(TAG, "证书解析失败 -0x%04x", -ret);
        return "证书解析失败，需为 PEM 格式的证书链";
    }
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    const char *msg = NULL;
    ret = mbedtls_pk_parse_key(&pk, key, key_len, NULL, 0);
    if (ret != 0) {
        ESP_LOGW(TAG, "私钥解析失败 -0x%04x", -ret);
        msg = "私钥解析失败，需为未加密的 PEM 私钥";
    } else if ((ret = mbedtls_pk_check_pair(&crt->pk, &pk)) != 0) {
        ESP_LOGW(TAG, "证书与私钥不配对 -0x%04x", -ret);
        msg = "证书与私钥不匹配（私钥须对应证书链中的第一张证书）";
    }
    mbedtls_pk_free(&pk);
    return msg;
}

/* 复制为以 '\0' 结尾的 PEM 缓冲区 */
static uint8_t *pem_copy(const char *s, size_t *out_len)
{
    size_t n = strlen(s) + 1;
    uint8_t *d = malloc(n);
    if (d) {
        memcpy(d, s, n);
        *out_len = n;
    }
    return d;
}

/* 把 DNS 自定义解析中 old 的条目移到 new；old 没有条目时为 new 新增指向 AP 的条目。
 * new 已有条目时保持不变 */
static void move_dns(const char *old, const char *new_domain)
{
    if (strcmp(old, new_domain) == 0) {
        return;
    }
    uint32_t ip = 0, tmp;
    bool had_old = dns_relay_get_override(old, &ip);
    if (!dns_relay_get_override(new_domain, &tmp)) {
        const char *m;
        dns_relay_set_override(new_domain, had_old ? ip : 0, &m);
    }
    if (had_old) {
        dns_relay_del_override(old);
    }
}

/* ---------- 对外接口 ---------- */

void h2_site_load(void)
{
    s_lock = xSemaphoreCreateMutex();
    strlcpy(s_domain, H2_SITE_DEFAULT_DOMAIN, sizeof(s_domain));
    s_cert = builtin_cert_start;
    s_cert_len = builtin_cert_end - builtin_cert_start;
    s_key = builtin_key_start;
    s_key_len = builtin_key_end - builtin_key_start;

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        ESP_LOGI(TAG, "使用内嵌域名与证书");
        return;
    }
    char dom[sizeof(s_domain)];
    size_t dlen = sizeof(dom);
    if (nvs_get_str(h, "domain", dom, &dlen) == ESP_OK) {
        strlcpy(s_domain, dom, sizeof(s_domain));
        s_domain_custom = true;
    }

    size_t clen = 0, klen = 0;
    if (nvs_get_blob(h, "cert", NULL, &clen) == ESP_OK && nvs_get_blob(h, "key", NULL, &klen) == ESP_OK &&
        clen && klen) {
        uint8_t *c = malloc(clen), *k = malloc(klen);
        if (c && k && nvs_get_blob(h, "cert", c, &clen) == ESP_OK &&
            nvs_get_blob(h, "key", k, &klen) == ESP_OK) {
            mbedtls_x509_crt crt;
            mbedtls_x509_crt_init(&crt);
            const char *msg = check_pair(&crt, c, clen, k, klen);
            mbedtls_x509_crt_free(&crt);
            if (!msg) {
                s_cert = c; s_cert_len = clen;
                s_key = k; s_key_len = klen;
                s_cert_custom = true;
                c = k = NULL;
            } else {
                ESP_LOGW(TAG, "NVS 中的证书无效（%s），改用内嵌证书", msg);
            }
        }
        free(c);
        free(k);
    }
    nvs_close(h);
    ESP_LOGI(TAG, "站点 %s，证书：%s", s_domain, s_cert_custom ? "网页配置" : "内嵌");
}

void h2_site_get_domain(char *out, size_t cap)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    strlcpy(out, s_domain, cap);
    xSemaphoreGive(s_lock);
}

void h2_site_get_cert(const uint8_t **cert, size_t *cert_len, const uint8_t **key, size_t *key_len)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    *cert = s_cert; *cert_len = s_cert_len;
    *key = s_key;   *key_len = s_key_len;
    s_pinned_cert = s_cert;
    s_pinned_key = s_key;
    xSemaphoreGive(s_lock);
}

void h2_site_set_server(h2_server_handle_t srv)
{
    s_srv = srv;
}

esp_err_t h2_site_update(const char *domain, const char *cert_pem, const char *key_pem,
                         const char **err_msg, char *warn, size_t warn_cap)
{
    warn[0] = '\0';
    char dom[DNS_OVR_NAME_MAX + 1];
    const char *msg = normalize_domain(domain ? domain : "", dom);
    if (msg) {
        *err_msg = msg;
        return ESP_ERR_INVALID_ARG;
    }
    bool new_cert = cert_pem && cert_pem[0];
    bool new_key = key_pem && key_pem[0];
    if (new_cert != new_key) {
        *err_msg = "证书和私钥须同时提供（只改域名时两者都留空）";
        return ESP_ERR_INVALID_ARG;
    }
    if (new_cert && (strlen(cert_pem) > H2_SITE_CERT_MAX || strlen(key_pem) > H2_SITE_KEY_MAX)) {
        *err_msg = "证书不超过 8KB，私钥不超过 4KB";
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = ESP_OK;
    uint8_t *c = NULL, *k = NULL;
    size_t clen = 0, klen = 0;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    bool crt_ok = false;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (new_cert) {
        c = pem_copy(cert_pem, &clen);
        k = pem_copy(key_pem, &klen);
        if (!c || !k) {
            *err_msg = "内存不足";
            err = ESP_ERR_NO_MEM;
            goto out;
        }
        if ((msg = check_pair(&crt, c, clen, k, klen)) != NULL) {
            *err_msg = msg;
            err = ESP_ERR_INVALID_ARG;
            goto out;
        }
        crt_ok = true;
    } else {
        crt_ok = mbedtls_x509_crt_parse(&crt, s_cert, s_cert_len) == 0;
    }
    if (crt_ok && !san_matches(&crt, dom)) {
        snprintf(warn, warn_cap, "证书的 SAN 中不包含 %s，浏览器会提示证书与域名不符", dom);
    }

    /* 写 NVS */
    nvs_handle_t h;
    err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        err = nvs_set_str(h, "domain", dom);
        if (err == ESP_OK && new_cert) err = nvs_set_blob(h, "cert", c, clen);
        if (err == ESP_OK && new_cert) err = nvs_set_blob(h, "key", k, klen);
        if (err == ESP_OK) err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) {
        *err_msg = err == ESP_ERR_NVS_NOT_ENOUGH_SPACE ? "NVS 空间不足" : "写入 NVS 失败";
        goto out;
    }

    if (new_cert) {
        if (s_srv) {
            h2_server_set_cert(s_srv, c, clen, k, klen);   /* 服务内部复制 */
        }
        free_buf(s_cert);
        free_buf(s_key);
        s_cert = c; s_cert_len = clen;
        s_key = k;  s_key_len = klen;
        s_cert_custom = true;
        c = k = NULL;
    }
    char old[sizeof(s_domain)];
    strlcpy(old, s_domain, sizeof(old));
    strlcpy(s_domain, dom, sizeof(s_domain));
    s_domain_custom = true;
    xSemaphoreGive(s_lock);

    move_dns(old, dom);
    ESP_LOGI(TAG, "站点已更新：%s%s%s", dom, new_cert ? "，证书已替换" : "", warn[0] ? "（域名与证书不符）" : "");
    mbedtls_x509_crt_free(&crt);
    *err_msg = NULL;
    return ESP_OK;

out:
    xSemaphoreGive(s_lock);
    mbedtls_x509_crt_free(&crt);
    free(c);
    free(k);
    return err;
}

esp_err_t h2_site_reset(void)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err == ESP_OK) {
        nvs_erase_all(h);
        err = nvs_commit(h);
        nvs_close(h);
    }
    if (err != ESP_OK) {
        return err;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    char old[sizeof(s_domain)];
    strlcpy(old, s_domain, sizeof(old));
    if (s_cert_custom) {
        free_buf(s_cert);
        free_buf(s_key);
        s_cert = builtin_cert_start;
        s_cert_len = builtin_cert_end - builtin_cert_start;
        s_key = builtin_key_start;
        s_key_len = builtin_key_end - builtin_key_start;
        s_cert_custom = false;
        if (s_srv) {
            h2_server_set_cert(s_srv, s_cert, s_cert_len, s_key, s_key_len);
        }
    }
    strlcpy(s_domain, H2_SITE_DEFAULT_DOMAIN, sizeof(s_domain));
    s_domain_custom = false;
    xSemaphoreGive(s_lock);

    move_dns(old, H2_SITE_DEFAULT_DOMAIN);
    ESP_LOGI(TAG, "已恢复内嵌域名与证书");
    return ESP_OK;
}

static size_t json_esc(char *out, size_t cap, const char *s)
{
    size_t o = 0;
    for (; *s && o + 7 < cap; s++) {
        unsigned char ch = (unsigned char)*s;
        if (ch == '"' || ch == '\\') {
            out[o++] = '\\';
            out[o++] = ch;
        } else if (ch < 0x20) {
            o += snprintf(out + o, cap - o, "\\u%04x", ch);
        } else {
            out[o++] = ch;
        }
    }
    out[o] = '\0';
    return o;
}

void h2_site_export(void (*fn)(const char *domain, const char *cert, const char *key, void *arg), void *arg)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    fn(s_domain, s_cert_custom ? (const char *)s_cert : NULL, s_cert_custom ? (const char *)s_key : NULL, arg);
    xSemaphoreGive(s_lock);
}

int h2_site_info_json(char *out, size_t cap)
{
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    char dn[256], subj[300] = "", iss[300] = "", san[400] = "";
    char nb[24] = "", na[24] = "";
    bool match = false, ok;

    xSemaphoreTake(s_lock, portMAX_DELAY);
    ok = mbedtls_x509_crt_parse(&crt, s_cert, s_cert_len) == 0;
    if (ok) {
        if (mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.subject) > 0) json_esc(subj, sizeof(subj), dn);
        if (mbedtls_x509_dn_gets(dn, sizeof(dn), &crt.issuer) > 0) json_esc(iss, sizeof(iss), dn);
        snprintf(nb, sizeof(nb), "%04d-%02d-%02d %02d:%02d:%02d", crt.valid_from.year, crt.valid_from.mon,
                 crt.valid_from.day, crt.valid_from.hour, crt.valid_from.min, crt.valid_from.sec);
        snprintf(na, sizeof(na), "%04d-%02d-%02d %02d:%02d:%02d", crt.valid_to.year, crt.valid_to.mon,
                 crt.valid_to.day, crt.valid_to.hour, crt.valid_to.min, crt.valid_to.sec);
        size_t o = 0;
        for (const mbedtls_x509_sequence *cur = &crt.subject_alt_names; cur; cur = cur->next) {
            if (!cur->buf.p || (cur->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) != MBEDTLS_X509_SAN_DNS_NAME) {
                continue;
            }
            char name[128];
            size_t n = cur->buf.len < sizeof(name) - 1 ? cur->buf.len : sizeof(name) - 1;
            memcpy(name, cur->buf.p, n);
            name[n] = '\0';
            char esc[260];
            json_esc(esc, sizeof(esc), name);
            int w = snprintf(san + o, sizeof(san) - o, "%s\"%s\"", o ? "," : "", esc);
            if (w < 0 || (size_t)w >= sizeof(san) - o) {
                break;
            }
            o += w;
        }
        match = san_matches(&crt, s_domain);
    }
    int n = snprintf(out, cap,
                     "{\"domain\":\"%s\",\"port\":%d,\"domain_source\":\"%s\",\"cert_source\":\"%s\","
                     "\"cert_ok\":%s,\"subject\":\"%s\",\"issuer\":\"%s\",\"not_before\":\"%s\","
                     "\"not_after\":\"%s\",\"san\":[%s],\"domain_match\":%s,"
                     "\"max_cert\":%d,\"max_key\":%d}",
                     s_domain, H2_SITE_PORT, s_domain_custom ? "web" : "builtin",
                     s_cert_custom ? "web" : "builtin", ok ? "true" : "false", subj, iss, nb, na, san,
                     match ? "true" : "false", H2_SITE_CERT_MAX, H2_SITE_KEY_MAX);
    xSemaphoreGive(s_lock);
    mbedtls_x509_crt_free(&crt);
    return n;
}
