/*
 * h2_server：基于 esp-tls（服务端 + ALPN）与 nghttp2 的 HTTP/2 服务端
 *
 * - 仅支持 TLS 上的 HTTP/2（h2），浏览器不支持明文 h2c
 * - 每个连接一个任务；请求收齐（END_STREAM）后同步调用处理函数
 * - 处理函数内调用 h2_resp_send() 一次性给出响应（状态码、头、正文）
 * - ALPN 协商到 http/1.1 或未使用 ALPN 的客户端走 HTTP/1.1（支持持久连接、
 *   Content-Length 请求体；不支持 chunked 请求体），路由与处理函数相同
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "esp_err.h"
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct h2_server *h2_server_handle_t;
typedef struct h2_req h2_req_t;

typedef esp_err_t (*h2_handler_t)(h2_req_t *req);

typedef struct {
    const char *method;     /* "GET"、"POST"…；NULL 表示任意方法 */
    const char *path;       // 精确匹配；以 '*' 结尾表示前缀匹配，如 "/api/*"
    h2_handler_t handler;
    void *user_ctx;
} h2_route_t;

/* 客户端证书（mTLS）处理方式 */
typedef enum {
    H2_CLIENT_AUTH_IGNORE = 0,  /* 默认：不请求客户端证书；客户端配置了 mTLS 也照常连接，证书被忽略 */
    H2_CLIENT_AUTH_OPTIONAL,    /* 请求并校验，客户端不给证书也放行（需开启
                                   CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL） */
    H2_CLIENT_AUTH_REQUIRED,    /* 必须提供由 client_ca 签发的证书，否则握手失败 */
} h2_client_auth_t;

typedef struct {
    uint16_t port;
    const uint8_t *cert_pem;    /* 服务器证书 PEM，长度含结尾 '\0' */
    size_t cert_len;
    const uint8_t *key_pem;     /* 私钥 PEM，长度含结尾 '\0' */
    size_t key_len;
    h2_client_auth_t client_auth;   /* 默认 H2_CLIENT_AUTH_IGNORE */
    const uint8_t *client_ca_pem;   /* OPTIONAL/REQUIRED 时用于校验客户端证书的 CA，长度含 '\0' */
    size_t client_ca_len;
    uint8_t max_conns;          /* 同时连接数，超出直接关闭 */
    uint32_t max_streams;       /* 每连接并发流（SETTINGS_MAX_CONCURRENT_STREAMS） */
    size_t max_body;            /* 请求体上限，超出回 413 */
    size_t max_header_bytes;    /* 单个请求头总字节上限 */
    uint32_t idle_timeout_ms;   /* 连接空闲超时，到期发送 GOAWAY 后关闭 */
    uint32_t task_stack;
    UBaseType_t task_prio;
    uint8_t max_routes;
} h2_server_config_t;

#define H2_SERVER_DEFAULT_CONFIG() {    \
    .port = 8443,                       \
    .client_auth = H2_CLIENT_AUTH_IGNORE, \
    .max_conns = 3,                     \
    .max_streams = 8,                   \
    .max_body = 16 * 1024,              \
    .max_header_bytes = 4096,           \
    .idle_timeout_ms = 30000,           \
    .task_stack = 8192,                 \
    .task_prio = 5,                     \
    .max_routes = 16,                   \
}

/* 启动监听。证书/私钥缓冲区须在服务运行期间保持有效 */
esp_err_t h2_server_start(const h2_server_config_t *cfg, h2_server_handle_t *out);
esp_err_t h2_server_register(h2_server_handle_t srv, const h2_route_t *route);
/* 替换服务器证书链和私钥（PEM，内部复制）。只影响之后的新连接，已建立的连接不受影响。
 * 调用方应先校验证书与私钥配对，否则新连接握手会失败 */
esp_err_t h2_server_set_cert(h2_server_handle_t srv, const uint8_t *cert_pem, size_t cert_len,
                             const uint8_t *key_pem, size_t key_len);
/* 停止接受新连接；已有连接在当前请求处理完或空闲超时后退出 */
void h2_server_stop(h2_server_handle_t srv);

/* ---- 请求 ---- */
const char *h2_req_method(const h2_req_t *req);
const char *h2_req_path(const h2_req_t *req);    /* 不含查询串 */
const char *h2_req_query(const h2_req_t *req);   /* '?' 之后部分，没有则为 "" */
const char *h2_req_authority(const h2_req_t *req);
int32_t h2_req_stream_id(const h2_req_t *req);  /* HTTP/1.1 请求为 0 */
const char *h2_req_proto(const h2_req_t *req);  /* "h2" 或 "http/1.1" */
const char *h2_req_peer(const h2_req_t *req);    /* 客户端 IP 字符串 */
/* 按名查找请求头（不区分大小写），没有返回 NULL */
const char *h2_req_header(const h2_req_t *req, const char *name);
/* 遍历请求头，cb 返回 false 停止 */
void h2_req_foreach_header(const h2_req_t *req,
                           bool (*cb)(const char *name, const char *value, void *arg), void *arg);
const uint8_t *h2_req_body(const h2_req_t *req, size_t *len);
void *h2_req_user_ctx(const h2_req_t *req);

/* ---- 响应（每个请求调用一次） ---- */
/* 追加响应头，须在 h2_resp_send 之前调用；name 须为小写 */
esp_err_t h2_resp_add_header(h2_req_t *req, const char *name, const char *value);
/* 发送响应，body 会被复制；content_type 可为 NULL */
esp_err_t h2_resp_send(h2_req_t *req, int status, const char *content_type,
                       const void *body, size_t len);
static inline esp_err_t h2_resp_sendstr(h2_req_t *req, int status, const char *content_type,
                                        const char *str)
{
    return h2_resp_send(req, status, content_type, str, str ? strlen(str) : 0);
}

#ifdef __cplusplus
}
#endif
