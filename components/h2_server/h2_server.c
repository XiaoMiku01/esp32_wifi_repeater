/*
 * h2_server 实现
 *
 * 结构：
 *   accept 任务 ──accept──> 每连接一个任务：
 *       esp-tls 服务端握手（ALPN 协商 h2）
 *       nghttp2 服务端会话：TLS 读 -> nghttp2_session_mem_recv2 -> 回调收集请求
 *       请求收齐 -> 路由 -> 处理函数 -> h2_resp_send -> nghttp2_submit_response2
 *       nghttp2_session_send -> send 回调 -> TLS 写
 */
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_tls.h"
#include "mbedtls/ssl.h"
#include "lwip/sockets.h"
#include "nghttp2/nghttp2.h"
#include "h2_server.h"

static const char *TAG = "h2";

#define RX_BUF_SIZE   4096

typedef struct h2_hdr {
    struct h2_hdr *next;
    char *name;
    char *value;
} h2_hdr_t;

/* 服务器证书与私钥。握手时取一个引用，握手结束即释放（mbedTLS 解析时已复制）；
 * 替换证书后，旧证书在最后一个握手结束时释放 */
typedef struct {
    int refs;
    bool owned;             /* true：缓冲区由本模块分配 */
    const uint8_t *cert;
    size_t cert_len;
    const uint8_t *key;
    size_t key_len;
} cert_bundle_t;

struct h2_server {
    h2_server_config_t cfg;
    esp_tls_cfg_server_t tls_cfg;   /* 模板；证书字段在每次握手时填入 */
    cert_bundle_t *cert;            /* 受 lock 保护 */
    int listen_fd;
    volatile bool stopping;
    SemaphoreHandle_t conn_sem;
    SemaphoreHandle_t lock;         /* 保护路由表和证书 */
    h2_route_t *routes;
    uint8_t n_routes;
};

typedef struct {
    h2_server_handle_t srv;
    esp_tls_t *tls;
    int fd;
    nghttp2_session *ng;
    char peer[16];
} h2_conn_t;

struct h2_req {
    h2_conn_t *conn;
    int32_t stream_id;
    char method[12];
    char *path;             /* ':path' 去掉查询串 */
    const char *query;      /* 指向 path 缓冲区内 '?' 之后 */
    char *authority;
    h2_hdr_t *hdrs;
    size_t hdr_bytes;
    uint8_t *body;
    size_t body_len;
    bool body_too_large;
    bool dispatched;
    bool responded;
    bool http1;             /* HTTP/1.1 连接上的请求 */
    bool http1_close;       /* 应答后关闭连接 */
    bool write_failed;
    void *user_ctx;
    /* 响应 */
    h2_hdr_t *resp_hdrs;
    uint8_t *resp_body;
    size_t resp_len;
    size_t resp_off;
};

/* ---------- 工具 ---------- */

static h2_hdr_t *hdr_new(const uint8_t *name, size_t nlen, const uint8_t *value, size_t vlen)
{
    h2_hdr_t *h = calloc(1, sizeof(*h) + nlen + 1 + vlen + 1);
    if (!h) {
        return NULL;
    }
    h->name = (char *)(h + 1);
    memcpy(h->name, name, nlen);
    h->name[nlen] = '\0';
    h->value = h->name + nlen + 1;
    memcpy(h->value, value, vlen);
    h->value[vlen] = '\0';
    return h;
}

static void hdr_free_list(h2_hdr_t *h)
{
    while (h) {
        h2_hdr_t *n = h->next;
        free(h);
        h = n;
    }
}

static void req_free(h2_req_t *req)
{
    if (!req) {
        return;
    }
    hdr_free_list(req->hdrs);
    hdr_free_list(req->resp_hdrs);
    free(req->path);
    free(req->authority);
    free(req->body);
    free(req->resp_body);
    free(req);
}

static int hexval(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

void h2_path_normalize(char *p)
{
    /* 1. 百分号解码；非法序列和 %00 保留原样 */
    char *r = p, *w = p;
    while (*r) {
        if (r[0] == '%' && hexval(r[1]) >= 0 && hexval(r[2]) >= 0) {
            int v = hexval(r[1]) * 16 + hexval(r[2]);
            if (v) {
                *w++ = (char)v;
                r += 3;
                continue;
            }
        }
        *w++ = *r++;
    }
    *w = '\0';
    /* 2. 合并连续斜杠 */
    r = w = p;
    while (*r) {
        if (*r == '/' && w > p && w[-1] == '/') {
            r++;
            continue;
        }
        *w++ = *r++;
    }
    *w = '\0';
    /* 3. 去掉结尾斜杠（根路径除外） */
    size_t n = w - p;
    while (n > 1 && p[n - 1] == '/') {
        p[--n] = '\0';
    }
}

/* 路径已规范化，按不区分大小写比较 */
static bool route_match(const h2_route_t *r, const char *method, const char *path, bool *path_hit)
{
    size_t plen = strlen(r->path);
    bool hit;
    if (plen && r->path[plen - 1] == '*') {
        hit = strncasecmp(path, r->path, plen - 1) == 0;
    } else {
        hit = strcasecmp(path, r->path) == 0;
    }
    if (!hit) {
        return false;
    }
    *path_hit = true;
    return r->method == NULL || strcmp(r->method, method) == 0;
}

/* ---------- 请求 / 响应 API ---------- */

const char *h2_req_method(const h2_req_t *req)    { return req->method; }
const char *h2_req_path(const h2_req_t *req)      { return req->path ? req->path : ""; }
const char *h2_req_query(const h2_req_t *req)     { return req->query ? req->query : ""; }
const char *h2_req_authority(const h2_req_t *req) { return req->authority ? req->authority : ""; }
int32_t h2_req_stream_id(const h2_req_t *req)     { return req->stream_id; }
const char *h2_req_proto(const h2_req_t *req)     { return req->http1 ? "http/1.1" : "h2"; }
const char *h2_req_peer(const h2_req_t *req)      { return req->conn->peer; }
void *h2_req_user_ctx(const h2_req_t *req)        { return req->user_ctx; }

const char *h2_req_header(const h2_req_t *req, const char *name)
{
    for (h2_hdr_t *h = req->hdrs; h; h = h->next) {
        if (strcasecmp(h->name, name) == 0) {
            return h->value;
        }
    }
    return NULL;
}

void h2_req_foreach_header(const h2_req_t *req,
                           bool (*cb)(const char *name, const char *value, void *arg), void *arg)
{
    for (h2_hdr_t *h = req->hdrs; h; h = h->next) {
        if (!cb(h->name, h->value, arg)) {
            break;
        }
    }
}

const uint8_t *h2_req_body(const h2_req_t *req, size_t *len)
{
    if (len) {
        *len = req->body_len;
    }
    return req->body;
}

esp_err_t h2_resp_add_header(h2_req_t *req, const char *name, const char *value)
{
    if (req->responded || !name || !value) {
        return ESP_ERR_INVALID_STATE;
    }
    h2_hdr_t *h = hdr_new((const uint8_t *)name, strlen(name), (const uint8_t *)value, strlen(value));
    if (!h) {
        return ESP_ERR_NO_MEM;
    }
    /* HTTP/2 要求头名小写 */
    for (char *p = h->name; *p; p++) {
        if (*p >= 'A' && *p <= 'Z') {
            *p += 'a' - 'A';
        }
    }
    /* 按添加顺序输出 */
    h2_hdr_t **pp = &req->resp_hdrs;
    while (*pp) {
        pp = &(*pp)->next;
    }
    *pp = h;
    return ESP_OK;
}

/* ---------- TLS 写 ---------- */

static bool tls_write_all(h2_conn_t *c, const void *data, size_t length)
{
    const uint8_t *p = data;
    size_t off = 0;
    while (off < length) {
        ssize_t n = esp_tls_conn_write(c->tls, p + off, length - off);
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        off += n;
    }
    return true;
}

/* ---------- HTTP/1.1 应答 ---------- */

static const char *reason_phrase(int status)
{
    switch (status) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 505: return "HTTP Version Not Supported";
    default:  return "";
    }
}

/* "x-checksum" -> "X-Checksum" */
static size_t title_case(char *out, size_t cap, const char *name)
{
    size_t i = 0;
    bool up = true;
    for (; name[i] && i + 1 < cap; i++) {
        char ch = name[i];
        out[i] = up ? (char)toupper((unsigned char)ch) : ch;
        up = ch == '-';
    }
    out[i] = '\0';
    return i;
}

static esp_err_t http1_send(h2_req_t *req, int status, const char *content_type,
                            const void *body, size_t len)
{
    size_t cap = 192 + (content_type ? strlen(content_type) : 0) + len;
    for (h2_hdr_t *h = req->resp_hdrs; h; h = h->next) {
        cap += strlen(h->name) + strlen(h->value) + 4;
    }
    char *buf = malloc(cap);
    if (!buf) {
        req->write_failed = true;
        return ESP_ERR_NO_MEM;
    }
    size_t o = snprintf(buf, cap, "HTTP/1.1 %d %s\r\n", status, reason_phrase(status));
    if (content_type) {
        o += snprintf(buf + o, cap - o, "Content-Type: %s\r\n", content_type);
    }
    for (h2_hdr_t *h = req->resp_hdrs; h; h = h->next) {
        o += title_case(buf + o, cap - o, h->name);
        o += snprintf(buf + o, cap - o, ": %s\r\n", h->value);
    }
    o += snprintf(buf + o, cap - o, "Content-Length: %u\r\nServer: esp32-h2\r\n%s\r\n",
                  (unsigned)len, req->http1_close ? "Connection: close\r\n" : "");
    if (len) {
        memcpy(buf + o, body, len);
        o += len;
    }
    bool ok = tls_write_all(req->conn, buf, o);
    free(buf);
    if (!ok) {
        req->write_failed = true;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static nghttp2_ssize resp_read_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf,
                                  size_t length, uint32_t *data_flags,
                                  nghttp2_data_source *source, void *user_data)
{
    h2_req_t *req = source->ptr;
    size_t left = req->resp_len - req->resp_off;
    size_t n = left < length ? left : length;
    memcpy(buf, req->resp_body + req->resp_off, n);
    req->resp_off += n;
    if (req->resp_off == req->resp_len) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    }
    return (nghttp2_ssize)n;
}

#define MAKE_NV(n, v) { (uint8_t *)(n), (uint8_t *)(v), strlen(n), strlen(v), NGHTTP2_NV_FLAG_NONE }

esp_err_t h2_resp_send(h2_req_t *req, int status, const char *content_type,
                       const void *body, size_t len)
{
    if (req->responded) {
        return ESP_ERR_INVALID_STATE;
    }
    req->responded = true;

    if (req->http1) {
        esp_err_t err = http1_send(req, status, content_type, body, len);
        ESP_LOGI(TAG, "%s http/1.1 %s %s%s%s -> %d (%u B)", req->conn->peer, req->method,
                 h2_req_path(req), req->query ? "?" : "", req->query ? req->query : "",
                 status, (unsigned)len);
        return err;
    }

    if (len) {
        req->resp_body = malloc(len);
        if (!req->resp_body) {
            return ESP_ERR_NO_MEM;
        }
        memcpy(req->resp_body, body, len);
        req->resp_len = len;
    }

    char status_str[4], len_str[12];
    snprintf(status_str, sizeof(status_str), "%03d", status);
    snprintf(len_str, sizeof(len_str), "%u", (unsigned)len);

    size_t n_extra = 0;
    for (h2_hdr_t *h = req->resp_hdrs; h; h = h->next) {
        n_extra++;
    }
    size_t cap = 4 + n_extra;
    nghttp2_nv *nva = calloc(cap, sizeof(*nva));
    if (!nva) {
        return ESP_ERR_NO_MEM;
    }
    size_t n = 0;
    nva[n++] = (nghttp2_nv)MAKE_NV(":status", status_str);
    nva[n++] = (nghttp2_nv)MAKE_NV("server", "esp32-h2");
    nva[n++] = (nghttp2_nv)MAKE_NV("content-length", len_str);
    if (content_type) {
        nva[n++] = (nghttp2_nv)MAKE_NV("content-type", content_type);
    }
    for (h2_hdr_t *h = req->resp_hdrs; h; h = h->next) {
        nva[n++] = (nghttp2_nv)MAKE_NV(h->name, h->value);
    }

    nghttp2_data_provider2 prd = { .source.ptr = req, .read_callback = resp_read_cb };
    /* nghttp2 会复制头部，nva 可立即释放 */
    int rv = nghttp2_submit_response2(req->conn->ng, req->stream_id, nva, n, len ? &prd : NULL);
    free(nva);
    if (rv != 0) {
        ESP_LOGW(TAG, "submit_response 失败: %s", nghttp2_strerror(rv));
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "%s h2 %s %s%s%s -> %d (%u B, stream %ld)", req->conn->peer, req->method,
             req->path, req->query ? "?" : "", req->query ? req->query : "",
             status, (unsigned)len, (long)req->stream_id);
    return ESP_OK;
}

/* ---------- 分发 ---------- */

static void dispatch(h2_conn_t *c, h2_req_t *req)
{
    req->dispatched = true;
    if (!req->method[0] || !req->path) {
        if (req->http1) {
            h2_resp_sendstr(req, 400, "text/plain", "bad request\n");
        } else {
            nghttp2_submit_rst_stream(c->ng, NGHTTP2_FLAG_NONE, req->stream_id, NGHTTP2_PROTOCOL_ERROR);
        }
        return;
    }
    h2_path_normalize(req->path);   /* 路由前统一规范化，h2_req_path() 返回规范化后的路径 */
    if (req->body_too_large) {
        h2_resp_sendstr(req, 413, "text/plain", "request body too large\n");
        return;
    }

    h2_server_handle_t srv = c->srv;
    h2_route_t route = { 0 };
    bool found = false, path_hit = false;
    xSemaphoreTake(srv->lock, portMAX_DELAY);
    for (int i = 0; i < srv->n_routes; i++) {
        if (route_match(&srv->routes[i], req->method, req->path, &path_hit)) {
            route = srv->routes[i];
            found = true;
            break;
        }
    }
    xSemaphoreGive(srv->lock);

    if (!found) {
        if (path_hit) {
            h2_resp_sendstr(req, 405, "text/plain", "method not allowed\n");
        } else {
            h2_resp_sendstr(req, 404, "text/plain", "not found\n");
        }
        return;
    }

    req->user_ctx = route.user_ctx;
    esp_err_t err = route.handler(req);
    if (!req->responded) {
        ESP_LOGW(TAG, "处理函数未发送响应（%s）", esp_err_to_name(err));
        h2_resp_sendstr(req, 500, "text/plain", "handler did not respond\n");
    }
}

/* ---------- nghttp2 回调 ---------- */

static nghttp2_ssize send_cb(nghttp2_session *session, const uint8_t *data, size_t length,
                             int flags, void *user_data)
{
    return tls_write_all(user_data, data, length) ? (nghttp2_ssize)length : NGHTTP2_ERR_CALLBACK_FAILURE;
}

static int on_begin_headers_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    h2_req_t *req = calloc(1, sizeof(*req));
    if (!req) {
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    req->conn = user_data;
    req->stream_id = frame->hd.stream_id;
    nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, req);
    return 0;
}

static int on_header_cb(nghttp2_session *session, const nghttp2_frame *frame,
                        const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen,
                        uint8_t flags, void *user_data)
{
    if (frame->hd.type != NGHTTP2_HEADERS || frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
        return 0;
    }
    h2_conn_t *c = user_data;
    h2_req_t *req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!req) {
        return 0;
    }
    req->hdr_bytes += namelen + valuelen;
    if (req->hdr_bytes > c->srv->cfg.max_header_bytes) {
        /* 重置该流 */
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    if (namelen && name[0] == ':') {
        if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
            size_t n = valuelen < sizeof(req->method) - 1 ? valuelen : sizeof(req->method) - 1;
            memcpy(req->method, value, n);
            req->method[n] = '\0';
        } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
            req->path = strndup((const char *)value, valuelen);
            if (!req->path) {
                return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
            }
            char *q = strchr(req->path, '?');
            if (q) {
                *q = '\0';
                req->query = q + 1;
            }
        } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
            req->authority = strndup((const char *)value, valuelen);
        }
        return 0;
    }

    h2_hdr_t *h = hdr_new(name, namelen, value, valuelen);
    if (!h) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    /* 按出现顺序追加到链表尾部 */
    h2_hdr_t **pp = &req->hdrs;
    while (*pp) {
        pp = &(*pp)->next;
    }
    *pp = h;
    return 0;
}

static int on_data_chunk_cb(nghttp2_session *session, uint8_t flags, int32_t stream_id,
                            const uint8_t *data, size_t len, void *user_data)
{
    h2_conn_t *c = user_data;
    h2_req_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (!req || req->body_too_large) {
        return 0;
    }
    if (req->body_len + len > c->srv->cfg.max_body) {
        req->body_too_large = true;
        free(req->body);
        req->body = NULL;
        req->body_len = 0;
        return 0;
    }
    uint8_t *nb = realloc(req->body, req->body_len + len + 1);
    if (!nb) {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    memcpy(nb + req->body_len, data, len);
    req->body = nb;
    req->body_len += len;
    req->body[req->body_len] = '\0';    /* 方便按字符串处理 */
    return 0;
}

static int on_frame_recv_cb(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        h2_req_t *req = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
        if (req && !req->dispatched) {
            dispatch(user_data, req);
        }
    }
    return 0;
}

static int on_stream_close_cb(nghttp2_session *session, int32_t stream_id,
                              uint32_t error_code, void *user_data)
{
    h2_req_t *req = nghttp2_session_get_stream_user_data(session, stream_id);
    if (req) {
        nghttp2_session_set_stream_user_data(session, stream_id, NULL);
        req_free(req);
    }
    return 0;
}

/* ---------- 连接 ---------- */

static void serve_h2(h2_conn_t *c)
{
    nghttp2_session_callbacks *cbs;
    if (nghttp2_session_callbacks_new(&cbs) != 0) {
        return;
    }
    nghttp2_session_callbacks_set_send_callback2(cbs, send_cb);
    nghttp2_session_callbacks_set_on_begin_headers_callback(cbs, on_begin_headers_cb);
    nghttp2_session_callbacks_set_on_header_callback(cbs, on_header_cb);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cbs, on_data_chunk_cb);
    nghttp2_session_callbacks_set_on_frame_recv_callback(cbs, on_frame_recv_cb);
    nghttp2_session_callbacks_set_on_stream_close_callback(cbs, on_stream_close_cb);
    int rv = nghttp2_session_server_new(&c->ng, cbs, c);
    nghttp2_session_callbacks_del(cbs);
    if (rv != 0) {
        ESP_LOGE(TAG, "session_server_new 失败: %s", nghttp2_strerror(rv));
        return;
    }

    nghttp2_settings_entry iv[] = {
        { NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, c->srv->cfg.max_streams },
        { NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE, (uint32_t)c->srv->cfg.max_header_bytes * 2 },
    };
    nghttp2_submit_settings(c->ng, NGHTTP2_FLAG_NONE, iv, sizeof(iv) / sizeof(iv[0]));

    uint8_t *buf = malloc(RX_BUF_SIZE);
    if (!buf) {
        goto out;
    }
    TickType_t last_rx = xTaskGetTickCount();
    const TickType_t idle = pdMS_TO_TICKS(c->srv->cfg.idle_timeout_ms);

    while (nghttp2_session_want_read(c->ng) || nghttp2_session_want_write(c->ng)) {
        if ((rv = nghttp2_session_send(c->ng)) != 0) {
            ESP_LOGD(TAG, "session_send: %s", nghttp2_strerror(rv));
            break;
        }
        if (!nghttp2_session_want_read(c->ng)) {
            continue;
        }
        ssize_t n = esp_tls_conn_read(c->tls, buf, RX_BUF_SIZE);
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            /* SO_RCVTIMEO 到期也走这里 */
            if (c->srv->stopping || xTaskGetTickCount() - last_rx > idle) {
                ESP_LOGI(TAG, "%s 空闲超时，发送 GOAWAY", c->peer);
                nghttp2_session_terminate_session(c->ng, NGHTTP2_NO_ERROR);
                nghttp2_session_send(c->ng);
                break;
            }
            continue;
        }
        if (n <= 0) {
            break;      /* 对端关闭或出错 */
        }
        last_rx = xTaskGetTickCount();
        nghttp2_ssize r = nghttp2_session_mem_recv2(c->ng, buf, n);
        if (r < 0) {
            ESP_LOGW(TAG, "%s 协议错误: %s", c->peer, nghttp2_strerror((int)r));
            nghttp2_session_send(c->ng);    /* 尽量把 GOAWAY 发出去 */
            break;
        }
    }

out:
    free(buf);
    nghttp2_session_del(c->ng);     /* 会对未关闭的流触发 on_stream_close，释放请求 */
    c->ng = NULL;
}

static void bundle_unref_locked(cert_bundle_t *b)
{
    if (--b->refs == 0) {
        if (b->owned) {
            free((void *)b->cert);
            free((void *)b->key);
        }
        free(b);
    }
}

static cert_bundle_t *bundle_acquire(h2_server_handle_t srv)
{
    xSemaphoreTake(srv->lock, portMAX_DELAY);
    cert_bundle_t *b = srv->cert;
    b->refs++;
    xSemaphoreGive(srv->lock);
    return b;
}

static void bundle_release(h2_server_handle_t srv, cert_bundle_t *b)
{
    xSemaphoreTake(srv->lock, portMAX_DELAY);
    bundle_unref_locked(b);
    xSemaphoreGive(srv->lock);
}

/* 复制 PEM，保证以 '\0' 结尾（mbedTLS 解析 PEM 要求长度含结尾 0） */
static uint8_t *pem_dup(const uint8_t *src, size_t len, size_t *out_len)
{
    bool has_nul = len && src[len - 1] == '\0';
    size_t n = has_nul ? len : len + 1;
    uint8_t *d = malloc(n);
    if (d) {
        memcpy(d, src, len);
        d[n - 1] = '\0';
        *out_len = n;
    }
    return d;
}

esp_err_t h2_server_set_cert(h2_server_handle_t srv, const uint8_t *cert_pem, size_t cert_len,
                             const uint8_t *key_pem, size_t key_len)
{
    if (!srv || !cert_pem || !cert_len || !key_pem || !key_len) {
        return ESP_ERR_INVALID_ARG;
    }
    cert_bundle_t *b = calloc(1, sizeof(*b));
    if (!b) {
        return ESP_ERR_NO_MEM;
    }
    b->refs = 1;
    b->owned = true;
    b->cert = pem_dup(cert_pem, cert_len, &b->cert_len);
    b->key = pem_dup(key_pem, key_len, &b->key_len);
    if (!b->cert || !b->key) {
        free((void *)b->cert);
        free((void *)b->key);
        free(b);
        return ESP_ERR_NO_MEM;
    }
    xSemaphoreTake(srv->lock, portMAX_DELAY);
    cert_bundle_t *old = srv->cert;
    srv->cert = b;
    bundle_unref_locked(old);
    xSemaphoreGive(srv->lock);
    ESP_LOGI(TAG, "服务器证书已更新，新连接生效");
    return ESP_OK;
}

/* ---------- HTTP/1.1 连接 ---------- */

/* 读到数据返回字节数；空闲超时或连接关闭返回 <= 0 */
static ssize_t http1_read(h2_conn_t *c, void *buf, size_t len, TickType_t *last_rx)
{
    const TickType_t idle = pdMS_TO_TICKS(c->srv->cfg.idle_timeout_ms);
    for (;;) {
        ssize_t n = esp_tls_conn_read(c->tls, buf, len);
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            if (c->srv->stopping || xTaskGetTickCount() - *last_rx > idle) {
                return 0;
            }
            continue;
        }
        if (n > 0) {
            *last_rx = xTaskGetTickCount();
        }
        return n;
    }
}

static void http1_error(h2_req_t *req, int status, const char *msg)
{
    req->http1_close = true;
    h2_resp_sendstr(req, status, "text/plain", msg);
}

static void serve_http1(h2_conn_t *c)
{
    h2_server_handle_t srv = c->srv;
    const size_t cap = srv->cfg.max_header_bytes + 1024;   /* 请求行 + 请求头 */
    char *buf = malloc(cap + 1);
    if (!buf) {
        return;
    }
    size_t have = 0;
    TickType_t last_rx = xTaskGetTickCount();

    for (;;) {
        char *end = have >= 4 ? memmem(buf, have, "\r\n\r\n", 4) : NULL;
        if (!end) {
            if (have >= cap) {
                h2_req_t tmp = { .conn = c, .http1 = true };
                http1_error(&tmp, 431, "request header too large\n");
                hdr_free_list(tmp.resp_hdrs);
                break;
            }
            ssize_t n = http1_read(c, buf + have, cap - have, &last_rx);
            if (n <= 0) {
                if (n == 0 && have == 0) {
                    ESP_LOGI(TAG, "%s 空闲超时", c->peer);
                }
                break;
            }
            have += n;
            continue;
        }

        size_t head_len = end - buf + 4;
        *end = '\0';
        h2_req_t *req = calloc(1, sizeof(*req));
        if (!req) {
            break;
        }
        req->conn = c;
        req->http1 = true;
        bool keep = false;
        long clen = 0;
        int err_status = 0;
        const char *err_msg = NULL;

        /* 请求行：METHOD SP target SP HTTP/x.y */
        char *line = buf, *next = strstr(line, "\r\n");
        if (next) {
            *next = '\0';
            next += 2;
        }
        char *sp1 = strchr(line, ' ');
        char *sp2 = sp1 ? strchr(sp1 + 1, ' ') : NULL;
        if (!sp1 || !sp2 || sp1 == line || (size_t)(sp1 - line) >= sizeof(req->method) || sp2 == sp1 + 1) {
            err_status = 400;
            err_msg = "bad request line\n";
        } else {
            *sp1 = *sp2 = '\0';
            strcpy(req->method, line);
            const char *target = sp1 + 1, *ver = sp2 + 1;
            if (strcmp(ver, "HTTP/1.1") == 0) {
                keep = true;
            } else if (strcmp(ver, "HTTP/1.0") != 0) {
                err_status = 505;
                err_msg = "unsupported HTTP version\n";
            }
            if (!err_status && target[0] != '/') {
                err_status = 400;
                err_msg = "request target must be an absolute path\n";
            }
            if (!err_status) {
                req->path = strdup(target);
                char *q = req->path ? strchr(req->path, '?') : NULL;
                if (q) {
                    *q = '\0';
                    req->query = q + 1;
                }
            }
        }

        /* 请求头 */
        for (line = next; !err_status && line && *line; line = next) {
            next = strstr(line, "\r\n");
            if (next) {
                *next = '\0';
                next += 2;
            }
            char *colon = strchr(line, ':');
            if (!colon || colon == line) {
                err_status = 400;
                err_msg = "bad header line\n";
                break;
            }
            *colon = '\0';
            char *v = colon + 1;
            while (*v == ' ' || *v == '\t') {
                v++;
            }
            char *ve = v + strlen(v);
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) {
                *--ve = '\0';
            }
            for (char *p = line; *p; p++) {
                *p = (char)tolower((unsigned char)*p);
            }
            if (strcmp(line, "content-length") == 0) {
                char *e;
                clen = strtol(v, &e, 10);
                if (e == v || *e || clen < 0) {
                    err_status = 400;
                    err_msg = "bad content-length\n";
                }
            } else if (strcmp(line, "transfer-encoding") == 0) {
                err_status = 501;
                err_msg = "transfer-encoding not supported, use content-length\n";
            } else if (strcmp(line, "connection") == 0) {
                if (strcasecmp(v, "close") == 0) {
                    keep = false;
                } else if (strcasecmp(v, "keep-alive") == 0) {
                    keep = true;
                }
            } else if (strcmp(line, "host") == 0 && !req->authority) {
                req->authority = strdup(v);
            }
            h2_hdr_t *h = hdr_new((uint8_t *)line, strlen(line), (uint8_t *)v, strlen(v));
            if (h) {
                h2_hdr_t **pp = &req->hdrs;
                while (*pp) {
                    pp = &(*pp)->next;
                }
                *pp = h;
            }
        }
        req->hdr_bytes = head_len;
        if (!err_status && head_len > srv->cfg.max_header_bytes) {
            err_status = 431;
            err_msg = "request header too large\n";
        }

        /* 请求体（Content-Length） */
        size_t consumed = head_len;
        bool io_failed = false;
        if (!err_status && clen > 0) {
            if ((size_t)clen > srv->cfg.max_body) {
                req->body_too_large = true;     /* 不读取正文，回 413 后关闭连接 */
                keep = false;
            } else {
                req->body = malloc(clen + 1);
                if (!req->body) {
                    io_failed = true;
                } else {
                    size_t avail = have - head_len;
                    size_t got = avail < (size_t)clen ? avail : (size_t)clen;
                    memcpy(req->body, buf + head_len, got);
                    consumed += got;
                    while (got < (size_t)clen) {
                        ssize_t n = http1_read(c, req->body + got, clen - got, &last_rx);
                        if (n <= 0) {
                            io_failed = true;
                            break;
                        }
                        got += n;
                    }
                    req->body[got] = '\0';
                    req->body_len = got;
                }
            }
        }
        if (io_failed) {
            req_free(req);
            break;
        }

        req->http1_close = !keep;
        if (err_status) {
            http1_error(req, err_status, err_msg);
            keep = false;
        } else {
            dispatch(c, req);
        }
        bool ok = !req->write_failed;
        req_free(req);
        if (!ok || !keep) {
            break;
        }
        /* 保留已读到的下一个请求（流水线） */
        memmove(buf, buf + consumed, have - consumed);
        have -= consumed;
    }
    free(buf);
}

static void conn_task(void *arg)
{
    h2_conn_t *c = arg;
    h2_server_handle_t srv = c->srv;

    /* 读超时用于周期检查空闲和停止标志；握手也受此限制 */
    struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
    setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(c->fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(c->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    c->tls = esp_tls_init();
    if (!c->tls) {
        goto done;
    }
    /* tls_cfg 在整个连接期间保持有效（esp-tls 可能保留其指针） */
    esp_tls_cfg_server_t tls_cfg = srv->tls_cfg;
    cert_bundle_t *cb = bundle_acquire(srv);
    tls_cfg.servercert_buf = cb->cert;
    tls_cfg.servercert_bytes = cb->cert_len;
    tls_cfg.serverkey_buf = cb->key;
    tls_cfg.serverkey_bytes = cb->key_len;
    int ret = esp_tls_server_session_create(&tls_cfg, c->fd, c->tls);
    bundle_release(srv, cb);    /* 证书已被 mbedTLS 解析复制 */
    if (ret != 0) {
        ESP_LOGW(TAG, "%s TLS 握手失败: -0x%04x", c->peer, -ret);
        goto done;
    }

    /* ALPN 协商到 h2 走 HTTP/2；协商到 http/1.1 或未使用 ALPN 走 HTTP/1.1 */
    const char *alpn = mbedtls_ssl_get_alpn_protocol(esp_tls_get_ssl_context(c->tls));
    if (alpn && strcmp(alpn, "h2") == 0) {
        ESP_LOGI(TAG, "%s 已连接（h2）", c->peer);
        serve_h2(c);
    } else {
        ESP_LOGI(TAG, "%s 已连接（http/1.1，ALPN=%s）", c->peer, alpn ? alpn : "无");
        serve_http1(c);
    }
    ESP_LOGI(TAG, "%s 断开", c->peer);

done:
    if (c->tls) {
        esp_tls_server_session_delete(c->tls);
    }
    close(c->fd);
    free(c);
    xSemaphoreGive(srv->conn_sem);
    vTaskDelete(NULL);
}

static void accept_task(void *arg)
{
    h2_server_handle_t srv = arg;
    while (!srv->stopping) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int fd = accept(srv->listen_fd, (struct sockaddr *)&peer, &plen);
        if (fd < 0) {
            if (srv->stopping) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (xSemaphoreTake(srv->conn_sem, 0) != pdTRUE) {
            char ip[16];
            inet_ntoa_r(peer.sin_addr, ip, sizeof(ip));
            ESP_LOGW(TAG, "连接数已满，拒绝 %s", ip);
            close(fd);
            continue;
        }
        h2_conn_t *c = calloc(1, sizeof(*c));
        if (!c) {
            close(fd);
            xSemaphoreGive(srv->conn_sem);
            continue;
        }
        c->srv = srv;
        c->fd = fd;
        inet_ntoa_r(peer.sin_addr, c->peer, sizeof(c->peer));
        if (xTaskCreate(conn_task, "h2_conn", srv->cfg.task_stack, c, srv->cfg.task_prio, NULL) != pdPASS) {
            ESP_LOGE(TAG, "创建连接任务失败");
            close(fd);
            free(c);
            xSemaphoreGive(srv->conn_sem);
        }
    }
    vTaskDelete(NULL);
}

/* ---------- 启动 / 停止 ---------- */

static const char *s_alpn[] = { "h2", "http/1.1", NULL };

esp_err_t h2_server_start(const h2_server_config_t *cfg, h2_server_handle_t *out)
{
    if (!cfg || !out || !cfg->cert_pem || !cfg->key_pem || !cfg->max_conns || !cfg->max_routes) {
        return ESP_ERR_INVALID_ARG;
    }
    h2_server_handle_t srv = calloc(1, sizeof(*srv));
    if (!srv) {
        return ESP_ERR_NO_MEM;
    }
    srv->cfg = *cfg;
    srv->routes = calloc(cfg->max_routes, sizeof(h2_route_t));
    srv->conn_sem = xSemaphoreCreateCounting(cfg->max_conns, cfg->max_conns);
    srv->lock = xSemaphoreCreateMutex();
    if (!srv->routes || !srv->conn_sem || !srv->lock) {
        goto fail_mem;
    }

    srv->tls_cfg.alpn_protos = s_alpn;
    srv->cert = calloc(1, sizeof(cert_bundle_t));
    if (!srv->cert) {
        goto fail_mem;
    }
    *srv->cert = (cert_bundle_t) {
        .refs = 1, .owned = false,
        .cert = cfg->cert_pem, .cert_len = cfg->cert_len,
        .key = cfg->key_pem, .key_len = cfg->key_len,
    };

    /* 客户端证书：IGNORE 时不设 CA，esp-tls 不发 CertificateRequest，客户端不会出示证书 */
    switch (cfg->client_auth) {
    case H2_CLIENT_AUTH_IGNORE:
        break;
    case H2_CLIENT_AUTH_OPTIONAL:
#ifndef CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL
        ESP_LOGE(TAG, "OPTIONAL 需开启 CONFIG_ESP_TLS_SERVER_MIN_AUTH_MODE_OPTIONAL");
        goto fail_arg;
#else
        srv->tls_cfg.client_cert_authmode_optional = true;
#endif
        /* fallthrough */
    case H2_CLIENT_AUTH_REQUIRED:
        if (!cfg->client_ca_pem || !cfg->client_ca_len) {
            ESP_LOGE(TAG, "校验客户端证书需要提供 client_ca_pem");
            goto fail_arg;
        }
        srv->tls_cfg.cacert_buf = cfg->client_ca_pem;
        srv->tls_cfg.cacert_bytes = cfg->client_ca_len;
        break;
    default:
        goto fail_arg;
    }

    srv->listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv->listen_fd < 0) {
        goto fail_mem;
    }
    int one = 1;
    setsockopt(srv->listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(cfg->port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(srv->listen_fd, 4) < 0) {
        ESP_LOGE(TAG, "bind/listen 端口 %u 失败 errno=%d", cfg->port, errno);
        close(srv->listen_fd);
        goto fail_mem;
    }
    if (xTaskCreate(accept_task, "h2_accept", 3072, srv, cfg->task_prio, NULL) != pdPASS) {
        close(srv->listen_fd);
        goto fail_mem;
    }
    static const char *const auth_name[] = { "忽略", "可选", "必须" };
    ESP_LOGI(TAG, "HTTP/2 服务已启动，端口 %u（TLS，ALPN h2，客户端证书：%s）",
             cfg->port, auth_name[cfg->client_auth]);
    *out = srv;
    return ESP_OK;

fail_arg:
    if (srv->conn_sem) vSemaphoreDelete(srv->conn_sem);
    if (srv->lock) vSemaphoreDelete(srv->lock);
    free(srv->routes);
    free(srv->cert);
    free(srv);
    return ESP_ERR_INVALID_ARG;

fail_mem:
    if (srv->conn_sem) vSemaphoreDelete(srv->conn_sem);
    if (srv->lock) vSemaphoreDelete(srv->lock);
    free(srv->routes);
    free(srv->cert);
    free(srv);
    return ESP_FAIL;
}

esp_err_t h2_server_register(h2_server_handle_t srv, const h2_route_t *route)
{
    if (!srv || !route || !route->path || !route->handler) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = ESP_OK;
    xSemaphoreTake(srv->lock, portMAX_DELAY);
    if (srv->n_routes >= srv->cfg.max_routes) {
        err = ESP_ERR_NO_MEM;
    } else {
        srv->routes[srv->n_routes++] = *route;
    }
    xSemaphoreGive(srv->lock);
    return err;
}

void h2_server_stop(h2_server_handle_t srv)
{
    if (!srv || srv->stopping) {
        return;
    }
    srv->stopping = true;
    shutdown(srv->listen_fd, SHUT_RDWR);
    close(srv->listen_fd);
    /* 句柄本身不释放：连接任务退出前仍会访问它 */
}
