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

struct h2_server {
    h2_server_config_t cfg;
    esp_tls_cfg_server_t tls_cfg;
    int listen_fd;
    volatile bool stopping;
    SemaphoreHandle_t conn_sem;
    SemaphoreHandle_t lock;         /* 保护路由表 */
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

static bool route_match(const h2_route_t *r, const char *method, const char *path, bool *path_hit)
{
    size_t plen = strlen(r->path);
    bool hit;
    if (plen && r->path[plen - 1] == '*') {
        hit = strncmp(path, r->path, plen - 1) == 0;
    } else {
        hit = strcmp(path, r->path) == 0;
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
    h->next = req->resp_hdrs;
    req->resp_hdrs = h;
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
    ESP_LOGI(TAG, "%s %s %s%s%s -> %d (%u B, stream %ld)", req->conn->peer, req->method,
             req->path, req->query ? "?" : "", req->query ? req->query : "",
             status, (unsigned)len, (long)req->stream_id);
    return ESP_OK;
}

/* ---------- 分发 ---------- */

static void dispatch(h2_conn_t *c, h2_req_t *req)
{
    req->dispatched = true;
    if (!req->method[0] || !req->path) {
        nghttp2_submit_rst_stream(c->ng, NGHTTP2_FLAG_NONE, req->stream_id, NGHTTP2_PROTOCOL_ERROR);
        return;
    }
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
    h2_conn_t *c = user_data;
    size_t off = 0;
    while (off < length) {
        ssize_t n = esp_tls_conn_write(c->tls, data + off, length - off);
        if (n == ESP_TLS_ERR_SSL_WANT_READ || n == ESP_TLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (n <= 0) {
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        off += n;
    }
    return (nghttp2_ssize)length;
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
    int ret = esp_tls_server_session_create(&srv->tls_cfg, c->fd, c->tls);
    if (ret != 0) {
        ESP_LOGW(TAG, "%s TLS 握手失败: -0x%04x", c->peer, -ret);
        goto done;
    }

    const char *alpn = mbedtls_ssl_get_alpn_protocol(esp_tls_get_ssl_context(c->tls));
    if (!alpn || strcmp(alpn, "h2") != 0) {
        static const char msg[] =
            "HTTP/1.1 505 HTTP Version Not Supported\r\n"
            "Content-Type: text/plain\r\nConnection: close\r\nContent-Length: 28\r\n\r\n"
            "This server requires HTTP/2\n";
        ESP_LOGI(TAG, "%s 未协商 h2（ALPN=%s），回 505", c->peer, alpn ? alpn : "无");
        esp_tls_conn_write(c->tls, msg, sizeof(msg) - 1);
        goto done;
    }

    ESP_LOGI(TAG, "%s 已连接（h2）", c->peer);
    serve_h2(c);
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
    srv->tls_cfg.servercert_buf = cfg->cert_pem;
    srv->tls_cfg.servercert_bytes = cfg->cert_len;
    srv->tls_cfg.serverkey_buf = cfg->key_pem;
    srv->tls_cfg.serverkey_bytes = cfg->key_len;

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
    free(srv);
    return ESP_ERR_INVALID_ARG;

fail_mem:
    if (srv->conn_sem) vSemaphoreDelete(srv->conn_sem);
    if (srv->lock) vSemaphoreDelete(srv->lock);
    free(srv->routes);
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
