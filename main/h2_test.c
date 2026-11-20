/*
 * HTTP/2 站点（端口 443，TLS，同时支持 HTTP/1.1）。域名、证书链、私钥由 h2_site 提供：
 * 默认为内嵌的 main/certs2/ 证书，可在配置页修改
 * 下游客户端经 DNS 中继把该域名解析到 192.168.4.1
 *   GET  /          说明页
 *   GET  /ping      连通性 + 协议信息
 *   GET  /status    中继运行状态 JSON
 *   GET  /headers   回显请求头（验证 HPACK）
 *   POST /echo      原样回显请求体
 *   其他路径        按配置页设置的自定义接口应答 JSON（见 h2_routes.c），否则 404
 *
 * 测试（连在 ESP32 热点上）：curl --http2 https://www.aabbcc.com/ping
 */
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "h2_server.h"
#include "repeater.h"
#include "h2_routes.h"
#include "h2_site.h"

static const char *TAG = "h2_test";

static esp_err_t index_get(h2_req_t *req)
{
    static const char html[] =
        "<!DOCTYPE html><html lang=\"zh-CN\"><meta charset=\"utf-8\">"
        "<title>ESP32 HTTP/2</title>"
        "<h1>ESP32 HTTP/2 OK</h1>"
        "<ul><li><a href=\"/ping\">/ping</a></li><li><a href=\"/status\">/status</a></li>"
        "<li><a href=\"/headers\">/headers</a></li><li>POST /echo</li></ul></html>\n";
    return h2_resp_send(req, 200, "text/html; charset=utf-8", html, sizeof(html) - 1);
}

static esp_err_t ping_get(h2_req_t *req)
{
    char buf[200];
    snprintf(buf, sizeof(buf),
             "{\"ok\":true,\"proto\":\"%s\",\"stream\":%ld,\"peer\":\"%s\",\"authority\":\"%s\",\"uptime_ms\":%lld}\n",
             h2_req_proto(req), (long)h2_req_stream_id(req), h2_req_peer(req), h2_req_authority(req),
             esp_timer_get_time() / 1000);
    return h2_resp_sendstr(req, 200, "application/json", buf);
}

static esp_err_t status_get(h2_req_t *req)
{
    repeater_status_t st;
    repeater_get_status(&st);
    char buf[320];
    snprintf(buf, sizeof(buf),
             "{\"sta_connected\":%s,\"sta_ip\":\"%s\",\"sta_gw\":\"%s\",\"ap_ip\":\"%s\","
             "\"rssi\":%d,\"channel\":%u,\"clients\":%d,\"uptime\":%lu,\"free_heap\":%lu}\n",
             st.sta_connected ? "true" : "false", st.sta_ip, st.sta_gw, st.ap_ip,
             st.rssi, st.channel, st.clients,
             (unsigned long)st.uptime_s, (unsigned long)st.free_heap);
    return h2_resp_sendstr(req, 200, "application/json", buf);
}

typedef struct {
    char *buf;
    size_t cap;
    size_t len;
} sbuf_t;

static bool append_header(const char *name, const char *value, void *arg)
{
    sbuf_t *s = arg;
    int n = snprintf(s->buf + s->len, s->cap - s->len, "%s: %s\n", name, value);
    if (n < 0 || (size_t)n >= s->cap - s->len) {
        return false;
    }
    s->len += n;
    return true;
}

static esp_err_t headers_get(h2_req_t *req)
{
    char buf[1024];
    sbuf_t s = { buf, sizeof(buf), 0 };
    s.len = snprintf(buf, sizeof(buf), ":method: %s\n:path: %s%s%s\n:authority: %s\n",
                     h2_req_method(req), h2_req_path(req),
                     h2_req_query(req)[0] ? "?" : "", h2_req_query(req), h2_req_authority(req));
    h2_req_foreach_header(req, append_header, &s);
    return h2_resp_send(req, 200, "text/plain; charset=utf-8", buf, s.len);
}

static esp_err_t echo_post(h2_req_t *req)
{
    size_t len;
    const uint8_t *body = h2_req_body(req, &len);
    const char *ct = h2_req_header(req, "content-type");
    char lenstr[12];
    snprintf(lenstr, sizeof(lenstr), "%u", (unsigned)len);
    h2_resp_add_header(req, "x-echo-length", lenstr);
    return h2_resp_send(req, 200, ct ? ct : "application/octet-stream", body, len);
}

/* 自定义接口应答：
 *   :status 200
 *   content-type: application/json
 *   x-checksum: <md5(body) 小写 hex>
 *   cache-control: no-store
 *   正文为压缩 JSON（无空格、无换行） */
static void send_custom_json(const char *json, const char *md5, void *arg)
{
    h2_req_t *req = arg;
    h2_resp_add_header(req, "x-checksum", md5);
    h2_resp_add_header(req, "cache-control", "no-store");
    h2_resp_sendstr(req, 200, "application/json", json);
}

/* 兜底路由：查自定义接口表（任意方法） */
static esp_err_t custom_handler(h2_req_t *req)
{
    if (h2_routes_with(h2_req_path(req), send_custom_json, req)) {
        return ESP_OK;
    }
    return h2_resp_sendstr(req, 404, "text/plain", "not found\n");
}

esp_err_t h2_test_start(void)
{
    h2_server_config_t cfg = H2_SERVER_DEFAULT_CONFIG();
    cfg.port = H2_SITE_PORT;
    h2_site_get_cert(&cfg.cert_pem, &cfg.cert_len, &cfg.key_pem, &cfg.key_len);

    h2_server_handle_t srv;
    esp_err_t err = h2_server_start(&cfg, &srv);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP/2 站点启动失败: %s", esp_err_to_name(err));
        return err;
    }
    h2_site_set_server(srv);
    char domain[64];
    h2_site_get_domain(domain, sizeof(domain));
    ESP_LOGI(TAG, "HTTP/2 站点 https://%s/ （端口 %d）", domain, H2_SITE_PORT);
    const h2_route_t routes[] = {
        { "GET",  "/",        index_get,   NULL },
        { "GET",  "/ping",    ping_get,    NULL },
        { "GET",  "/status",  status_get,  NULL },
        { "GET",  "/headers", headers_get, NULL },
        { "POST", "/echo",    echo_post,   NULL },
        { NULL,   "/*",       custom_handler, NULL },   /* 须最后注册，内置接口优先 */
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        h2_server_register(srv, &routes[i]);
    }
    return ESP_OK;
}
