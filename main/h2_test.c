/*
 * HTTP/2 测试接口（端口 8443，TLS，自签证书）
 *   GET  /ping      连通性 + 协议信息
 *   GET  /status    中继运行状态 JSON
 *   GET  /headers   回显请求头（验证 HPACK）
 *   POST /echo      原样回显请求体
 *
 * 测试：curl -k --http2 https://<ip>:8443/ping
 */
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "h2_server.h"
#include "repeater.h"

static const char *TAG = "h2_test";

extern const uint8_t h2_cert_start[] asm("_binary_h2_cert_pem_start");
extern const uint8_t h2_cert_end[]   asm("_binary_h2_cert_pem_end");
extern const uint8_t h2_key_start[]  asm("_binary_h2_key_pem_start");
extern const uint8_t h2_key_end[]    asm("_binary_h2_key_pem_end");

static esp_err_t ping_get(h2_req_t *req)
{
    char buf[200];
    snprintf(buf, sizeof(buf),
             "{\"ok\":true,\"proto\":\"h2\",\"stream\":%ld,\"peer\":\"%s\",\"authority\":\"%s\",\"uptime_ms\":%lld}\n",
             (long)h2_req_stream_id(req), h2_req_peer(req), h2_req_authority(req),
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

esp_err_t h2_test_start(void)
{
    h2_server_config_t cfg = H2_SERVER_DEFAULT_CONFIG();
    cfg.port = 8443;
    cfg.cert_pem = h2_cert_start;
    cfg.cert_len = h2_cert_end - h2_cert_start;
    cfg.key_pem = h2_key_start;
    cfg.key_len = h2_key_end - h2_key_start;

    h2_server_handle_t srv;
    esp_err_t err = h2_server_start(&cfg, &srv);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP/2 测试服务启动失败: %s", esp_err_to_name(err));
        return err;
    }
    const h2_route_t routes[] = {
        { "GET",  "/ping",    ping_get,    NULL },
        { "GET",  "/status",  status_get,  NULL },
        { "GET",  "/headers", headers_get, NULL },
        { "POST", "/echo",    echo_post,   NULL },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        h2_server_register(srv, &routes[i]);
    }
    return ESP_OK;
}
