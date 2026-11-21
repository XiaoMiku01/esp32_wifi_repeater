/*
 * 配置页 HTTP 服务
 *   GET  /             配置页（main/www/index.html）
 *   GET  /api/status   运行状态 JSON
 *   GET  /api/config   当前配置 JSON（不返回密码）
 *   POST /api/config   保存并应用配置，表单编码
 *   GET  /api/scan     扫描周边网络（阻塞约 2-3 秒）
 *   POST /api/restart  重启
 *   GET  /api/h2routes HTTP/2 站点自定义接口列表
 *   POST /api/h2routes 新增/修改（action=set&path=&json=）或删除（action=del&path=）
 *   GET  /api/dns      自定义 DNS 解析列表
 *   POST /api/dns      新增/修改（action=set&name=&ip=，ip 留空或 ap 表示 AP 地址）
 *                      或删除（action=del&name=）
 *   GET  /api/h2site   HTTP/2 站点域名与证书信息（不含私钥）
 *   POST /api/h2site   修改（action=set&domain=&cert=&key=，cert/key 同时为空表示只改域名）
 *                      或恢复内嵌（action=reset）
 *   GET  /monitor        记录页（main/www/monitor.html）
 *   GET  /api/mon/live   客户端、连接、性能统计
 *   GET  /api/mon/dns    DNS 记录（?since=<id> 增量）
 *   GET  /api/mon/block  黑名单；POST action=add|del&domain=
 *   POST /api/mon/ctl    action=enable|disable|reset_perf
 *   GET  /api/mon/bench  合成包压测转发钩子开销
 *   GET  /api/dnsblock  DNS 黑名单与例外（?test=<域名> 查看该域名的处理结果）
 *   POST /api/dnsblock  block=<每行一条>&allow=<每行一条>，整体替换
 *   GET  /api/export   导出全部配置 JSON（含 Wi-Fi 密码与网页上传的私钥），网页端转为 YAML；
 *                      导入由网页解析 YAML 后逐段调用上述接口完成
 *   GET  /ws           WebSocket，推送实时日志（二进制帧，UTF-8 文本）
 */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_system.h"
#include "repeater.h"
#include "web_log_priv.h"
#include "h2_routes.h"
#include "h2_site.h"
#include "monitor.h"
#include "dns_filter.h"
#include "lwip/inet.h"

static const char *TAG = "web";
static httpd_handle_t s_server;

extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[]   asm("_binary_index_html_end");
extern const char monitor_html_start[] asm("_binary_monitor_html_start");
extern const char monitor_html_end[]   asm("_binary_monitor_html_end");

/* ---------- 工具函数 ---------- */

/* 把 s 以 JSON 字符串形式（含引号）写入 out，返回写入长度 */
static size_t json_str(char *out, size_t cap, const char *s)
{
    size_t o = 0;
    if (cap < 3) {
        return 0;
    }
    out[o++] = '"';
    for (; *s && o + 7 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = c;
        } else if (c < 0x20) {
            o += snprintf(out + o, cap - o, "\\u%04x", c);
        } else {
            out[o++] = c;
        }
    }
    out[o++] = '"';
    out[o] = '\0';
    return o;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* application/x-www-form-urlencoded 解码；输出超长返回 false */
static bool url_decode(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    for (; *in; in++) {
        char c = *in;
        if (c == '+') {
            c = ' ';
        } else if (c == '%' && in[1] && in[2]) {
            int h = hexval(in[1]), l = hexval(in[2]);
            if (h < 0 || l < 0) {
                return false;
            }
            c = (char)(h << 4 | l);
            in += 2;
        }
        if (o + 1 >= cap) {
            return false;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return true;
}

/* 读取表单字段：不存在返回 0，成功返回 1，非法/超长返回 -1 */
static int form_get(const char *body, const char *key, char *out, size_t cap)
{
    char raw[200];
    esp_err_t err = httpd_query_key_value(body, key, raw, sizeof(raw));
    if (err == ESP_ERR_NOT_FOUND) {
        return 0;
    }
    if (err != ESP_OK) {
        return -1;
    }
    return url_decode(raw, out, cap) ? 1 : -1;
}

static esp_err_t send_json_error(httpd_req_t *req, const char *status, const char *msg)
{
    char buf[200], m[160];
    json_str(m, sizeof(m), msg);
    snprintf(buf, sizeof(buf), "{\"ok\":false,\"error\":%s}", m);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

/* ---------- HTTP 处理 ---------- */

static esp_err_t index_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    /* EMBED_TXTFILES 末尾附加了 '\0'，不发送 */
    return httpd_resp_send(req, index_html_start, index_html_end - index_html_start - 1);
}

static esp_err_t status_get(httpd_req_t *req)
{
    repeater_status_t st;
    repeater_get_status(&st);
    char buf[320];
    snprintf(buf, sizeof(buf),
             "{\"sta_connected\":%s,\"sta_ip\":\"%s\",\"sta_gw\":\"%s\",\"ap_ip\":\"%s\","
             "\"rssi\":%d,\"channel\":%u,\"clients\":%d,\"uptime\":%lu,\"free_heap\":%lu}",
             st.sta_connected ? "true" : "false", st.sta_ip, st.sta_gw, st.ap_ip,
             st.rssi, st.channel, st.clients,
             (unsigned long)st.uptime_s, (unsigned long)st.free_heap);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static esp_err_t config_get(httpd_req_t *req)
{
    repeater_cfg_t c;
    repeater_get_cfg(&c);
    char sta[80], ap[80], buf[320];
    json_str(sta, sizeof(sta), c.sta_ssid);
    json_str(ap, sizeof(ap), c.ap_ssid);
    snprintf(buf, sizeof(buf),
             "{\"sta_ssid\":%s,\"sta_has_pass\":%s,\"ap_ssid\":%s,\"ap_has_pass\":%s,\"ap_max_conn\":%u}",
             sta, c.sta_pass[0] ? "true" : "false",
             ap, c.ap_pass[0] ? "true" : "false", c.ap_max_conn);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, buf);
}

static esp_err_t config_post(httpd_req_t *req)
{
    char body[768];
    if (req->content_len >= sizeof(body)) {
        return send_json_error(req, "413 Payload Too Large", "请求过大");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = '\0';

    /* 以当前配置为基础：密码字段为空表示不修改，*_open=1 表示改为开放网络 */
    repeater_cfg_t c;
    repeater_get_cfg(&c);
    char tmp[80];
    int r;

    if ((r = form_get(body, "sta_ssid", c.sta_ssid, sizeof(c.sta_ssid))) < 0) {
        return send_json_error(req, "400 Bad Request", "上游 SSID 过长");
    }
    if ((r = form_get(body, "sta_pass", tmp, sizeof(c.sta_pass))) < 0) {
        return send_json_error(req, "400 Bad Request", "上游密码过长");
    } else if (r > 0 && tmp[0]) {
        strlcpy(c.sta_pass, tmp, sizeof(c.sta_pass));
    }
    if (form_get(body, "sta_open", tmp, sizeof(tmp)) > 0 && strcmp(tmp, "1") == 0) {
        c.sta_pass[0] = '\0';
    }

    if ((r = form_get(body, "ap_ssid", c.ap_ssid, sizeof(c.ap_ssid))) < 0) {
        return send_json_error(req, "400 Bad Request", "AP SSID 过长");
    }
    if ((r = form_get(body, "ap_pass", tmp, sizeof(c.ap_pass))) < 0) {
        return send_json_error(req, "400 Bad Request", "AP 密码过长");
    } else if (r > 0 && tmp[0]) {
        strlcpy(c.ap_pass, tmp, sizeof(c.ap_pass));
    }
    if (form_get(body, "ap_open", tmp, sizeof(tmp)) > 0 && strcmp(tmp, "1") == 0) {
        c.ap_pass[0] = '\0';
    }
    if (form_get(body, "ap_max_conn", tmp, sizeof(tmp)) > 0) {
        int v = atoi(tmp);
        c.ap_max_conn = (v >= 1 && v <= 15) ? v : 0; /* 0 会被校验拒绝 */
    }

    const char *msg = NULL;
    if (repeater_set_cfg(&c, &msg) != ESP_OK) {
        return send_json_error(req, "400 Bad Request", msg ? msg : "保存失败");
    }
    ESP_LOGI(TAG, "配置已保存");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

#define SCAN_MAX 30

static esp_err_t scan_get(httpd_req_t *req)
{
    repeater_scan_item_t *items = calloc(SCAN_MAX, sizeof(*items));
    if (!items) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    int n = repeater_scan(items, SCAN_MAX);
    if (n < 0) {
        free(items);
        return send_json_error(req, "503 Service Unavailable", "扫描失败，请稍后重试");
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, "{\"ok\":true,\"aps\":[");
    char buf[160], ssid[80];
    for (int i = 0; i < n; i++) {
        json_str(ssid, sizeof(ssid), items[i].ssid);
        snprintf(buf, sizeof(buf), "%s{\"ssid\":%s,\"rssi\":%d,\"channel\":%u,\"open\":%s}",
                 i ? "," : "", ssid, items[i].rssi, items[i].channel, items[i].open ? "true" : "false");
        httpd_resp_sendstr_chunk(req, buf);
    }
    httpd_resp_sendstr_chunk(req, "]}");
    free(items);
    return httpd_resp_sendstr_chunk(req, NULL);
}

static void restart_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
}

static esp_err_t restart_post(httpd_req_t *req)
{
    ESP_LOGW(TAG, "收到重启请求");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"ok\":true}");
    xTaskCreate(restart_task, "restart", 2048, NULL, 5, NULL);
    return ESP_OK;
}

/* ---------- WebSocket 日志 ---------- */

static void ws_send_fd(void *ctx, const char *data, size_t len)
{
    int fd = (int)(intptr_t)ctx;
    httpd_ws_frame_t f = {
        .type = HTTPD_WS_TYPE_BINARY,  /* 分块可能切断 UTF-8 字符，用二进制帧由浏览器流式解码 */
        .payload = (uint8_t *)data,
        .len = len,
        .final = true,
    };
    esp_err_t err = httpd_ws_send_frame_async(s_server, fd, &f);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "WS 发送失败 fd=%d len=%u: %s", fd, (unsigned)len, esp_err_to_name(err));
    }
}

/* 广播给所有 WS 客户端（由日志推送任务调用） */
static void ws_broadcast(void *ctx, const char *data, size_t len)
{
    if (!s_server) {
        return;
    }
    int fds[CONFIG_LWIP_MAX_SOCKETS];
    size_t n = sizeof(fds) / sizeof(fds[0]);
    if (httpd_get_client_list(s_server, &n, fds) != ESP_OK) {
        return;
    }
    for (size_t i = 0; i < n; i++) {
        if (httpd_ws_get_fd_info(s_server, fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET) {
            ws_send_fd((void *)(intptr_t)fds[i], data, len);
        }
    }
}

static void ws_send_history_work(void *arg)
{
    ESP_LOGI(TAG, "WS 客户端 fd=%d 已连接，发送历史日志", (int)(intptr_t)arg);
    web_log_send_history(ws_send_fd, arg);
}

/* 纯文本历史日志，便于不用 WebSocket 时查看 */
static void http_chunk_sink(void *ctx, const char *data, size_t len)
{
    httpd_resp_send_chunk((httpd_req_t *)ctx, data, len);
}

static esp_err_t log_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    web_log_send_history(http_chunk_sink, req);
    return httpd_resp_send_chunk(req, NULL, 0);
}

/* IDF 6.x 握手时不再调用 handler，用握手后回调发送历史日志 */
static esp_err_t ws_post_handshake(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);
    /* 排队到 httpd 任务，确保 101 响应已发出 */
    return httpd_queue_work(req->handle, ws_send_history_work, (void *)(intptr_t)fd);
}

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        return ESP_OK;
    }
    /* 客户端发来的数据帧：读出丢弃 */
    httpd_ws_frame_t f = { 0 };
    esp_err_t err = httpd_ws_recv_frame(req, &f, 0);
    if (err != ESP_OK || f.len == 0) {
        return err;
    }
    uint8_t *buf = malloc(f.len);
    if (!buf) {
        return ESP_ERR_NO_MEM;
    }
    f.payload = buf;
    err = httpd_ws_recv_frame(req, &f, f.len);
    free(buf);
    return err;
}

/* ---------- HTTP/2 站点自定义接口 ---------- */

typedef struct {
    httpd_req_t *req;
    bool not_first;
} route_list_ctx_t;

static void route_chunk(const char *path, const char *json, void *arg)
{
    route_list_ctx_t *ctx = arg;
    /* 每个字符最多转义成 6 字节 */
    size_t cap = strlen(json) * 6 + strlen(path) * 6 + 32;
    char *buf = malloc(cap);
    if (!buf) {
        return;
    }
    size_t o = 0;
    o += snprintf(buf + o, cap - o, "%s{\"path\":", ctx->not_first ? "," : "");
    o += json_str(buf + o, cap - o, path);
    o += snprintf(buf + o, cap - o, ",\"json\":");
    o += json_str(buf + o, cap - o, json);
    o += snprintf(buf + o, cap - o, "}");
    httpd_resp_send_chunk(ctx->req, buf, o);
    free(buf);
    ctx->not_first = true;
}

static esp_err_t h2routes_get(httpd_req_t *req)
{
    char head[160], domain[64];
    h2_site_get_domain(domain, sizeof(domain));
    snprintf(head, sizeof(head),
             "{\"domain\":\"%s\",\"port\":%d,\"max\":%d,\"max_json\":%d,\"routes\":[",
             domain, H2_SITE_PORT, H2_ROUTES_MAX, H2_ROUTE_JSON_MAX);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, head);
    route_list_ctx_t ctx = { .req = req };
    h2_routes_foreach(route_chunk, &ctx);
    httpd_resp_sendstr_chunk(req, "]}");
    return httpd_resp_sendstr_chunk(req, NULL);
}

/* 读取表单字段到新分配的缓冲区（已 URL 解码），不存在或非法返回 NULL */
static char *form_get_alloc(const char *body, const char *key)
{
    size_t cap = strlen(body) + 1;
    char *raw = malloc(cap), *out = malloc(cap);
    if (!raw || !out || httpd_query_key_value(body, key, raw, cap) != ESP_OK ||
        !url_decode(raw, out, cap)) {
        free(raw);
        free(out);
        return NULL;
    }
    free(raw);
    return out;
}

static esp_err_t h2routes_post(httpd_req_t *req)
{
    const size_t max = (H2_ROUTE_PATH_MAX + H2_ROUTE_JSON_MAX) * 3 + 64;
    if (req->content_len == 0 || req->content_len > max) {
        return send_json_error(req, "413 Payload Too Large", "请求过大");
    }
    char *body = malloc(req->content_len + 1);
    if (!body) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            free(body);
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = '\0';

    char *action = form_get_alloc(body, "action");
    char *path = form_get_alloc(body, "path");
    char *json = form_get_alloc(body, "json");
    free(body);

    esp_err_t ret;
    const char *msg = NULL;
    if (!action || !path) {
        ret = send_json_error(req, "400 Bad Request", "缺少 action 或 path");
    } else if (strcmp(action, "set") == 0) {
        if (!json) {
            ret = send_json_error(req, "400 Bad Request", "缺少 json");
        } else if (h2_routes_set(path, json, &msg) != ESP_OK) {
            ret = send_json_error(req, "400 Bad Request", msg ? msg : "保存失败");
        } else {
            httpd_resp_set_type(req, "application/json");
            ret = httpd_resp_sendstr(req, "{\"ok\":true}");
        }
    } else if (strcmp(action, "del") == 0) {
        if (h2_routes_del(path) != ESP_OK) {
            ret = send_json_error(req, "404 Not Found", "没有该路径");
        } else {
            httpd_resp_set_type(req, "application/json");
            ret = httpd_resp_sendstr(req, "{\"ok\":true}");
        }
    } else {
        ret = send_json_error(req, "400 Bad Request", "action 须为 set 或 del");
    }
    free(action);
    free(path);
    free(json);
    return ret;
}

/* ---------- 自定义 DNS 解析 ---------- */

static void dns_chunk(const char *name, uint32_t ip, void *arg)
{
    route_list_ctx_t *ctx = arg;
    char buf[160], ipstr[16];
    if (ip) {
        inet_ntoa_r(*(struct in_addr *)&ip, ipstr, sizeof(ipstr));
    } else {
        strcpy(ipstr, "ap");
    }
    /* 域名已校验为 [a-z0-9-_.]，无需转义 */
    int n = snprintf(buf, sizeof(buf), "%s{\"name\":\"%s\",\"ip\":\"%s\"}",
                     ctx->not_first ? "," : "", name, ipstr);
    httpd_resp_send_chunk(ctx->req, buf, n);
    ctx->not_first = true;
}

static esp_err_t dns_get(httpd_req_t *req)
{
    repeater_status_t st;
    repeater_get_status(&st);
    char head[96];
    snprintf(head, sizeof(head), "{\"max\":%d,\"ap_ip\":\"%s\",\"entries\":[", DNS_OVR_MAX, st.ap_ip);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr_chunk(req, head);
    route_list_ctx_t ctx = { .req = req };
    dns_relay_foreach_override(dns_chunk, &ctx);
    httpd_resp_sendstr_chunk(req, "]}");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t dns_post(httpd_req_t *req)
{
    char body[256];
    if (req->content_len == 0 || req->content_len >= sizeof(body)) {
        return send_json_error(req, "413 Payload Too Large", "请求过大");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = '\0';

    char action[8], name[80], ipstr[24] = "";
    if (form_get(body, "action", action, sizeof(action)) <= 0) {
        return send_json_error(req, "400 Bad Request", "action 须为 set 或 del");
    }
    int r = form_get(body, "name", name, sizeof(name));
    if (r == 0) {
        return send_json_error(req, "400 Bad Request", "缺少 name");
    } else if (r < 0) {
        return send_json_error(req, "400 Bad Request", "域名长度需为 1-63");
    }
    if (strcmp(action, "del") == 0) {
        if (dns_relay_del_override(name) != ESP_OK) {
            return send_json_error(req, "404 Not Found", "没有该域名");
        }
    } else if (strcmp(action, "set") == 0) {
        if (form_get(body, "ip", ipstr, sizeof(ipstr)) < 0) {
            return send_json_error(req, "400 Bad Request", "IP 格式错误");
        }
        uint32_t ip = 0;            /* 留空或 "ap"：解析为 AP 地址 */
        if (ipstr[0] && strcmp(ipstr, "ap") != 0) {
            /* 严格四段十进制；lwIP 的 inet_pton 会接受 "1.2.3" 这类简写 */
            unsigned b[4];
            char tail;
            if (sscanf(ipstr, "%3u.%3u.%3u.%3u%c", &b[0], &b[1], &b[2], &b[3], &tail) != 4 ||
                b[0] > 255 || b[1] > 255 || b[2] > 255 || b[3] > 255 ||
                strspn(ipstr, "0123456789.") != strlen(ipstr)) {
                return send_json_error(req, "400 Bad Request", "IP 格式错误，应为 IPv4，如 192.168.4.1");
            }
            uint8_t bytes[4] = { b[0], b[1], b[2], b[3] };
            memcpy(&ip, bytes, 4);  /* 网络字节序 */
            if (ip == 0 || ip == 0xFFFFFFFF) {
                return send_json_error(req, "400 Bad Request", "IP 不能为 0.0.0.0 或 255.255.255.255");
            }
        }
        const char *msg = NULL;
        if (dns_relay_set_override(name, ip, &msg) != ESP_OK) {
            return send_json_error(req, "400 Bad Request", msg ? msg : "保存失败");
        }
    } else {
        return send_json_error(req, "400 Bad Request", "action 须为 set 或 del");
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

/* ---------- HTTP/2 站点：域名与证书 ---------- */

static esp_err_t h2site_get(httpd_req_t *req)
{
    char *buf = malloc(2048);
    if (!buf) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    int n = h2_site_info_json(buf, 2048);
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_send(req, buf, n < 2048 ? n : 2047);
    free(buf);
    return ret;
}

static esp_err_t h2site_post(httpd_req_t *req)
{
    const size_t max = (H2_SITE_CERT_MAX + H2_SITE_KEY_MAX) * 3 + 256;
    if (req->content_len == 0 || req->content_len > max) {
        return send_json_error(req, "413 Payload Too Large", "请求过大（证书不超过 8KB，私钥不超过 4KB）");
    }
    char *body = malloc(req->content_len + 1);
    if (!body) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            free(body);
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = '\0';

    char *action = form_get_alloc(body, "action");
    char *domain = form_get_alloc(body, "domain");
    char *cert = form_get_alloc(body, "cert");
    char *key = form_get_alloc(body, "key");
    /* 请求体含私钥，尽快清零释放 */
    memset(body, 0, got);
    free(body);

    esp_err_t ret;
    if (action && strcmp(action, "reset") == 0) {
        if (h2_site_reset() == ESP_OK) {
            httpd_resp_set_type(req, "application/json");
            ret = httpd_resp_sendstr(req, "{\"ok\":true}");
        } else {
            ret = send_json_error(req, "500 Internal Server Error", "清除 NVS 失败");
        }
    } else if (action && strcmp(action, "set") == 0) {
        const char *msg = NULL;
        char warn[160];
        if (h2_site_update(domain, cert, key, &msg, warn, sizeof(warn)) != ESP_OK) {
            ret = send_json_error(req, "400 Bad Request", msg ? msg : "保存失败");
        } else {
            char resp[240], esc[200];
            json_str(esc, sizeof(esc), warn);
            snprintf(resp, sizeof(resp), "{\"ok\":true,\"warning\":%s}", esc);
            httpd_resp_set_type(req, "application/json");
            ret = httpd_resp_sendstr(req, resp);
        }
    } else {
        ret = send_json_error(req, "400 Bad Request", "action 须为 set 或 reset");
    }
    free(action);
    free(domain);
    free(cert);
    if (key) {
        memset(key, 0, strlen(key));
        free(key);
    }
    return ret;
}

/* ---------- 流量记录 ---------- */

static esp_err_t monitor_page_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    return httpd_resp_send(req, monitor_html_start, monitor_html_end - monitor_html_start - 1);
}

static esp_err_t send_owned_json(httpd_req_t *req, char *buf, size_t len)
{
    if (!buf) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t ret = httpd_resp_send(req, buf, len);
    free(buf);
    return ret;
}

static bool chunk_writer(void *ctx, const char *data, size_t len)
{
    return httpd_resp_send_chunk((httpd_req_t *)ctx, data, len) == ESP_OK;
}

/* 记录数据分批序列化、分块发送（不在设备上拼出整个应答） */
static esp_err_t send_streamed_json(httpd_req_t *req, esp_err_t err)
{
    if (err == ESP_ERR_NO_MEM) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    if (err != ESP_OK) {
        return ESP_FAIL;
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t mon_live_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_streamed_json(req, monitor_live_write(chunk_writer, req));
}

static esp_err_t mon_dns_get(httpd_req_t *req)
{
    char q[48], v[16];
    uint32_t since = 0;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "since", v, sizeof(v)) == ESP_OK) {
        since = strtoul(v, NULL, 10);
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_streamed_json(req, monitor_dns_write(since, chunk_writer, req));
}

static esp_err_t mon_block_get(httpd_req_t *req)
{
    size_t len = 0;
    char *b = monitor_block_json(&len);
    return send_owned_json(req, b, len);
}

static int recv_small_body(httpd_req_t *req, char *body, size_t cap)
{
    if (req->content_len == 0 || req->content_len >= cap) {
        return -1;
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            return -1;
        }
        got += r;
    }
    body[got] = '\0';
    return (int)got;
}

static esp_err_t mon_block_post(httpd_req_t *req)
{
    char body[256], action[8], domain[96];
    if (recv_small_body(req, body, sizeof(body)) < 0) {
        return send_json_error(req, "400 Bad Request", "请求无效");
    }
    if (form_get(body, "action", action, sizeof(action)) <= 0 ||
        form_get(body, "domain", domain, sizeof(domain)) <= 0) {
        return send_json_error(req, "400 Bad Request", "缺少 action 或 domain");
    }
    if (strcmp(action, "add") == 0) {
        const char *msg = NULL;
        if (monitor_block_add(domain, &msg) != ESP_OK) {
            return send_json_error(req, "400 Bad Request", msg ? msg : "添加失败");
        }
    } else if (strcmp(action, "del") == 0) {
        if (monitor_block_del(domain) != ESP_OK) {
            return send_json_error(req, "404 Not Found", "黑名单中没有该域名");
        }
    } else {
        return send_json_error(req, "400 Bad Request", "action 须为 add 或 del");
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t mon_ctl_post(httpd_req_t *req)
{
    char body[64], action[16];
    if (recv_small_body(req, body, sizeof(body)) < 0 ||
        form_get(body, "action", action, sizeof(action)) <= 0) {
        return send_json_error(req, "400 Bad Request", "缺少 action");
    }
    if (strcmp(action, "enable") == 0) {
        if (monitor_set_enabled(true) != ESP_OK) {
            return send_json_error(req, "500 Internal Server Error", "内存不足，无法开启记录");
        }
    } else if (strcmp(action, "disable") == 0) {
        monitor_set_enabled(false);
    } else if (strcmp(action, "reset_perf") == 0) {
        monitor_reset_perf();
    } else {
        return send_json_error(req, "400 Bad Request", "action 须为 enable、disable 或 reset_perf");
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t mon_bench_get(httpd_req_t *req)
{
    size_t len = 0;
    char *b = monitor_bench_json(&len);
    return send_owned_json(req, b, len);
}

/* ---------- DNS 黑名单 ---------- */

/* GET：列表；带 ?test=<域名> 时按 DNS 中继的判定顺序给出该域名的处理结果 */
static esp_err_t dnsblock_get(httpd_req_t *req)
{
    char q[128], name[80];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "test", name, sizeof(name)) == ESP_OK) {
        char dec[80];
        if (!url_decode(name, dec, sizeof(dec))) {
            return send_json_error(req, "400 Bad Request", "域名无效");
        }
        size_t n = strlen(dec);
        while (n && dec[n - 1] == '.') dec[--n] = '\0';
        for (char *p = dec; *p; p++) *p = (char)tolower((unsigned char)*p);
        for (char *p = dec; *p; p++) {
            if (!(isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == '.')) {
                return send_json_error(req, "400 Bad Request", "域名只能包含字母、数字、- _ .");
            }
        }
        const char *result, *detail = "";
        char rule[72] = "";
        uint32_t ip;
        if (monitor_is_blocked(dec)) {
            result = "blocked_monitor";             /* 记录页临时黑名单 */
        } else if (dns_relay_get_override(dec, &ip)) {
            result = "local";                       /* 自定义解析 */
        } else {
            dnsf_result_t r = dns_filter_check(dec, rule, sizeof(rule));
            result = r == DNSF_BLOCK ? "blocked" : r == DNSF_ALLOW ? "allowed" : "forward";
            detail = rule;
        }
        char buf[256];
        snprintf(buf, sizeof(buf), "{\"name\":\"%s\",\"result\":\"%s\",\"rule\":\"%s\"}", dec, result, detail);
        httpd_resp_set_type(req, "application/json");
        return httpd_resp_sendstr(req, buf);
    }
    size_t len = 0;
    char *b = dns_filter_json(&len);
    return send_owned_json(req, b, len);
}

static esp_err_t dnsblock_post(httpd_req_t *req)
{
    const size_t max = (DNSF_BLOCK_MAX + DNSF_ALLOW_MAX) * (DNSF_NAME_MAX + 2) * 3 + 64;
    if (req->content_len == 0 || req->content_len > max) {
        return send_json_error(req, "413 Payload Too Large", "请求过大");
    }
    char *body = malloc(req->content_len + 1);
    if (!body) {
        return send_json_error(req, "500 Internal Server Error", "内存不足");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) {
            free(body);
            return ESP_FAIL;
        }
        got += r;
    }
    body[got] = '\0';
    char *block = form_get_alloc(body, "block");
    char *allow = form_get_alloc(body, "allow");
    free(body);
    char err[200];
    esp_err_t e = dns_filter_set(block ? block : "", allow ? allow : "", err, sizeof(err));
    free(block);
    free(allow);
    if (e != ESP_OK) {
        return send_json_error(req, "400 Bad Request", err);
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

/* ---------- 配置导出（含密码与私钥，网页端转换为 YAML） ---------- */

static void chunk_json_str(httpd_req_t *req, const char *s)
{
    size_t cap = strlen(s) * 6 + 3;
    char *b = malloc(cap);
    if (!b) {
        return;
    }
    size_t n = json_str(b, cap, s);
    httpd_resp_send_chunk(req, b, n);
    free(b);
}

static void export_site(const char *domain, const char *cert, const char *key, void *arg)
{
    httpd_req_t *req = arg;
    httpd_resp_sendstr_chunk(req, "\"h2_site\":{\"domain\":");
    chunk_json_str(req, domain);
    if (cert && key) {
        httpd_resp_sendstr_chunk(req, ",\"cert\":");
        chunk_json_str(req, cert);
        httpd_resp_sendstr_chunk(req, ",\"key\":");
        chunk_json_str(req, key);
    }
    httpd_resp_sendstr_chunk(req, "}");
}

static esp_err_t export_get(httpd_req_t *req)
{
    repeater_cfg_t c;
    repeater_get_cfg(&c);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    httpd_resp_sendstr_chunk(req, "{\"version\":1,\"wifi\":{\"sta_ssid\":");
    chunk_json_str(req, c.sta_ssid);
    httpd_resp_sendstr_chunk(req, ",\"sta_password\":");
    chunk_json_str(req, c.sta_pass);
    httpd_resp_sendstr_chunk(req, ",\"ap_ssid\":");
    chunk_json_str(req, c.ap_ssid);
    httpd_resp_sendstr_chunk(req, ",\"ap_password\":");
    chunk_json_str(req, c.ap_pass);
    char num[48];
    snprintf(num, sizeof(num), ",\"ap_max_conn\":%u},", c.ap_max_conn);
    httpd_resp_sendstr_chunk(req, num);

    route_list_ctx_t ctx = { .req = req };
    httpd_resp_sendstr_chunk(req, "\"dns\":[");
    dns_relay_foreach_override(dns_chunk, &ctx);
    httpd_resp_sendstr_chunk(req, "],");

    h2_site_export(export_site, req);

    ctx.not_first = false;
    httpd_resp_sendstr_chunk(req, ",\"h2_routes\":[");
    h2_routes_foreach(route_chunk, &ctx);
    httpd_resp_sendstr_chunk(req, "],\"dns_blacklist\":");
    size_t flen = 0;
    char *fj = dns_filter_json(&flen);
    if (fj) {
        httpd_resp_send_chunk(req, fj, flen);
        free(fj);
    } else {
        httpd_resp_sendstr_chunk(req, "null");
    }
    httpd_resp_sendstr_chunk(req, "}");
    ESP_LOGI(TAG, "配置已导出");
    return httpd_resp_sendstr_chunk(req, NULL);
}

esp_err_t web_server_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.max_uri_handlers = 30;
    cfg.lru_purge_enable = true;
    cfg.stack_size = 6144;

    esp_err_t err = httpd_start(&s_server, &cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start 失败: %s", esp_err_to_name(err));
        return err;
    }

    const httpd_uri_t uris[] = {
        { .uri = "/",            .method = HTTP_GET,  .handler = index_get },
        { .uri = "/api/status",  .method = HTTP_GET,  .handler = status_get },
        { .uri = "/api/config",  .method = HTTP_GET,  .handler = config_get },
        { .uri = "/api/config",  .method = HTTP_POST, .handler = config_post },
        { .uri = "/api/scan",    .method = HTTP_GET,  .handler = scan_get },
        { .uri = "/api/log",     .method = HTTP_GET,  .handler = log_get },
        { .uri = "/api/restart", .method = HTTP_POST, .handler = restart_post },
        { .uri = "/api/h2routes", .method = HTTP_GET,  .handler = h2routes_get },
        { .uri = "/api/h2routes", .method = HTTP_POST, .handler = h2routes_post },
        { .uri = "/api/dns",      .method = HTTP_GET,  .handler = dns_get },
        { .uri = "/api/dns",      .method = HTTP_POST, .handler = dns_post },
        { .uri = "/api/h2site",   .method = HTTP_GET,  .handler = h2site_get },
        { .uri = "/api/h2site",   .method = HTTP_POST, .handler = h2site_post },
        { .uri = "/api/export",   .method = HTTP_GET,  .handler = export_get },
        { .uri = "/api/dnsblock", .method = HTTP_GET,  .handler = dnsblock_get },
        { .uri = "/api/dnsblock", .method = HTTP_POST, .handler = dnsblock_post },
        { .uri = "/monitor",       .method = HTTP_GET,  .handler = monitor_page_get },
        { .uri = "/api/mon/live",  .method = HTTP_GET,  .handler = mon_live_get },
        { .uri = "/api/mon/dns",   .method = HTTP_GET,  .handler = mon_dns_get },
        { .uri = "/api/mon/block", .method = HTTP_GET,  .handler = mon_block_get },
        { .uri = "/api/mon/block", .method = HTTP_POST, .handler = mon_block_post },
        { .uri = "/api/mon/ctl",   .method = HTTP_POST, .handler = mon_ctl_post },
        { .uri = "/api/mon/bench", .method = HTTP_GET,  .handler = mon_bench_get },
        { .uri = "/ws",          .method = HTTP_GET,  .handler = ws_handler, .is_websocket = true,
          .ws_post_handshake_cb = ws_post_handshake },
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++) {
        httpd_register_uri_handler(s_server, &uris[i]);
    }

    web_log_set_sink(ws_broadcast);
    ESP_LOGI(TAG, "Web 配置页已启动，端口 %d", cfg.server_port);
    return ESP_OK;
}
