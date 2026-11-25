/* HTTPS 站点的临时 TLS 透传，见 h2_pass.h */
#include <string.h>
#include <strings.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "h2_pass.h"
#include "h2_site.h"
#include "repeater.h"

#define NVS_NS              "h2pass"
#define H2_PASS_MAX_CONNS   2           /* 同时透传的连接数（每条占 2 个 socket） */
#define H2_PASS_LINGER_MS   15000       /* 窗口结束后，透传中的连接最多再留这么久 */
#define H2_PASS_IDLE_MS     500         /* 窗口结束后空闲这么久就关闭 */
#define H2_PASS_CONNECT_S   5
#define H2_PASS_BUF         2048

static const char *TAG = "h2_pass";

static volatile bool s_enabled;
static volatile uint8_t s_secs = H2_PASS_SECS_DEFAULT;
static volatile int64_t s_until_us;     /* 透传窗口结束时刻（esp_timer_get_time） */
static volatile uint8_t s_conns;
static volatile uint32_t s_triggers, s_relayed;
static volatile uint32_t s_fc_hits;
static volatile int64_t s_fc_last_us;   /* 上次命中 feature_configuration 的时刻，0 = 还没命中过 */
static portMUX_TYPE s_mux = portMUX_INITIALIZER_UNLOCKED;

typedef struct {
    int fd;
    char peer[16];
} relay_arg_t;

static bool window_open(void)
{
    return esp_timer_get_time() < s_until_us;
}

void h2_pass_load(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        uint8_t en = 0, secs = H2_PASS_SECS_DEFAULT;
        nvs_get_u8(h, "enabled", &en);
        nvs_get_u8(h, "secs", &secs);
        nvs_close(h);
        s_enabled = en != 0;
        if (secs >= 1 && secs <= H2_PASS_SECS_MAX) {
            s_secs = secs;
        }
    }
    ESP_LOGI(TAG, "TLS 透传：%s，窗口 %u 秒", s_enabled ? "开启" : "关闭", (unsigned)s_secs);
}

void h2_pass_get(h2_pass_info_t *out)
{
    out->enabled = s_enabled;
    out->secs = s_secs;
    out->active = window_open();
    out->conns = s_conns;
    out->triggers = s_triggers;
    out->relayed = s_relayed;
    out->fc_hits = s_fc_hits;
    int64_t last = s_fc_last_us;
    out->fc_ago_s = last ? (int32_t)((esp_timer_get_time() - last) / 1000000) : -1;
}

void h2_pass_note_hit(const char *req_path)
{
    for (const char *p = req_path; *p; p++) {
        if (strncasecmp(p, H2_PASS_FEATURE_CFG, strlen(H2_PASS_FEATURE_CFG)) == 0) {
            s_fc_last_us = esp_timer_get_time();
            s_fc_hits++;
            return;
        }
    }
}

esp_err_t h2_pass_set(bool enabled, int secs)
{
    if (secs < 1 || secs > H2_PASS_SECS_MAX) {
        return ESP_ERR_INVALID_ARG;
    }
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(h, "enabled", enabled ? 1 : 0);
    if (err == ESP_OK) err = nvs_set_u8(h, "secs", (uint8_t)secs);
    if (err == ESP_OK) err = nvs_commit(h);
    nvs_close(h);
    if (err == ESP_OK) {
        s_enabled = enabled;
        s_secs = (uint8_t)secs;
        if (!enabled) {
            s_until_us = 0;     /* 关闭时立即结束窗口 */
        }
        ESP_LOGI(TAG, "TLS 透传已%s，窗口 %d 秒", enabled ? "开启" : "关闭", secs);
    }
    return err;
}

bool h2_pass_try_trigger(h2_req_t *req)
{
    if (!s_enabled) {
        return false;
    }
    const char *path = h2_req_path(req);
    size_t n = strlen(path), pl = strlen(H2_PASS_TRIGGER_PREFIX), sl = strlen(H2_PASS_TRIGGER_SUFFIX);
    if (n <= pl + sl || strncasecmp(path, H2_PASS_TRIGGER_PREFIX, pl) != 0 ||
        strcasecmp(path + n - sl, H2_PASS_TRIGGER_SUFFIX) != 0) {
        return false;
    }
    s_until_us = esp_timer_get_time() + (int64_t)s_secs * 1000000;
    s_triggers++;
    ESP_LOGI(TAG, "PASS path=%s peer=%s：本机不应答，%u 秒内新连接透传到真实服务器",
             path, h2_req_peer(req), (unsigned)s_secs);
    h2_req_refuse(req);
    return true;
}

/* 把 src 上读到的数据全部写到 dst；返回读到的字节数，0 = 对端关闭，-1 = 出错 */
static int pump(int src, int dst, uint8_t *buf)
{
    int n = recv(src, buf, H2_PASS_BUF, 0);
    if (n <= 0) {
        return n == 0 ? 0 : -1;
    }
    for (int off = 0; off < n;) {
        int w = send(dst, buf + off, n - off, 0);
        if (w <= 0) {
            return -1;
        }
        off += w;
    }
    return n;
}

static void relay_task(void *arg)
{
    relay_arg_t *a = arg;
    int cfd = a->fd, ufd = -1;
    uint8_t *buf = malloc(H2_PASS_BUF);
    char domain[64], ipstr[16] = "?";
    uint32_t up = 0, down = 0;
    h2_site_get_domain(domain, sizeof(domain));

    /* 本机自己的解析走上游 DNS（不经过给客户端用的 DNS 中继），拿到的是真实地址 */
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    if (!buf || getaddrinfo(domain, "443", &hints, &res) != 0 || !res) {
        ESP_LOGW(TAG, "%s 透传失败：解析 %s 失败", a->peer, domain);
        goto done;
    }
    struct sockaddr_in sa = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    inet_ntoa_r(sa.sin_addr, ipstr, sizeof(ipstr));
    ufd = socket(AF_INET, SOCK_STREAM, 0);
    if (ufd < 0) {
        ESP_LOGW(TAG, "%s 透传失败：socket 不足", a->peer);
        goto done;
    }
    struct timeval tv = { .tv_sec = H2_PASS_CONNECT_S };
    setsockopt(ufd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(ufd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(ufd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        ESP_LOGW(TAG, "%s 透传失败：连接 %s (%s) 失败 errno=%d", a->peer, domain, ipstr, errno);
        goto done;
    }
    ESP_LOGI(TAG, "%s 透传开始 -> %s (%s):443", a->peer, domain, ipstr);

    int64_t last_data = esp_timer_get_time();
    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(cfd, &rfds);
        FD_SET(ufd, &rfds);
        struct timeval to = { .tv_sec = 0, .tv_usec = 100 * 1000 };
        int r = select((cfd > ufd ? cfd : ufd) + 1, &rfds, NULL, NULL, &to);
        if (r < 0) {
            break;
        }
        int64_t now = esp_timer_get_time();
        if (r > 0) {
            int n;
            if (FD_ISSET(cfd, &rfds)) {
                if ((n = pump(cfd, ufd, buf)) <= 0) break;
                up += n;
            }
            if (FD_ISSET(ufd, &rfds)) {
                if ((n = pump(ufd, cfd, buf)) <= 0) break;
                down += n;
            }
            last_data = now;
        }
        /* 窗口结束后：空闲即关闭，让客户端下次重连回到本机；最多再留 H2_PASS_LINGER_MS */
        int64_t over = now - s_until_us;
        if (over > 0 && (now - last_data > H2_PASS_IDLE_MS * 1000LL || over > H2_PASS_LINGER_MS * 1000LL)) {
            break;
        }
    }
    ESP_LOGI(TAG, "%s 透传结束：上行 %u 字节，下行 %u 字节", a->peer, (unsigned)up, (unsigned)down);

done:
    if (ufd >= 0) {
        close(ufd);
    }
    close(cfd);
    free(buf);
    free(a);
    portENTER_CRITICAL(&s_mux);
    s_conns--;
    portEXIT_CRITICAL(&s_mux);
    vTaskDelete(NULL);
}

/* accept 任务里调用：透传窗口内接管新连接 */
static bool accept_hook(int fd, const char *peer, void *arg)
{
    (void)arg;
    if (!s_enabled || !window_open()) {
        return false;
    }
    bool ok = false;
    portENTER_CRITICAL(&s_mux);
    if (s_conns < H2_PASS_MAX_CONNS) {
        s_conns++;
        ok = true;
    }
    portEXIT_CRITICAL(&s_mux);
    if (!ok) {
        ESP_LOGW(TAG, "%s 透传连接数已满，交回本机处理", peer);
        return false;
    }
    relay_arg_t *a = calloc(1, sizeof(*a));
    if (a) {
        a->fd = fd;
        strlcpy(a->peer, peer, sizeof(a->peer));
    }
    if (!a || xTaskCreate(relay_task, "h2_pass", 4096, a, 5, NULL) != pdPASS) {
        free(a);
        portENTER_CRITICAL(&s_mux);
        s_conns--;
        portEXIT_CRITICAL(&s_mux);
        return false;
    }
    s_relayed++;
    return true;
}

void h2_pass_attach(h2_server_handle_t srv)
{
    h2_server_set_accept_hook(srv, accept_hook, NULL);
}
