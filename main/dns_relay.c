/*
 * DNS 中继：监听 AP 地址 192.168.4.1:53，把客户端的查询转发给 STA 当前的上游 DNS，
 * 再把应答送回客户端。
 *
 * AP 的 DHCP 服务器默认把自身地址作为 DNS 下发，客户端无论何时连入
 * （包括上游尚未连上时），拿到的 DNS 都是可用的；上游 DNS 变化也无需客户端续租。
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "repeater.h"

#define DNS_PORT      53
#define BUF_SIZE      1500
#define SLOTS         32
#define TIMEOUT_MS    5000

static const char *TAG = "dns";

typedef struct {
    bool used;
    uint16_t orig_id;
    uint16_t new_id;
    struct sockaddr_in client;
    TickType_t ts;
} slot_t;

static slot_t s_slots[SLOTS];
static esp_netif_t *s_ap, *s_sta;

static bool get_upstream(struct sockaddr_in *out)
{
    esp_netif_dns_info_t dns;
    for (int t = ESP_NETIF_DNS_MAIN; t <= ESP_NETIF_DNS_BACKUP; t++) {
        if (esp_netif_get_dns_info(s_sta, t, &dns) == ESP_OK &&
            dns.ip.type == ESP_IPADDR_TYPE_V4 && dns.ip.u_addr.ip4.addr != 0) {
            memset(out, 0, sizeof(*out));
            out->sin_family = AF_INET;
            out->sin_port = htons(DNS_PORT);
            out->sin_addr.s_addr = dns.ip.u_addr.ip4.addr;
            return true;
        }
    }
    return false;
}

static slot_t *alloc_slot(TickType_t now)
{
    slot_t *oldest = &s_slots[0];
    for (int i = 0; i < SLOTS; i++) {
        slot_t *s = &s_slots[i];
        if (!s->used || now - s->ts > pdMS_TO_TICKS(TIMEOUT_MS)) {
            return s;
        }
        if (s->ts < oldest->ts) {
            oldest = s;
        }
    }
    return oldest;
}

static void dns_relay_task(void *arg)
{
    static uint8_t buf[BUF_SIZE];
    uint16_t next_id = (uint16_t)esp_random();

    /* 只监听 AP 地址，不在上游局域网上充当 DNS 服务器 */
    esp_netif_ip_info_t ap_ip;
    esp_netif_get_ip_info(s_ap, &ap_ip);

    int lsock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int usock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(DNS_PORT),
        .sin_addr.s_addr = ap_ip.ip.addr,
    };
    if (lsock < 0 || usock < 0 || bind(lsock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "socket/bind 失败 errno=%d", errno);
        goto out;
    }
    ESP_LOGI(TAG, "DNS 中继已启动 " IPSTR ":53", IP2STR(&ap_ip.ip));

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(lsock, &rfds);
        FD_SET(usock, &rfds);
        if (select((lsock > usock ? lsock : usock) + 1, &rfds, NULL, NULL, NULL) <= 0) {
            continue;
        }
        TickType_t now = xTaskGetTickCount();

        /* 客户端查询 -> 上游 */
        if (FD_ISSET(lsock, &rfds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            int n = recvfrom(lsock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            struct sockaddr_in up;
            if (n >= 12 && get_upstream(&up)) {
                slot_t *s = alloc_slot(now);
                s->used = true;
                s->orig_id = (buf[0] << 8) | buf[1];
                s->new_id = next_id++;
                s->client = from;
                s->ts = now;
                buf[0] = s->new_id >> 8;
                buf[1] = s->new_id & 0xff;
                sendto(usock, buf, n, 0, (struct sockaddr *)&up, sizeof(up));
            }
            /* 上游未连上时直接丢弃，客户端会超时重试 */
        }

        /* 上游应答 -> 客户端 */
        if (FD_ISSET(usock, &rfds)) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            int n = recvfrom(usock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n < 12 || from.sin_port != htons(DNS_PORT)) {
                continue;
            }
            uint16_t id = (buf[0] << 8) | buf[1];
            for (int i = 0; i < SLOTS; i++) {
                slot_t *s = &s_slots[i];
                if (s->used && s->new_id == id) {
                    buf[0] = s->orig_id >> 8;
                    buf[1] = s->orig_id & 0xff;
                    sendto(lsock, buf, n, 0, (struct sockaddr *)&s->client, sizeof(s->client));
                    s->used = false;
                    break;
                }
            }
        }
    }

out:
    if (lsock >= 0) close(lsock);
    if (usock >= 0) close(usock);
    vTaskDelete(NULL);
}

void dns_relay_start(esp_netif_t *ap, esp_netif_t *sta)
{
    s_ap = ap;
    s_sta = sta;
    xTaskCreate(dns_relay_task, "dns_relay", 4096, NULL, 5, NULL);
}
