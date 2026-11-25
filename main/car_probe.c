#include <string.h>
#include "nvs.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/netif.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "car_probe.h"

#define NVS_NS   "repeater"
#define NVS_KEY  "car_probe"

static const char *TAG = "car_probe";
static volatile bool s_on = true;       /* 默认开启 */

void car_probe_load(void)
{
    nvs_handle_t h;
    uint8_t v;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        if (nvs_get_u8(h, NVS_KEY, &v) == ESP_OK) {
            s_on = v != 0;
        }
        nvs_close(h);
    }
    ESP_LOGI(TAG, "本机应答车机联网检测：%s", s_on ? "开启" : "关闭");
}

bool car_probe_enabled(void)
{
    return s_on;
}

esp_err_t car_probe_set(bool on)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_u8(h, NVS_KEY, on ? 1 : 0);
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    if (err == ESP_OK) {
        s_on = on;
        ESP_LOGI(TAG, "已%s：本机应答车机联网检测", on ? "开启" : "关闭");
    }
    return err;
}

bool car_probe_dns_match(const char *name)
{
    if (strcmp(name, CAR_PROBE_ADMIN_HOST) == 0) {
        return true;
    }
    return s_on && (strcmp(name, CAR_PROBE_CONNMAN_HOST) == 0 || strcmp(name, CAR_PROBE_HEAD_HOST) == 0);
}

/* ---------- 别名网卡 ---------- */

static struct netif s_alias;

/* 本机以别名地址为源发出的包：lwIP 的按源地址选路钩子（ip4_route_src_hook）会选中别名网卡，
 * 这里再按目的地址选一次真正的出口（热点网卡）转交出去 */
static err_t alias_output(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    struct netif *out = ip4_route(ipaddr);
    if (out == NULL || out == netif || out->output == NULL) {
        return ERR_RTE;
    }
    return out->output(out, p, ipaddr);
}

static err_t alias_init(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = 'p';
    netif->output = alias_output;
    netif->mtu = 1500;
    return ERR_OK;
}

static esp_err_t alias_add(void *ctx)
{
    ip4_addr_t ip, mask, gw;
    ip4_addr_set_u32(&ip, car_probe_alias_addr());
    IP4_ADDR(&mask, 255, 255, 255, 255);    /* 只认这一个地址，不影响其他目的地址的选路 */
    ip4_addr_set_zero(&gw);
    if (netif_add(&s_alias, &ip, &mask, &gw, NULL, alias_init, ip4_input) == NULL) {
        return ESP_FAIL;
    }
    netif_set_link_up(&s_alias);
    netif_set_up(&s_alias);
    return ESP_OK;
}

uint32_t car_probe_alias_addr(void)
{
    return ipaddr_addr(CAR_PROBE_ALIAS_IP);
}

void car_probe_alias_start(void)
{
    esp_err_t err = esp_netif_tcpip_exec(alias_add, NULL);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "别名地址 %s 已挂到本机", CAR_PROBE_ALIAS_IP);
    } else {
        ESP_LOGE(TAG, "别名地址 %s 挂载失败", CAR_PROBE_ALIAS_IP);
    }
}
