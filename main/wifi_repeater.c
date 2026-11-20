/*
 * ESP32-S3 Wi-Fi 中继（APSTA + NAPT）
 *
 * STA 连上游路由器拿到 IP；SoftAP 给下游客户端分配 192.168.4.x，
 * lwIP NAPT 把 AP 侧流量地址转换后从 STA 发出。
 * 配置保存在 NVS，可通过 http://192.168.4.1/ 修改，页面同时显示实时日志。
 * 基于 ESP-IDF examples/wifi/softap_sta（CC0）。
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "repeater.h"
#include "h2_routes.h"
#include "h2_site.h"
#include "monitor.h"

#define RECONNECT_DELAY_MS  3000
#define APPLY_DELAY_MS      500   /* 先让 HTTP 响应发出去再动 Wi-Fi */

static const char *TAG = "repeater";

static esp_netif_t *s_netif_ap;
static esp_netif_t *s_netif_sta;
static repeater_cfg_t s_cfg;
static SemaphoreHandle_t s_cfg_lock;
static volatile bool s_sta_connected;
static volatile bool s_scanning;        /* 扫描期间暂停自动重连 */
static SemaphoreHandle_t s_scan_lock;

static void fill_wifi_configs(const repeater_cfg_t *c, wifi_config_t *ap, wifi_config_t *sta)
{
    memset(ap, 0, sizeof(*ap));
    strlcpy((char *)ap->ap.ssid, c->ap_ssid, sizeof(ap->ap.ssid));
    ap->ap.ssid_len = strlen(c->ap_ssid);
    strlcpy((char *)ap->ap.password, c->ap_pass, sizeof(ap->ap.password));
    ap->ap.max_connection = c->ap_max_conn;
    ap->ap.authmode = c->ap_pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    ap->ap.pmf_cfg.required = false;
    /* APSTA 下 AP 信道会自动跟随 STA 所连上游的信道 */

    memset(sta, 0, sizeof(*sta));
    /* ssid 32 字节、password 64 字节不要求 NUL 结尾，用 memcpy 避免截断 */
    memcpy(sta->sta.ssid, c->sta_ssid, strlen(c->sta_ssid));
    memcpy(sta->sta.password, c->sta_pass, strlen(c->sta_pass));
    sta->sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
    sta->sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    sta->sta.threshold.authmode = c->sta_pass[0] ? WIFI_AUTH_WPA_PSK : WIFI_AUTH_OPEN;
    sta->sta.sae_pwe_h2e = WPA3_SAE_PWE_BOTH;
}

static void reconnect_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(RECONNECT_DELAY_MS));
    if (!s_scanning) {          /* 扫描结束后由扫描函数负责重连 */
        esp_wifi_connect();
    }
    vTaskDelete(NULL);
}

static void event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT) {
        switch (id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_DISCONNECTED: {
            wifi_event_sta_disconnected_t *e = data;
            s_sta_connected = false;
            ESP_LOGW(TAG, "上游断开 reason=%d，%d ms 后重连", e->reason, RECONNECT_DELAY_MS);
            /* 不在事件循环里阻塞等待 */
            xTaskCreate(reconnect_task, "reconnect", 2048, NULL, 3, NULL);
            break;
        }
        case WIFI_EVENT_AP_STACONNECTED: {
            wifi_event_ap_staconnected_t *e = data;
            ESP_LOGI(TAG, "客户端 " MACSTR " 加入, AID=%d", MAC2STR(e->mac), e->aid);
            monitor_on_join(e->mac);
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            wifi_event_ap_stadisconnected_t *e = data;
            ESP_LOGI(TAG, "客户端 " MACSTR " 离开, reason=%d", MAC2STR(e->mac), e->reason);
            monitor_on_leave(e->mac);
            break;
        }
        default:
            break;
        }
    } else if (base == IP_EVENT) {
        if (id == IP_EVENT_STA_GOT_IP) {
            ip_event_got_ip_t *e = data;
            s_sta_connected = true;
            ESP_LOGI(TAG, "上游已连接，STA IP: " IPSTR " GW: " IPSTR,
                     IP2STR(&e->ip_info.ip), IP2STR(&e->ip_info.gw));
        } else if (id == IP_EVENT_ASSIGNED_IP_TO_CLIENT) {
            ip_event_assigned_ip_to_client_t *e = data;
            ESP_LOGI(TAG, "分配 " IPSTR " 给 " MACSTR, IP2STR(&e->ip), MAC2STR(e->mac));
            monitor_on_ip(e->mac, e->ip.addr, e->hostname);
        }
    }
}

/* ---------- 供 Web 页面调用 ---------- */

void repeater_get_cfg(repeater_cfg_t *out)
{
    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    *out = s_cfg;
    xSemaphoreGive(s_cfg_lock);
}

static void apply_task(void *arg)
{
    bool sta_changed = (bool)(uintptr_t)arg;
    vTaskDelay(pdMS_TO_TICKS(APPLY_DELAY_MS));

    repeater_cfg_t c;
    repeater_get_cfg(&c);
    wifi_config_t ap, sta;
    fill_wifi_configs(&c, &ap, &sta);

    ESP_LOGI(TAG, "应用新配置：上游 \"%s\"，AP \"%s\"", c.sta_ssid, c.ap_ssid);
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_config(WIFI_IF_AP, &ap));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_config(WIFI_IF_STA, &sta));
    if (sta_changed) {
        /* 触发 DISCONNECTED 事件，由重连逻辑用新配置连接 */
        esp_wifi_disconnect();
    }
    vTaskDelete(NULL);
}

esp_err_t repeater_set_cfg(const repeater_cfg_t *cfg, const char **err_msg)
{
    const char *msg = repeater_cfg_validate(cfg);
    if (msg) {
        *err_msg = msg;
        return ESP_ERR_INVALID_ARG;
    }
    esp_err_t err = repeater_cfg_save(cfg);
    if (err != ESP_OK) {
        *err_msg = "写入 NVS 失败";
        return err;
    }

    xSemaphoreTake(s_cfg_lock, portMAX_DELAY);
    bool sta_changed = strcmp(s_cfg.sta_ssid, cfg->sta_ssid) || strcmp(s_cfg.sta_pass, cfg->sta_pass);
    s_cfg = *cfg;
    xSemaphoreGive(s_cfg_lock);

    xTaskCreate(apply_task, "apply_cfg", 3072, (void *)(uintptr_t)sta_changed, 4, NULL);
    *err_msg = NULL;
    return ESP_OK;
}

void repeater_get_status(repeater_status_t *st)
{
    memset(st, 0, sizeof(*st));
    esp_netif_ip_info_t ip;

    st->sta_connected = s_sta_connected;
    if (esp_netif_get_ip_info(s_netif_sta, &ip) == ESP_OK) {
        snprintf(st->sta_ip, sizeof(st->sta_ip), IPSTR, IP2STR(&ip.ip));
        snprintf(st->sta_gw, sizeof(st->sta_gw), IPSTR, IP2STR(&ip.gw));
    }
    if (esp_netif_get_ip_info(s_netif_ap, &ip) == ESP_OK) {
        snprintf(st->ap_ip, sizeof(st->ap_ip), IPSTR, IP2STR(&ip.ip));
    }
    wifi_ap_record_t rec;
    if (s_sta_connected && esp_wifi_sta_get_ap_info(&rec) == ESP_OK) {
        st->rssi = rec.rssi;
        st->channel = rec.primary;
    } else {
        uint8_t ch;
        wifi_second_chan_t second;
        if (esp_wifi_get_channel(&ch, &second) == ESP_OK) {
            st->channel = ch;
        }
    }
    wifi_sta_list_t list;
    if (esp_wifi_ap_get_sta_list(&list) == ESP_OK) {
        st->clients = list.num;
    }
    st->uptime_s = (uint32_t)(esp_timer_get_time() / 1000000);
    st->free_heap = esp_get_free_heap_size();
}

static int cmp_rssi_desc(const void *a, const void *b)
{
    return ((const wifi_ap_record_t *)b)->rssi - ((const wifi_ap_record_t *)a)->rssi;
}

int repeater_scan(repeater_scan_item_t *out, int max)
{
    xSemaphoreTake(s_scan_lock, portMAX_DELAY);
    s_scanning = true;

    /* 未连上时 STA 一直在重连，处于 connecting 状态下无法扫描，先中止 */
    if (!s_sta_connected) {
        esp_wifi_disconnect();
    }
    wifi_scan_config_t sc = { .show_hidden = false };
    esp_err_t err = ESP_FAIL;
    for (int i = 0; i < 10; i++) {
        err = esp_wifi_scan_start(&sc, true);   /* 阻塞，约 2-3 秒 */
        if (err != ESP_ERR_WIFI_STATE) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(300));
    }

    int n_out = -1;
    if (err == ESP_OK) {
        uint16_t num = 0;
        esp_wifi_scan_get_ap_num(&num);
        if (num > 40) {
            num = 40;
        }
        wifi_ap_record_t *recs = calloc(num ? num : 1, sizeof(*recs));
        if (recs && esp_wifi_scan_get_ap_records(&num, recs) == ESP_OK) {
            qsort(recs, num, sizeof(*recs), cmp_rssi_desc);
            n_out = 0;
            for (int i = 0; i < num && n_out < max; i++) {
                if (!recs[i].ssid[0]) {
                    continue;
                }
                /* 同名多个 AP 只保留信号最强的（已按信号排序） */
                bool dup = false;
                for (int j = 0; j < n_out; j++) {
                    if (strcmp(out[j].ssid, (char *)recs[i].ssid) == 0) {
                        dup = true;
                        break;
                    }
                }
                if (dup) {
                    continue;
                }
                strlcpy(out[n_out].ssid, (char *)recs[i].ssid, sizeof(out[n_out].ssid));
                out[n_out].rssi = recs[i].rssi;
                out[n_out].channel = recs[i].primary;
                out[n_out].open = recs[i].authmode == WIFI_AUTH_OPEN;
                n_out++;
            }
        } else {
            esp_wifi_clear_ap_list();
        }
        free(recs);
        ESP_LOGI(TAG, "扫描完成，找到 %d 个网络", n_out);
    } else {
        ESP_LOGW(TAG, "扫描失败: %s", esp_err_to_name(err));
    }

    s_scanning = false;
    if (!s_sta_connected) {
        esp_wifi_connect();
    }
    xSemaphoreGive(s_scan_lock);
    return n_out;
}

/* ---------- 启动 ---------- */

void app_main(void)
{
    /* 最先接管日志，后面的启动日志也能在网页看到 */
    web_log_init();

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    s_cfg_lock = xSemaphoreCreateMutex();
    s_scan_lock = xSemaphoreCreateMutex();
    repeater_cfg_load(&s_cfg);
    h2_routes_init();
    dns_relay_load_overrides();
    h2_site_load();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_netif_ap = esp_netif_create_default_wifi_ap();
    s_netif_sta = esp_netif_create_default_wifi_sta();
    monitor_init(s_netif_ap);     /* 须在 Wi-Fi 启动、DNS 中继之前 */

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ASSIGNED_IP_TO_CLIENT, event_handler, NULL, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t ap_cfg, sta_cfg;
    fill_wifi_configs(&s_cfg, &ap_cfg, &sta_cfg);
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_cfg));

    ESP_ERROR_CHECK(esp_wifi_start());

    /* 出口走 STA；AP 侧开启 NAPT */
    ESP_ERROR_CHECK(esp_netif_set_default_netif(s_netif_sta));
    ESP_ERROR_CHECK(esp_netif_napt_enable(s_netif_ap));

    /* 客户端 DNS 指向 192.168.4.1（DHCP 默认下发），由中继转发到上游 DNS */
    dns_relay_start(s_netif_ap, s_netif_sta);

    ESP_ERROR_CHECK(web_server_start());
    /* 测试服务失败不影响中继 */
    h2_test_start();

    ESP_LOGI(TAG, "中继已启动：上游 \"%s\" -> 本机 AP \"%s\"，配置页 http://192.168.4.1/",
             s_cfg.sta_ssid, s_cfg.ap_ssid);
}
