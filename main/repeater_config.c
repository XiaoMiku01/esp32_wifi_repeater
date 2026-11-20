#include <string.h>
#include "nvs.h"
#include "esp_log.h"
#include "repeater.h"

#define NVS_NS   "repeater"
#define NVS_KEY  "cfg"

static const char *TAG = "cfg";

static void load_defaults(repeater_cfg_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    strlcpy(cfg->sta_ssid, CONFIG_REPEATER_STA_SSID, sizeof(cfg->sta_ssid));
    strlcpy(cfg->sta_pass, CONFIG_REPEATER_STA_PASSWORD, sizeof(cfg->sta_pass));
    strlcpy(cfg->ap_ssid, CONFIG_REPEATER_AP_SSID, sizeof(cfg->ap_ssid));
    strlcpy(cfg->ap_pass, CONFIG_REPEATER_AP_PASSWORD, sizeof(cfg->ap_pass));
    cfg->ap_max_conn = CONFIG_REPEATER_AP_MAX_CONN;
}

void repeater_cfg_load(repeater_cfg_t *cfg)
{
    load_defaults(cfg);

    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) != ESP_OK) {
        ESP_LOGI(TAG, "NVS 无配置，使用 menuconfig 默认值");
        return;
    }
    repeater_cfg_t tmp;
    size_t len = sizeof(tmp);
    esp_err_t err = nvs_get_blob(h, NVS_KEY, &tmp, &len);
    nvs_close(h);

    if (err == ESP_OK && len == sizeof(tmp) && repeater_cfg_validate(&tmp) == NULL) {
        *cfg = tmp;
        ESP_LOGI(TAG, "已从 NVS 加载配置");
    } else {
        ESP_LOGW(TAG, "NVS 配置无效（%s），使用默认值", esp_err_to_name(err));
    }
}

esp_err_t repeater_cfg_save(const repeater_cfg_t *cfg)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(NVS_NS, NVS_READWRITE, &h);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(h, NVS_KEY, cfg, sizeof(*cfg));
    if (err == ESP_OK) {
        err = nvs_commit(h);
    }
    nvs_close(h);
    return err;
}

const char *repeater_cfg_validate(const repeater_cfg_t *cfg)
{
    size_t n;

    n = strnlen(cfg->sta_ssid, sizeof(cfg->sta_ssid));
    if (n == 0 || n > 32) {
        return "上游 SSID 长度需为 1-32";
    }
    if (strnlen(cfg->sta_pass, sizeof(cfg->sta_pass)) > 64) {
        return "上游密码过长";
    }
    n = strnlen(cfg->ap_ssid, sizeof(cfg->ap_ssid));
    if (n == 0 || n > 32) {
        return "AP SSID 长度需为 1-32";
    }
    n = strnlen(cfg->ap_pass, sizeof(cfg->ap_pass));
    if (n != 0 && (n < 8 || n > 63)) {
        return "AP 密码需为 8-63 位，或留空（开放网络）";
    }
    if (cfg->ap_max_conn < 1 || cfg->ap_max_conn > 15) {
        return "AP 最大客户端数需为 1-15";
    }
    return NULL;
}
