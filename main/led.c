/*
 * 板载 WS2812 灯：RMT 10 MHz，字节编码器按 GRB 顺序发 24 位
 *   0 码：高 0.3us / 低 0.9us；1 码：高 0.9us / 低 0.3us；空闲低电平 >50us 为复位
 * 闪烁：后台任务按红绿蓝黄青品红白轮流亮 0.3s、灭 0.3s，持续到截止时间后恢复设置的颜色；
 *   闪烁中再次触发从当前时刻重新计时，手动设置颜色会立即结束闪烁
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_timer.h"
#include "driver/rmt_tx.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "led.h"

#define LED_RES_HZ 10000000
#define LED_BLINK_STEP_MS 300

static const char *TAG = "led";
static SemaphoreHandle_t s_lock;
static rmt_channel_handle_t s_chan;
static rmt_encoder_handle_t s_enc;
static int s_gpio = -1;
static uint8_t s_rgb[3];          /* 设置的颜色（闪烁结束后恢复） */
static TaskHandle_t s_blink_task;
static int64_t s_blink_until;      /* esp_timer 微秒，0 表示不闪；持锁读写 */

static const uint8_t k_palette[][3] = {
    {255, 0, 0}, {0, 255, 0}, {0, 0, 255}, {255, 255, 0}, {0, 255, 255}, {255, 0, 255}, {255, 255, 255},
};

static esp_err_t open_channel(int gpio)
{
    rmt_tx_channel_config_t cc = {
        .gpio_num = gpio,
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = LED_RES_HZ,
        .mem_block_symbols = 48,
        .trans_queue_depth = 2,
    };
    esp_err_t err = rmt_new_tx_channel(&cc, &s_chan);
    if (err != ESP_OK) {
        s_chan = NULL;
        return err;
    }
    err = rmt_enable(s_chan);
    if (err != ESP_OK) {
        rmt_del_channel(s_chan);
        s_chan = NULL;
        return err;
    }
    s_gpio = gpio;
    return ESP_OK;
}

static void close_channel(void)
{
    if (s_chan) {
        rmt_disable(s_chan);
        rmt_del_channel(s_chan);
        s_chan = NULL;
    }
    if (s_gpio >= 0) {
        gpio_reset_pin(s_gpio);
        s_gpio = -1;
    }
}

static esp_err_t send_rgb_locked(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_chan) {
        return ESP_ERR_INVALID_STATE;
    }
    uint8_t grb[3] = { g, r, b };
    rmt_transmit_config_t tc = { .loop_count = 0 };
    esp_err_t err = rmt_transmit(s_chan, s_enc, grb, sizeof(grb), &tc);
    if (err == ESP_OK) {
        err = rmt_tx_wait_all_done(s_chan, 100);
    }
    vTaskDelay(pdMS_TO_TICKS(1));   /* 复位间隔 */
    return err;
}

static esp_err_t send_locked(void)
{
    return send_rgb_locked(s_rgb[0], s_rgb[1], s_rgb[2]);
}

static void blink_task(void *arg)
{
    for (;;) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        for (unsigned step = 0;; step++) {
            xSemaphoreTake(s_lock, portMAX_DELAY);
            if (s_blink_until == 0 || esp_timer_get_time() >= s_blink_until) {
                if (s_blink_until != 0) {   /* 到时结束；被手动设置取消时颜色已由设置方发出 */
                    s_blink_until = 0;
                    send_locked();
                }
                xSemaphoreGive(s_lock);
                break;
            }
            if (step % 2 == 0) {
                const uint8_t *c = k_palette[(step / 2) % (sizeof(k_palette) / sizeof(k_palette[0]))];
                send_rgb_locked(c[0], c[1], c[2]);
            } else {
                send_rgb_locked(0, 0, 0);
            }
            xSemaphoreGive(s_lock);
            vTaskDelay(pdMS_TO_TICKS(LED_BLINK_STEP_MS));
        }
    }
}

esp_err_t led_init(int gpio)
{
    s_lock = xSemaphoreCreateMutex();
    rmt_bytes_encoder_config_t ec = {
        .bit0 = { .level0 = 1, .duration0 = 3, .level1 = 0, .duration1 = 9 },
        .bit1 = { .level0 = 1, .duration0 = 9, .level1 = 0, .duration1 = 3 },
        .flags.msb_first = 1,
    };
    esp_err_t err = rmt_new_bytes_encoder(&ec, &s_enc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "创建编码器失败: %s", esp_err_to_name(err));
        return err;
    }
    err = open_channel(gpio);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GPIO%d 打开 RMT 失败: %s", gpio, esp_err_to_name(err));
        return err;
    }
    memset(s_rgb, 0, sizeof(s_rgb));
    send_locked();
    if (xTaskCreate(blink_task, "led_blink", 2560, NULL, 3, &s_blink_task) != pdPASS) {
        ESP_LOGE(TAG, "创建闪烁任务失败");
        s_blink_task = NULL;
    }
    ESP_LOGI(TAG, "WS2812 灯已初始化，GPIO%d", gpio);
    return ESP_OK;
}

esp_err_t led_set_gpio(int gpio)
{
    if (!s_lock) {
        return ESP_ERR_INVALID_STATE;
    }
    if (!GPIO_IS_VALID_OUTPUT_GPIO(gpio)) {
        return ESP_ERR_INVALID_ARG;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t err = ESP_OK;
    if (gpio != s_gpio) {
        if (s_chan) {   /* 旧引脚上的灯先熄灭 */
            uint8_t keep[3];
            memcpy(keep, s_rgb, 3);
            memset(s_rgb, 0, 3);
            send_locked();
            memcpy(s_rgb, keep, 3);
        }
        close_channel();
        err = open_channel(gpio);
        if (err == ESP_OK) {
            if (s_blink_until == 0) {
                err = send_locked();
            }
            ESP_LOGI(TAG, "灯引脚切换到 GPIO%d", gpio);
        }
    }
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t led_set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    if (!s_lock) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_rgb[0] = r;
    s_rgb[1] = g;
    s_rgb[2] = b;
    s_blink_until = 0;
    esp_err_t err = send_locked();
    xSemaphoreGive(s_lock);
    return err;
}

esp_err_t led_blink(uint32_t ms)
{
    if (!s_lock || !s_blink_task || !s_chan) {
        return ESP_ERR_INVALID_STATE;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_blink_until = esp_timer_get_time() + (int64_t)ms * 1000;
    xSemaphoreGive(s_lock);
    xTaskNotifyGive(s_blink_task);
    return ESP_OK;
}

bool led_blinking(void)
{
    if (!s_lock) {
        return false;
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    bool on = s_blink_until != 0;
    xSemaphoreGive(s_lock);
    return on;
}

void led_get(int *gpio, uint8_t *r, uint8_t *g, uint8_t *b)
{
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
    }
    *gpio = s_gpio;
    *r = s_rgb[0];
    *g = s_rgb[1];
    *b = s_rgb[2];
    if (s_lock) {
        xSemaphoreGive(s_lock);
    }
}
