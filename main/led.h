#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

/* 板载 WS2812 灯（单颗），RMT 驱动 */
esp_err_t led_init(int gpio);
/* 切换数据引脚（便于确认板子上灯接在哪个引脚），旧引脚复位 */
esp_err_t led_set_gpio(int gpio);
esp_err_t led_set_rgb(uint8_t r, uint8_t g, uint8_t b);
/* 彩色闪烁 ms 毫秒后恢复设置的颜色；闪烁中再调用从现在重新计时 */
esp_err_t led_blink(uint32_t ms);
bool led_blinking(void);
void led_get(int *gpio, uint8_t *r, uint8_t *g, uint8_t *b);
