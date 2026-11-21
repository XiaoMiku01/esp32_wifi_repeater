/*
 * 日志转发：接管 esp_log 的 vprintf 输出，
 * 一份照常走串口，一份写入环形缓冲，由后台任务推送给所有 WebSocket 客户端，
 * 并保留最近一段历史，新连接的页面先收到历史日志。
 */
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/ringbuf.h"
#include "esp_log.h"
#include "web_log_priv.h"
#include "repeater.h"

#define RB_SIZE       8192
#define HISTORY_SIZE  8192
#define CHUNK_MAX     1024
#define LINE_MAX_LEN  256

static RingbufHandle_t s_rb;
static vprintf_like_t s_orig_vprintf;

static char s_hist[HISTORY_SIZE];
static size_t s_hist_head;      /* 下一个写入位置 */
static bool s_hist_full;
static SemaphoreHandle_t s_lock;

static web_log_sink_t s_sink;   /* 由 web_server 注册：广播给所有 WS 客户端 */

static int log_vprintf(const char *fmt, va_list ap)
{
    char line[LINE_MAX_LEN];
    va_list ap2;
    va_copy(ap2, ap);
    int n = vsnprintf(line, sizeof(line), fmt, ap2);
    va_end(ap2);
    /* 原输出为默认的 vprintf 且这一行没被截断时，直接写出已格式化的内容，不再格式化第二遍 */
    bool reuse = s_orig_vprintf == vprintf && n >= 0 && n < (int)sizeof(line);
    if (n > 0) {
        /* 不阻塞：缓冲满时丢弃 */
        if (n >= (int)sizeof(line)) {
            /* 超长行截断，补回换行，避免和下一行粘连 */
            char last = line[sizeof(line) - 2];
            line[sizeof(line) - 2] = '\n';
            xRingbufferSend(s_rb, line, sizeof(line) - 1, 0);
            line[sizeof(line) - 2] = last;
        } else {
            xRingbufferSend(s_rb, line, n, 0);
        }
    }
    if (reuse) {
        return n ? (int)fwrite(line, 1, n, stdout) : 0;
    }
    return s_orig_vprintf(fmt, ap);
}

static void hist_append(const char *data, size_t len)
{
    if (len >= HISTORY_SIZE) {              /* 只保留最后 HISTORY_SIZE 字节 */
        data += len - HISTORY_SIZE;
        len = HISTORY_SIZE;
    }
    size_t first = HISTORY_SIZE - s_hist_head;
    if (first > len) first = len;
    memcpy(s_hist + s_hist_head, data, first);
    memcpy(s_hist, data + first, len - first);
    s_hist_head += len;
    if (s_hist_head >= HISTORY_SIZE) {
        s_hist_head -= HISTORY_SIZE;
        s_hist_full = true;
    }
}

void web_log_send_history(web_log_sink_t one, void *ctx)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    if (s_hist_full) {
        one(ctx, s_hist + s_hist_head, HISTORY_SIZE - s_hist_head);
    }
    if (s_hist_head) {
        one(ctx, s_hist, s_hist_head);
    }
    xSemaphoreGive(s_lock);
}

void web_log_set_sink(web_log_sink_t sink)
{
    s_sink = sink;
}

static void log_push_task(void *arg)
{
    static char chunk[CHUNK_MAX];
    for (;;) {
        size_t total = 0, len;
        /* 第一段阻塞等待，之后把已有数据尽量攒成一块 */
        TickType_t wait = portMAX_DELAY;
        while (total < CHUNK_MAX) {
            char *p = xRingbufferReceiveUpTo(s_rb, &len, wait, CHUNK_MAX - total);
            if (!p) {
                break;
            }
            memcpy(chunk + total, p, len);
            total += len;
            vRingbufferReturnItem(s_rb, p);
            wait = pdMS_TO_TICKS(20);
        }
        if (total == 0) {
            continue;
        }
        /* 持锁保证新客户端的“历史 + 实时”顺序不乱 */
        xSemaphoreTake(s_lock, portMAX_DELAY);
        hist_append(chunk, total);
        if (s_sink) {
            s_sink(NULL, chunk, total);
        }
        xSemaphoreGive(s_lock);
    }
}

void web_log_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    s_rb = xRingbufferCreate(RB_SIZE, RINGBUF_TYPE_BYTEBUF);
    configASSERT(s_lock && s_rb);
    xTaskCreate(log_push_task, "log_push", 4096, NULL, 2, NULL);
    s_orig_vprintf = esp_log_set_vprintf(log_vprintf);
}
