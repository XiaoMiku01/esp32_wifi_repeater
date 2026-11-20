#pragma once

#include <stddef.h>

/* ctx 为 NULL 表示广播；非 NULL 时由调用方解释（web_server 传 fd） */
typedef void (*web_log_sink_t)(void *ctx, const char *data, size_t len);

void web_log_set_sink(web_log_sink_t sink);
/* 把历史日志按顺序交给 one() 发送，期间持锁，不会与实时推送交错 */
void web_log_send_history(web_log_sink_t one, void *ctx);
