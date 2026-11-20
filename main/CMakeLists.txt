# HTTP/2 站点证书：放在 main/certs2/（不入库），构建时嵌入固件
set(H2_CERT "certs2/www.aabbcc.com.fullchain.pem")
set(H2_KEY  "certs2/www.aabbcc.com.key")
foreach(f ${H2_CERT} ${H2_KEY})
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/${f}")
        message(FATAL_ERROR "缺少证书文件 main/${f}")
    endif()
endforeach()

idf_component_register(SRCS "wifi_repeater.c" "repeater_config.c" "web_log.c" "web_server.c"
                            "dns_relay.c" "h2_test.c" "h2_routes.c" "h2_site.c" "monitor.c"
                    PRIV_REQUIRES esp_wifi esp_netif nvs_flash esp_psram esp_http_server esp_timer
                                  esp_ringbuf h2_server mbedtls lwip esp_hw_support
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "www/index.html" "www/monitor.html" "${H2_CERT}" "${H2_KEY}")

# 流量记录：把转发钩子注入 lwip 组件（只影响 lwip 自身的编译单元）
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
    target_compile_definitions(${lwip_lib} PRIVATE "ESP_IDF_LWIP_HOOK_FILENAME=\"monitor_lwip_hook.h\"")
    target_include_directories(${lwip_lib} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/lwip_hook")
endif()
