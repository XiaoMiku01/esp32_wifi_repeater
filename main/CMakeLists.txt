# HTTP/2 站点证书（构建时嵌入固件）：
#   优先使用 main/certs2/ 下的证书（不入库）；
#   缺失时在构建目录生成自签证书（域名取 repeater.h 中的 H2_SITE_DEFAULT_DOMAIN），
#   烧录后可在配置页换成自己的域名和证书。
# 文件名决定嵌入符号名（见 h2_site.c），不要改。
set(H2_CERT_NAME "www.aabbcc.com.fullchain.pem")
set(H2_KEY_NAME  "www.aabbcc.com.key")
set(H2_USER_DIR  "${CMAKE_CURRENT_LIST_DIR}/certs2")
if(EXISTS "${H2_USER_DIR}/${H2_CERT_NAME}" AND EXISTS "${H2_USER_DIR}/${H2_KEY_NAME}")
    set(H2_CERT "${H2_USER_DIR}/${H2_CERT_NAME}")
    set(H2_KEY  "${H2_USER_DIR}/${H2_KEY_NAME}")
else()
    set(H2_GEN_DIR "${CMAKE_BINARY_DIR}/h2_selfsigned")
    set(H2_CERT "${H2_GEN_DIR}/${H2_CERT_NAME}")
    set(H2_KEY  "${H2_GEN_DIR}/${H2_KEY_NAME}")
    if(NOT CMAKE_BUILD_EARLY_EXPANSION)
        if(NOT EXISTS "${H2_CERT}" OR NOT EXISTS "${H2_KEY}")
            file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/repeater.h" _h2_def REGEX "#define[ \t]+H2_SITE_DEFAULT_DOMAIN")
            string(REGEX MATCH "\"([^\"]+)\"" _h2_m "${_h2_def}")
            set(H2_DOMAIN "${CMAKE_MATCH_1}")
            if(NOT H2_DOMAIN)
                message(FATAL_ERROR "无法从 main/repeater.h 读取 H2_SITE_DEFAULT_DOMAIN")
            endif()
            find_program(OPENSSL_BIN openssl)
            if(NOT OPENSSL_BIN)
                message(FATAL_ERROR "未找到 openssl，无法生成自签证书。请安装 openssl，或把证书放到 "
                                    "main/certs2/${H2_CERT_NAME} 和 main/certs2/${H2_KEY_NAME}")
            endif()
            file(MAKE_DIRECTORY "${H2_GEN_DIR}")
            # 用配置文件写 SAN，兼容 OpenSSL 与 macOS 自带的 LibreSSL
            file(WRITE "${H2_GEN_DIR}/openssl.cnf"
                 "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                 "[dn]\nCN = ${H2_DOMAIN}\n"
                 "[ext]\nsubjectAltName = DNS:${H2_DOMAIN}\nbasicConstraints = critical,CA:FALSE\n")
            execute_process(
                COMMAND "${OPENSSL_BIN}" req -x509 -newkey rsa:2048 -nodes -days 3650
                        -config "${H2_GEN_DIR}/openssl.cnf"
                        -keyout "${H2_KEY}" -out "${H2_CERT}"
                RESULT_VARIABLE _h2_res OUTPUT_QUIET ERROR_VARIABLE _h2_err)
            if(NOT _h2_res EQUAL 0)
                message(FATAL_ERROR "生成自签证书失败：${_h2_err}")
            endif()
        endif()
        message(WARNING "未找到 main/certs2/ 下的证书，使用自签证书（浏览器会提示不受信任）：${H2_GEN_DIR}")
    endif()
endif()

idf_component_register(SRCS "wifi_repeater.c" "repeater_config.c" "web_log.c" "web_server.c"
                            "dns_relay.c" "h2_test.c" "h2_routes.c" "h2_site.c" "monitor.c" "dns_filter.c" "led.c"
                    PRIV_REQUIRES esp_wifi esp_netif nvs_flash esp_psram esp_http_server esp_timer
                                  esp_ringbuf h2_server mbedtls lwip esp_hw_support
                                  esp_driver_rmt esp_driver_gpio
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "www/index.html" "www/monitor.html" "${H2_CERT}" "${H2_KEY}")

# 流量记录：把转发钩子注入 lwip 组件（只影响 lwip 自身的编译单元）
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    idf_component_get_property(lwip_lib lwip COMPONENT_LIB)
    target_compile_definitions(${lwip_lib} PRIVATE "ESP_IDF_LWIP_HOOK_FILENAME=\"monitor_lwip_hook.h\"")
    target_include_directories(${lwip_lib} PRIVATE "${CMAKE_CURRENT_LIST_DIR}/lwip_hook")
endif()
