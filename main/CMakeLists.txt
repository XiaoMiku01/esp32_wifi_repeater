# HTTP/2 测试接口用的自签证书：不入库，首次配置时用 openssl 生成到 main/certs/
set(H2_CERT_DIR "${CMAKE_CURRENT_LIST_DIR}/certs")
if(NOT EXISTS "${H2_CERT_DIR}/h2_cert.pem" OR NOT EXISTS "${H2_CERT_DIR}/h2_key.pem")
    find_program(OPENSSL_BIN openssl REQUIRED)
    file(MAKE_DIRECTORY "${H2_CERT_DIR}")
    execute_process(
        COMMAND "${OPENSSL_BIN}" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1
                -nodes -days 3650 -subj "/CN=esp32-repeater"
                -addext "subjectAltName=IP:192.168.4.1"
                -keyout "${H2_CERT_DIR}/h2_key.pem" -out "${H2_CERT_DIR}/h2_cert.pem"
        RESULT_VARIABLE H2_CERT_RES OUTPUT_QUIET ERROR_QUIET)
    if(NOT H2_CERT_RES EQUAL 0)
        message(FATAL_ERROR "生成 HTTP/2 自签证书失败，请检查 openssl")
    endif()
endif()

idf_component_register(SRCS "wifi_repeater.c" "repeater_config.c" "web_log.c" "web_server.c"
                            "dns_relay.c" "h2_test.c"
                    PRIV_REQUIRES esp_wifi esp_netif nvs_flash esp_psram esp_http_server esp_timer
                                  esp_ringbuf h2_server
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "www/index.html" "certs/h2_cert.pem" "certs/h2_key.pem")
