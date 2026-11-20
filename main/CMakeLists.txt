idf_component_register(SRCS "wifi_repeater.c" "repeater_config.c" "web_log.c" "web_server.c" "dns_relay.c"
                    PRIV_REQUIRES esp_wifi esp_netif nvs_flash esp_psram esp_http_server esp_timer esp_ringbuf
                    INCLUDE_DIRS "."
                    EMBED_TXTFILES "www/index.html")
