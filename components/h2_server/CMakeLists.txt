idf_component_register(SRCS "h2_server.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp-tls
                    PRIV_REQUIRES lwip mbedtls log)
