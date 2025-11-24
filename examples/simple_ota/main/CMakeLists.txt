idf_component_register(SRCS "simple_ota_main.c"
                    INCLUDE_DIRS "."
                    REQUIRES nvs_flash esp_ota_secure protocol_examples_common esp_netif)
