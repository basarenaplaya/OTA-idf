idf_component_register(
    SRCS "src/firmware.c"
    INCLUDE_DIRS "include"
    REQUIRES 
        esp_http_client
        esp_https_ota
        mbedtls
        json
        app_update
        nvs_flash
)
