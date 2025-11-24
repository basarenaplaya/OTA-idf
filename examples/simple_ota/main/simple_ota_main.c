/**
 * Simple OTA Example
 * 
 * Super simple! Just:
 * 1. Connect to WiFi (configured in sdkconfig: idf.py menuconfig → Example Connection Configuration)
 * 2. Call checkForUpdates() - that's it!
 * 
 * The component handles everything: SNTP, download, decrypt, verify, flash!
 */

#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"

//OTA component
#include "esp_ota_secure.h"

static const char *TAG = "simple_ota";

void app_main(void)
{
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "   Simple Secure OTA Example");
    ESP_LOGI(TAG, "========================================");

    // Initialize NVS
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    // Initialize network interface and event loop (required for WiFi)
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // Connect to WiFi (uses sdkconfig settings)
    ESP_LOGI(TAG, "Connecting to WiFi...");
    ESP_ERROR_CHECK(example_connect());
    ESP_LOGI(TAG, "✓ WiFi connected!");

    // Call the OTA component - it handles SNTP, download, decrypt, verify, flash!
    ESP_LOGI(TAG, "Checking for OTA updates...");
    checkForUpdates();

    // Your app code here
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "   Application Running");
    ESP_LOGI(TAG, "========================================");
    
    while (1) {
        ESP_LOGI(TAG, "App running...");
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}
