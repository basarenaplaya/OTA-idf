/* Advanced HTTPS OTA example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "protocol_examples_common.h"

#include "secrets/config.h"
#include "cJSON.h"
#include <stdlib.h>
#include "esp_sntp.h"
#include <time.h>

/* mbedTLS for RSA signature verification and AES decryption */
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>

#if CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
#include "esp_efuse.h"
#endif

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif

#if CONFIG_BT_BLE_ENABLED || CONFIG_BT_NIMBLE_ENABLED
#include "ble_api.h"
#endif

static const char *TAG = "firmware";
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

static void obtain_time(void)
{
    ESP_LOGI(TAG, "Initializing SNTP");
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();
    
    // Wait for time to be set
    int retry = 0;
    const int max_retries = 20;
    time_t now = time(NULL);
    struct tm timeinfo = {0};
    localtime_r(&now, &timeinfo);
    
    while (timeinfo.tm_year < (2023 - 1900) && ++retry < max_retries) {
        ESP_LOGI(TAG, "Waiting for system time to be set (%d/%d)...", retry, max_retries);
        vTaskDelay(pdMS_TO_TICKS(1000));
        now = time(NULL);
        localtime_r(&now, &timeinfo);
    }
    
    ESP_LOGI(TAG, "System time is set to: %s", asctime(&timeinfo));
}

#ifdef CONFIG_EXAMPLE_ENABLE_OTA_RESUMPTION

#define NVS_NAMESPACE_OTA_RESUMPTION  "ota_resumption"
#define NVS_KEY_OTA_WR_LENGTH  "nvs_ota_wr_len"
#define NVS_KEY_SAVED_URL  "nvs_ota_url"

static esp_err_t example_ota_res_get_ota_written_len_from_nvs(const nvs_handle_t nvs_ota_resumption_handle, const char *client_ota_url, uint32_t *nvs_ota_wr_len)
{
    esp_err_t err;
    char saved_url[OTA_URL_SIZE] = {0};
    size_t url_len = sizeof(saved_url);

    *nvs_ota_wr_len = 0;

    // Retrieve the saved URL from NVS
    err = nvs_get_str(nvs_ota_resumption_handle, NVS_KEY_SAVED_URL, saved_url, &url_len);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGD(TAG, "Saved URL is not initialized yet!");
        return err;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error reading saved URL (%s)", esp_err_to_name(err));
        return err;
    }

    // Compare the current URL with the saved URL
    if (strcmp(client_ota_url, saved_url) != 0) {
        ESP_LOGD(TAG, "URLs do not match. Restarting OTA from beginning.");
        return ESP_ERR_INVALID_STATE;
    }

    // Fetch the saved write length only if URLs match
    uint16_t saved_wr_len_kb = 0;
    err = nvs_get_u16(nvs_ota_resumption_handle, NVS_KEY_OTA_WR_LENGTH, &saved_wr_len_kb);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGD(TAG, "The write length is not initialized yet!");
        *nvs_ota_wr_len = 0;
        return err;
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "Error reading OTA write length (%s)", esp_err_to_name(err));
        return err;
    }

    // Convert the saved value back to bytes
    *nvs_ota_wr_len = saved_wr_len_kb * 1024;

    return ESP_OK;
}

static esp_err_t example_ota_res_save_ota_cfg_to_nvs(const nvs_handle_t nvs_ota_resumption_handle, int nvs_ota_wr_len,  const char *client_ota_url)
{
    // Convert the write length to kilobytes to optimize NVS space utilization
    uint16_t wr_len_kb = nvs_ota_wr_len / 1024;

    // Save the current OTA write length to NVS
    ESP_RETURN_ON_ERROR(nvs_set_u16(nvs_ota_resumption_handle, NVS_KEY_OTA_WR_LENGTH, wr_len_kb), TAG, "Failed to set OTA write length");

    // Save the URL only if the OTA write length is non-zero and the URL is not already saved
    if (nvs_ota_wr_len) {
        char saved_url[OTA_URL_SIZE] = {0};
        size_t url_len = sizeof(saved_url);

        esp_err_t err = nvs_get_str(nvs_ota_resumption_handle, NVS_KEY_SAVED_URL, saved_url, &url_len);
        if (err == ESP_ERR_NVS_NOT_FOUND || strcmp(saved_url, client_ota_url) != 0) {
            // URL not saved or changed; save it now
            ESP_RETURN_ON_ERROR(nvs_set_str(nvs_ota_resumption_handle, NVS_KEY_SAVED_URL, client_ota_url), TAG, "Failed to set URL in NVS");
        } else if (err != ESP_OK) {
            ESP_LOGE(TAG, "Error reading OTA URL");
            return err;
        }
    }

    ESP_RETURN_ON_ERROR(nvs_commit(nvs_ota_resumption_handle), TAG, "Failed to commit NVS");
    ESP_LOGD(TAG, "Saving state in NVS. Total image written so far : %d KB", wr_len_kb);
    return ESP_OK;
}

static esp_err_t example_ota_res_cleanup_ota_cfg_from_nvs(nvs_handle_t handle) {
    esp_err_t ret;

    // Erase all keys in the NVS handle and commit changes
    ESP_GOTO_ON_ERROR(nvs_erase_all(handle), err, TAG, "Error in erasing NVS");
    ESP_GOTO_ON_ERROR(nvs_commit(handle), err, TAG, "Error in committing NVS");
    ret = ESP_OK;
err:
    nvs_close(handle);
    return ret;
}

#endif

/* Event handler for catching system events */
static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    if (event_base == ESP_HTTPS_OTA_EVENT) {
        switch (event_id) {
            case ESP_HTTPS_OTA_START:
                ESP_LOGI(TAG, "OTA started");
                break;
            case ESP_HTTPS_OTA_CONNECTED:
                ESP_LOGI(TAG, "Connected to server");
                break;
            case ESP_HTTPS_OTA_GET_IMG_DESC:
                ESP_LOGI(TAG, "Reading Image Description");
                break;
            case ESP_HTTPS_OTA_VERIFY_CHIP_ID:
                ESP_LOGI(TAG, "Verifying chip id of new image: %d", *(esp_chip_id_t *)event_data);
                break;
            case ESP_HTTPS_OTA_VERIFY_CHIP_REVISION:
                ESP_LOGI(TAG, "Verifying chip revision of new image: %d", *(esp_chip_id_t *)event_data);
                break;
            case ESP_HTTPS_OTA_DECRYPT_CB:
                ESP_LOGI(TAG, "Callback to decrypt function");
                break;
            case ESP_HTTPS_OTA_WRITE_FLASH:
                ESP_LOGD(TAG, "Writing to flash: %d written", *(int *)event_data);
                break;
            case ESP_HTTPS_OTA_UPDATE_BOOT_PARTITION:
                ESP_LOGI(TAG, "Boot partition updated. Next Partition: %d", *(esp_partition_subtype_t *)event_data);
                break;
            case ESP_HTTPS_OTA_FINISH:
                ESP_LOGI(TAG, "OTA finish");
                break;
            case ESP_HTTPS_OTA_ABORT:
                ESP_LOGI(TAG, "OTA abort");
                break;
        }
    }
}

static esp_err_t validate_image_header(esp_app_desc_t *new_app_info)
{
    if (new_app_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_app_desc_t running_app_info;
    if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
        ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
    }

#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
    if (memcmp(new_app_info->version, running_app_info.version, sizeof(new_app_info->version)) == 0) {
        ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
        return ESP_FAIL;
    }
#endif

#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    /**
     * Secure version check from firmware image header prevents subsequent download and flash write of
     * entire firmware image. However this is optional because it is also taken care in API
     * esp_https_ota_finish at the end of OTA update procedure.
     */
    const uint32_t hw_sec_version = esp_efuse_read_secure_version();
    if (new_app_info->secure_version < hw_sec_version) {
        ESP_LOGW(TAG, "New firmware security version is less than eFuse programmed, %"PRIu32" < %"PRIu32, new_app_info->secure_version, hw_sec_version);
        return ESP_FAIL;
    }
#endif

    return ESP_OK;
}

static esp_err_t _http_client_init_cb(esp_http_client_handle_t http_client)
{
    esp_err_t err = ESP_OK;
    /* Uncomment to add custom headers to HTTP request */
    // err = esp_http_client_set_header(http_client, "Custom-Header", "Value");
    return err;
}

// Forward declaration for our new main logic function
void checkForUpdates(void);

// Helper function for version comparison
int compareVersionStrings(const char* v1, const char* v2) {
    long part1, part2;
    while (*v1 && *v2) {
        part1 = strtol(v1, (char**)&v1, 10);
        part2 = strtol(v2, (char**)&v2, 10);
        if (part1 > part2) return 1;
        if (part1 < part2) return -1;
        if (*v1 == '.') v1++;
        if (*v2 == '.') v2++;
    }
    if (*v1) return 1;
    if (*v2) return -1;
    return 0;
}

/**
 * Download firmware signature from server
 * Returns pointer to dynamically allocated signature buffer (must be freed by caller)
 * Returns NULL on failure
 */
static uint8_t* download_signature(const char* signature_url, size_t* out_sig_len) {
    if (!signature_url || !out_sig_len) {
        ESP_LOGE(TAG, "Invalid signature URL or output buffer");
        return NULL;
    }

    esp_http_client_config_t config = {
        .url = signature_url,
        .cert_pem = GITHUB_ROOT_CA_CERT,
        .timeout_ms = 10000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client for signature");
        return NULL;
    }

    if (esp_http_client_open(client, 0) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection for signature");
        esp_http_client_cleanup(client);
        return NULL;
    }

    int content_length = esp_http_client_fetch_headers(client);
    if (content_length <= 0) {
        ESP_LOGE(TAG, "Signature fetch returned no content");
        esp_http_client_cleanup(client);
        return NULL;
    }

    /* Allocate buffer for signature (typically 256 bytes for 2048-bit RSA) */
    uint8_t* signature_buffer = malloc(content_length);
    if (!signature_buffer) {
        ESP_LOGE(TAG, "Failed to allocate memory for signature (size: %d)", content_length);
        esp_http_client_cleanup(client);
        return NULL;
    }

    int read_len = esp_http_client_read(client, (char*)signature_buffer, content_length);
    esp_http_client_cleanup(client);

    if (read_len != content_length) {
        ESP_LOGE(TAG, "Failed to read complete signature. Expected: %d, Got: %d", content_length, read_len);
        free(signature_buffer);
        return NULL;
    }

    *out_sig_len = read_len;
    ESP_LOGI(TAG, "Successfully downloaded signature (%d bytes)", *out_sig_len);
    return signature_buffer;
}

/**
 * Verify encrypted firmware binary with RSA-PSS signature
 * Downloads encrypted firmware, decrypts it on-the-fly, computes hash, and verifies signature
 * Returns ESP_OK if signature is valid, ESP_FAIL otherwise
 */
/**
 * Download encrypted firmware, decrypt, verify signature, and flash to OTA partition
 * All operations done in a single pass to avoid downloading twice
 * Returns ESP_OK if successful, ESP_FAIL otherwise
 */
static esp_err_t download_decrypt_verify_and_flash(const char* firmware_url, const uint8_t* signature, size_t sig_len) {
    if (!firmware_url || !signature || sig_len == 0) {
        ESP_LOGE(TAG, "Invalid parameters");
        return ESP_FAIL;
    }

    esp_err_t err;
    esp_ota_handle_t ota_handle = 0;
    const esp_partition_t *update_partition = NULL;
    
    /* Get next OTA partition */
    update_partition = esp_ota_get_next_update_partition(NULL);
    if (update_partition == NULL) {
        ESP_LOGE(TAG, "Failed to find OTA partition");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%"PRIx32,
             update_partition->subtype, update_partition->address);

    /* Initialize RSA context for signature verification */
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    
    int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)PUBLIC_KEY, strlen(PUBLIC_KEY) + 1);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to parse public key (mbedtls error: %d)", ret);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    /* Initialize AES decryption context */
    mbedtls_aes_context aes_ctx;
    mbedtls_aes_init(&aes_ctx);
    
    ret = mbedtls_aes_setkey_dec(&aes_ctx, AES_KEY, 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "Failed to set AES key (mbedtls error: %d)", ret);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    /* Initialize SHA256 for hash computation */
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    /* Open HTTP connection */
    esp_http_client_config_t config = {
        .url = firmware_url,
        .cert_pem = GITHUB_ROOT_CA_CERT,
        .timeout_ms = 20000,
    };
    
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client");
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    if (esp_http_client_open(client, 0) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection");
        esp_http_client_cleanup(client);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    int firmware_size = esp_http_client_fetch_headers(client);
    if (firmware_size <= 0) {
        ESP_LOGE(TAG, "Invalid firmware size");
        esp_http_client_cleanup(client);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    /* Begin OTA update */
    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Downloading, decrypting, and flashing firmware (%d bytes)...", firmware_size);

    /* Download, decrypt, hash, and write to flash in chunks */
    #define CHUNK_SIZE 2048
    uint8_t *encrypted_buffer = malloc(CHUNK_SIZE);
    uint8_t *decrypted_buffer = malloc(CHUNK_SIZE);
    uint8_t *previous_buffer = malloc(CHUNK_SIZE);  // Store previous chunk to handle padding
    
    if (!encrypted_buffer || !decrypted_buffer || !previous_buffer) {
        ESP_LOGE(TAG, "Failed to allocate memory for buffers");
        free(encrypted_buffer);
        free(decrypted_buffer);
        free(previous_buffer);
        esp_ota_abort(ota_handle);
        esp_http_client_cleanup(client);
        mbedtls_md_free(&md_ctx);
        mbedtls_aes_free(&aes_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }
    
    /* Initialize IV - will be updated automatically by CBC mode */
    uint8_t iv_working[16];
    memcpy(iv_working, AES_IV, 16);
    
    int total_read = 0;
    int read_len;
    int prev_len = 0;
    bool ota_failed = false;
    bool is_first_chunk = true;

    while (total_read < firmware_size && !ota_failed) {
        int to_read = (firmware_size - total_read < CHUNK_SIZE) ? 
                      (firmware_size - total_read) : CHUNK_SIZE;
        
        /* Ensure block alignment for AES */
        to_read = (to_read / 16) * 16;
        if (to_read == 0 && total_read < firmware_size) {
            to_read = 16;
        }

        read_len = esp_http_client_read(client, (char*)encrypted_buffer, to_read);
        if (read_len <= 0) {
            ESP_LOGE(TAG, "Error reading firmware chunk");
            ota_failed = true;
            break;
        }

        /* Decrypt chunk - IV is automatically updated for next block in CBC mode */
        ret = mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_DECRYPT, read_len,
                                     iv_working, encrypted_buffer, decrypted_buffer);
        if (ret != 0) {
            ESP_LOGE(TAG, "AES decryption failed (mbedtls error: %d)", ret);
            ota_failed = true;
            break;
        }

        /* Debug: Log first decrypted bytes on first chunk */
        if (is_first_chunk) {
            ESP_LOGI(TAG, "First decrypted bytes: %02x %02x %02x %02x %02x %02x %02x %02x",
                     decrypted_buffer[0], decrypted_buffer[1], decrypted_buffer[2], decrypted_buffer[3],
                     decrypted_buffer[4], decrypted_buffer[5], decrypted_buffer[6], decrypted_buffer[7]);
            is_first_chunk = false;
        }

        /* Process previous chunk if we have one (delayed write to handle padding) */
        if (prev_len > 0) {
            /* Write previous chunk to hash and flash */
            mbedtls_md_update(&md_ctx, previous_buffer, prev_len);
            err = esp_ota_write(ota_handle, previous_buffer, prev_len);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write failed (%s)", esp_err_to_name(err));
                ota_failed = true;
                break;
            }
        }

        /* Store current decrypted chunk as previous for next iteration */
        memcpy(previous_buffer, decrypted_buffer, read_len);
        prev_len = read_len;

        total_read += read_len;
    }

    /* Handle the last chunk - remove PKCS7 padding */
    if (!ota_failed && prev_len > 0) {
        /* Get padding length from last byte (PKCS7 padding) */
        uint8_t padding_len = previous_buffer[prev_len - 1];
        
        /* Validate padding length (should be 1-16 for AES) */
        if (padding_len > 0 && padding_len <= 16 && padding_len <= prev_len) {
            /* Verify all padding bytes are correct */
            bool valid_padding = true;
            for (int i = prev_len - padding_len; i < prev_len; i++) {
                if (previous_buffer[i] != padding_len) {
                    valid_padding = false;
                    break;
                }
            }
            
            if (valid_padding) {
                prev_len -= padding_len;
                ESP_LOGI(TAG, "Removed %d bytes of PKCS7 padding", padding_len);
            }
        }
        
        /* Write final chunk without padding */
        if (prev_len > 0) {
            mbedtls_md_update(&md_ctx, previous_buffer, prev_len);
            err = esp_ota_write(ota_handle, previous_buffer, prev_len);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "esp_ota_write failed on final chunk (%s)", esp_err_to_name(err));
                ota_failed = true;
            }
        }
    }

    esp_http_client_cleanup(client);
    mbedtls_aes_free(&aes_ctx);
    free(encrypted_buffer);
    free(decrypted_buffer);
    free(previous_buffer);

    if (ota_failed) {
        esp_ota_abort(ota_handle);
        mbedtls_md_free(&md_ctx);
        mbedtls_pk_free(&pk);
        return ESP_FAIL;
    }

    /* Finalize hash and verify signature */
    uint8_t hash[32];
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    ESP_LOGI(TAG, "Verifying signature of decrypted firmware...");
    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 32, signature, sig_len);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        ESP_LOGE(TAG, "✗ Signature verification FAILED (mbedtls error: %d)", ret);
        esp_ota_abort(ota_handle);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "✓ Signature verification PASSED");

    /* Finalize OTA update */
    err = esp_ota_end(ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_end failed (%s)", esp_err_to_name(err));
        return ESP_FAIL;
    }

    /* Set boot partition to new firmware */
    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)", esp_err_to_name(err));
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "OTA update successful!");
    return ESP_OK;
}

// Core update-checking function: fetch manifest, parse and trigger OTA if newer
void checkForUpdates(void) {
    esp_http_client_config_t config = {};
    config.url = MANIFEST_URL;
    config.cert_pem = GITHUB_ROOT_CA_CERT;
    config.timeout_ms = 10000;

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialize HTTP client for manifest");
        return;
    }

    char buffer[1024] = {0};
    if (esp_http_client_open(client, 0) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to open HTTP connection for manifest");
        esp_http_client_cleanup(client);
        return;
    }
    int content_length = esp_http_client_fetch_headers(client);
    if (content_length <= 0) {
        ESP_LOGE(TAG, "Manifest fetch returned no content");
        esp_http_client_cleanup(client);
        return;
    }
    int read_len = esp_http_client_read(client, buffer, sizeof(buffer)-1);
    if (read_len <= 0) {
        ESP_LOGE(TAG, "Failed to read manifest content");
        esp_http_client_cleanup(client);
        return;
    }
    esp_http_client_cleanup(client);
    buffer[read_len] = '\0';

    cJSON *json = cJSON_Parse(buffer);
    if (json == NULL) {
        ESP_LOGE(TAG, "Failed to parse manifest JSON."); return;
    }

    const cJSON *version_item = cJSON_GetObjectItem(json, "version");
    const cJSON *file_url_item = cJSON_GetObjectItem(json, "file_url");
    const cJSON *signature_url_item = cJSON_GetObjectItem(json, "signature_url");

    if (cJSON_IsString(version_item) && cJSON_IsString(file_url_item) && cJSON_IsString(signature_url_item)) {
        char* newVersion = version_item->valuestring;
        if(newVersion[0] == 'v') newVersion++;

        ESP_LOGI(TAG, "Update Check: Current=%s, Available=%s", FIRMWARE_VERSION, newVersion);
        if (compareVersionStrings(newVersion, FIRMWARE_VERSION) > 0) {
            ESP_LOGI(TAG, "New version found. Downloading signature...");

            /* Download signature */
            size_t signature_len = 0;
            uint8_t* signature = download_signature(signature_url_item->valuestring, &signature_len);
            
            if (signature == NULL) {
                ESP_LOGE(TAG, "Failed to download firmware signature");
                cJSON_Delete(json);
                return;
            }

            ESP_LOGI(TAG, "Starting secure OTA: decrypt → verify → flash...");

            /* Single-pass: download encrypted firmware, decrypt, verify, and flash */
            esp_err_t result = download_decrypt_verify_and_flash(file_url_item->valuestring, signature, signature_len);
            free(signature);

            if (result == ESP_OK) {
                ESP_LOGI(TAG, "✓ Secure OTA complete! Rebooting in 2 seconds...");
                vTaskDelay(pdMS_TO_TICKS(2000));
                esp_restart();
            } else {
                ESP_LOGE(TAG, "✗ Secure OTA failed - staying on current firmware");
            }
        } else {
            ESP_LOGI(TAG, "No new version available.");
        }
    } else {
        ESP_LOGE(TAG, "Manifest is missing required fields (version, file_url, signature_url).");
    }
    cJSON_Delete(json);
}

void advanced_ota_example_task(void *pvParameter)
{
    ESP_LOGI(TAG, "Starting custom OTA task with manifest check...");
    ESP_LOGI(TAG, "Current firmware version: %s", FIRMWARE_VERSION);

    // The example's app_main already calls example_connect() which blocks until
    // the network interface is up. Proceed to an initial check immediately.
    checkForUpdates(); // Perform an initial check

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(UPDATE_CHECK_INTERVAL_MS));
        ESP_LOGI(TAG, "--------------------");
        ESP_LOGI(TAG, "Current firmware version: %s", FIRMWARE_VERSION);
        ESP_LOGI(TAG, "Checking for a new firmware version...");
        checkForUpdates();
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "OTA example app_main start");
    // Initialize NVS.
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // 1.OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // 2.NVS partition contains data in new format and cannot be recognized by this version of code.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK( err );

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(esp_event_handler_register(ESP_HTTPS_OTA_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
    */
    ESP_ERROR_CHECK(example_connect());
    
    // Set system time via SNTP before any HTTPS operations
    obtain_time();

#if defined(CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE)
    /**
     * We are treating successful WiFi connection as a checkpoint to cancel rollback
     * process and mark newly updated firmware image as active. For production cases,
     * please tune the checkpoint behavior per end application requirement.
     */
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            if (esp_ota_mark_app_valid_cancel_rollback() == ESP_OK) {
                ESP_LOGI(TAG, "App is valid, rollback cancelled successfully");
            } else {
                ESP_LOGE(TAG, "Failed to cancel rollback");
            }
        }
    }
#endif

#if CONFIG_EXAMPLE_CONNECT_WIFI
#if !CONFIG_BT_ENABLED
    /* Ensure to disable any WiFi power save mode, this allows best throughput
     * and hence timings for overall OTA operation.
     */
    esp_wifi_set_ps(WIFI_PS_NONE);
#else
    /* WIFI_PS_MIN_MODEM is the default mode for WiFi Power saving. When both
     * WiFi and Bluetooth are running, WiFI modem has to go down, hence we
     * need WIFI_PS_MIN_MODEM. And as WiFi modem goes down, OTA download time
     * increases.
     */
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
#endif // CONFIG_BT_ENABLED
#endif // CONFIG_EXAMPLE_CONNECT_WIFI

#if CONFIG_BT_CONTROLLER_ENABLED && (CONFIG_BT_BLE_ENABLED || CONFIG_BT_NIMBLE_ENABLED)
    ESP_ERROR_CHECK(esp_ble_helper_init());
#endif

    xTaskCreate(&advanced_ota_example_task, "advanced_ota_example_task", 1024 * 12, NULL, 5, NULL);
}
