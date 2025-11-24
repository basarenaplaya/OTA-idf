/**
 * ESP32 Secure OTA Component
 * 
 * Simple component for encrypted OTA updates with RSA signature verification
 * 
 * Prerequisites:
 * - WiFi must be connected before calling checkForUpdates()
 * - System time must be synced (use SNTP) for HTTPS certificate validation
 * - Edit config.h with your keys, manifest URL, and firmware version
 * 
 * Usage:
 *   #include "esp_ota_secure.h"
 * 
 *   void app_main() {
 *       wifi_connect();
 *       sntp_sync_time();
 *       checkForUpdates();  // Check for OTA updates
 *   }
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check for firmware updates from manifest server
 * Downloads manifest, compares versions, and performs OTA if newer version available
 * 
 * Prerequisites:
 * - WiFi must be connected
 * 
 * This function will:
 * 1. Sync system time via SNTP (for HTTPS certificate validation)
 * 2. Download manifest JSON
 * 3. Compare versions
 * 4. Download and verify signature
 * 5. Download encrypted firmware
 * 6. Decrypt and verify on-the-fly
 * 7. Flash to OTA partition
 * 8. Reboot if successful
 */
void checkForUpdates(void);

#ifdef __cplusplus
}
#endif
