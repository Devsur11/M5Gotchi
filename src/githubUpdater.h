#ifndef GITHUB_UPDATER_H
#define GITHUB_UPDATER_H

#ifdef __cplusplus
extern "C" {
#endif

// Checks for new firmware version and logs details, returns true if update needed
bool check_for_new_firmware_version(bool lite);

// Downloads and applies OTA update if available, returns true if update was successful
bool ota_update_from_url(bool lite);

#ifdef __cplusplus
}
#endif

#endif // GITHUB_UPDATER_H