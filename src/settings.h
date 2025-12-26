#pragma once
#include <Arduino.h>
#include <SPI.h>
#include "logger.h"
#include "WiFi.h"
#include <vector>
#include "pwngrid.h"

extern "C" {
  #include "esp_heap_caps.h"
}
void printHeapInfo() {
    logMessage("Free heap: " + String(ESP.getFreeHeap()));
    logMessage("Chip PSRAM: " + String(psramFound() ? "yes" : "no"));
    if (psramFound()) {
        logMessage("Free PSRAM (approx): " + String(ESP.getPsramSize()));
    }
}

bool wifion(){
    WiFi.mode(WIFI_MODE_APSTA);
    WiFi.softAP("pwngrid", NULL, 1, 1, 1);
    return true;
}

#ifndef CURRENT_VERSION
#define CURRENT_VERSION "dev"
#endif
#ifdef LITE_VERSION
#undef ENABLE_COREDUMP_LOGGING
#undef USE_EXPERIMENTAL_APPS
#endif

#define ADDRES_BOOK_FILE "/pwngrid/contacts.conf"
#define KEYS_FILE "/pwngrid/keys"
#define NORMAL_JSON_URL "https://devsur11.github.io/M5Gotchi/firmware/firmware.json"
#define LITE_JSON_URL   "https://devsur11.github.io/M5Gotchi/firmware/lite.json"
#define TEMP_DIR        "/temp"
#define TEMP_JSON_PATH  TEMP_DIR "/update.json"
#define TEMP_BIN_PATH   TEMP_DIR "/update.bin"
#define NEW_CONFIG_FILE "/m5gothi.conf"
#define PERSONALITY_FILE "/personality.conf"
#define UNIT_NAME_MAX 32
#define UNIT_FP_MAX   64
#define SERIAL_LOGS
//#define BYPASS_SD_CHECK
#define SD_CS    12  // G12
#define SD_MOSI  14  // G14
#define SD_SCK   40  // G40
#define SD_MISO  39  // G39
#define LORA_RST  3 // G3
#define MAX_PKT_SIZE 3000
#define ROW_SIZE 40
#define PADDING 10

struct personality{
    uint16_t nap_time;
    uint16_t delay_after_wifi_scan;
    uint16_t delay_after_no_networks_found;
    uint16_t delay_after_attack_fail;
    uint16_t delay_after_successful_attack;
    uint16_t deauth_packets_sent;
    uint16_t delay_after_deauth;
    uint16_t delay_after_picking_target;
    uint16_t delay_before_switching_target;
    uint16_t delay_after_client_found;
    bool sound_on_events;
    bool deauth_on;
    uint16_t handshake_wait_time;
    bool add_to_whitelist_on_success;
    bool add_to_whitelist_on_fail;
    bool activate_sniffer_on_deauth;
    uint16_t client_sniffing_time;
    uint16_t deauth_packet_delay;
    uint16_t delay_after_no_clients_found;
    uint16_t client_discovery_timeout;
    uint16_t gps_fix_timeout;
};

typedef struct {
  char name[UNIT_NAME_MAX];
  char fingerprint[UNIT_FP_MAX];
} unit_msg_t;

bool initVars();
bool saveSettings();
bool initPersonality();
bool savePersonality();

extern String hostname;
extern bool sound;
extern int brightness;
extern uint16_t pwned_ap;
extern SPIClass sdSPI;
struct SavedNetwork {
    String ssid;
    String pass;
    bool connectOnStart;
};
extern std::vector<SavedNetwork> savedNetworks;
extern String savedApSSID;
extern String savedAPPass;
extern bool connectWiFiOnStartup;

bool addSavedNetwork(const String &ssid, const String &pass, bool connectOnStart);
bool removeSavedNetwork(size_t idx);
bool setSavedNetworkConnectOnStart(size_t idx, bool enabled);
void attemptConnectSavedNetworks();
extern String whitelist;
extern bool pwnagothiMode;
extern uint8_t sessionCaptures;
extern bool pwnagothiModeEnabled;
extern String bg_color;
extern String tx_color;
extern bool skip_eapol_check;
extern String wpa_sec_api_key;
extern personality pwnagotchi;
extern bool sd_logging;
extern bool toogle_pwnagothi_with_gpio0;
extern bool lite_mode_wpa_sec_sync_on_startup;
extern String lastPwnedAP;
extern bool stealth_mode;
extern String pwngrid_indentity;
extern bool advertisePwngrid;
extern uint64_t lastTokenRefresh;
extern String wiggle_api_key;
extern bool cardputer_adv;
extern bool limitFeatures;
extern uint64_t hintsDisplayed;
extern bool dev_mode;
extern bool serial_overlay;
extern bool coords_overlay;
extern bool skip_file_manager_checks_in_dev;
extern uint8_t gpsTx;
extern uint8_t gpsRx;
extern bool useCustomGPSPins;
extern bool getLocationAfterPwn;
extern bool checkUpdatesAtNetworkStart;
extern bool auto_mode_and_wardrive;
extern uint lastSessionDeauths;
extern uint lastSessionCaptures;
extern long lastSessionTime;
extern uint8_t lastSessionPeers;
uint16_t tot_happy_epochs;
uint16_t tot_sad_epochs;
extern uint32_t allTimeDeauths;
extern uint32_t allTimeEpochs;
extern uint16_t allTimePeers;
extern long long allSessionTime;
extern uint16_t prev_level;
extern bool randomise_mac_at_boot;
extern bool add_new_units_to_friends;