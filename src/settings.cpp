#include "settings.h"
#include <vector>
#include "ArduinoJson.h"
#include "SD.h"
#include "logger.h"
#include "pwnagothi.h"
#include "ui.h"
#include "crypto.h"

static String _encryptSensitiveData(uint64_t val, const String &secret) {
    String payload = String(val);
    std::vector<uint8_t> buf((const uint8_t*)payload.c_str(), (const uint8_t*)payload.c_str() + payload.length());
    return pwngrid::crypto::encryptWithPassword(buf, secret);
}

static String _encryptSensitiveData32(uint32_t val, const String &secret) {
    String payload = String(val);
    std::vector<uint8_t> buf((const uint8_t*)payload.c_str(), (const uint8_t*)payload.c_str() + payload.length());
    return pwngrid::crypto::encryptWithPassword(buf, secret);
}

static String _encryptSensitiveData16(uint16_t val, const String &secret) {
    String payload = String(val);
    std::vector<uint8_t> buf((const uint8_t*)payload.c_str(), (const uint8_t*)payload.c_str() + payload.length());
    return pwngrid::crypto::encryptWithPassword(buf, secret);
}

static bool _decryptSensitiveData(const String &ciphertext, const String &secret, uint64_t &result) {
    std::vector<uint8_t> decoded;
    if (!pwngrid::crypto::decryptWithPassword(ciphertext, secret, decoded)) {
        return false;
    }
    String s((const char*)decoded.data(), decoded.size());
    result = s.toInt();
    return true;
}

static bool _decryptSensitiveData32(const String &ciphertext, const String &secret, uint32_t &result) {
    std::vector<uint8_t> decoded;
    if (!pwngrid::crypto::decryptWithPassword(ciphertext, secret, decoded)) {
        return false;
    }
    String s((const char*)decoded.data(), decoded.size());
    result = s.toInt();
    return true;
}

static bool _decryptSensitiveData16(const String &ciphertext, const String &secret, uint16_t &result) {
    std::vector<uint8_t> decoded;
    if (!pwngrid::crypto::decryptWithPassword(ciphertext, secret, decoded)) {
        return false;
    }
    String s((const char*)decoded.data(), decoded.size());
    result = s.toInt();
    return true;
}

// Public API wrappers to maintain compatibility
String encryptStatsValue(uint64_t value, const String &macAddress) {
    return _encryptSensitiveData(value, macAddress);
}

String encryptStatsValue32(uint32_t value, const String &macAddress) {
    return _encryptSensitiveData32(value, macAddress);
}

String encryptStatsValue16(uint16_t value, const String &macAddress) {
    return _encryptSensitiveData16(value, macAddress);
}

bool decryptStatsValue(const String &encrypted, const String &macAddress, uint64_t &outValue) {
    return _decryptSensitiveData(encrypted, macAddress, outValue);
}

bool decryptStatsValue32(const String &encrypted, const String &macAddress, uint32_t &outValue) {
    return _decryptSensitiveData32(encrypted, macAddress, outValue);
}

bool decryptStatsValue16(const String &encrypted, const String &macAddress, uint16_t &outValue) {
    return _decryptSensitiveData16(encrypted, macAddress, outValue);
}

String hostname = "M5Gotchi";
bool sound = false;
int brightness = 150;
bool autoDimEnabled = true;
uint16_t autoDimTimeout = 60000;  // 60 seconds
uint8_t autoDimMinBrightness = 10;
SPIClass sdSPI;
String savedApSSID;
String savedAPPass;
std::vector<SavedNetwork> savedNetworks;
bool connectWiFiOnStartup = true;
String whitelist;
File FConf;
bool pwnagothiMode = false;
uint8_t sessionCaptures;
bool pwnagothiModeEnabled = false;
String bg_color = "#ffffffff";
String tx_color = "#00000000";
bool skip_eapol_check = false;
String wpa_sec_api_key = "";
bool lite_mode_wpa_sec_sync_on_startup = false;
bool sync_pwned_on_boot = false;
bool sd_logging = false;
bool toogle_pwnagothi_with_gpio0 = false;
String lastPwnedAP = "";
bool stealth_mode = false;
String pwngrid_indentity;
bool advertisePwngrid = true;
uint64_t lastTokenRefresh;
String wiggle_api_key = "";
bool cardputer_adv = false;
bool limitFeatures = false;
bool checkUpdatesAtNetworkStart = true;
uint8_t gpsTx;
uint8_t gpsRx;
bool useCustomGPSPins = false;
uint32_t gpsBaudRate = 115200;
bool getLocationAfterPwn = false;
bool auto_mode_and_wardrive = false;
uint lastSessionDeauths = 0;
uint lastSessionCaptures = 0;
long lastSessionTime = 0;
uint8_t lastSessionPeers = 0;
uint32_t allTimeDeauths = 0;
uint32_t allTimeEpochs = 0;
uint16_t allTimePeers = 0;
long long allSessionTime = 0;
uint16_t prev_level = 0;
uint16_t pwned_ap;
bool randomise_mac_at_boot = true;
bool add_new_units_to_friends = false;
bool check_inbox_at_startup = false;
String originalMacAddress;

// Keep track of which hints have been displayed using bitmask
// Each bit represents a different hint
// 0b1 - not M5Burner version hint
// 0b10 - welcome hint
// 0b100 - new version available hint
// (1>>4) - manual mode hint
// (1>>5) - pwnagothi whitelist hint
// (1>>6) - stats legend hint
// (1>>7) - pwngrid enrol hint
// (1>>8) - wardriving mode hint
// (1>>9) - pwngrid messenger hint
// (1>>10) - pwngrid enrol time hint
// (1>>11) - pwngrid enrol restart hint
// (1>>12) - wpa sec api key hint
// (1>>13) - oobe
// (1>>14) - log tool hint
// (1>>15) - auto mode variations hint
// (1>>16) - gps pinout hint
// (1>>17) - PMKID grabber hint
// (1>>18) - donate hint
// (1>>19) - inbox at boot hint
uint64_t hintsDisplayed = 0b0;

// Developer flags
bool dev_mode = false;
bool serial_overlay = false;
bool coords_overlay = false;
bool skip_file_manager_checks_in_dev = false;

personality pwnagotchi = {
    5000,      // nap_time
    100,    // delay_after_wifi_scan
    5000,   // delay_after_no_networks_found
    1000,   // delay_after_attack_fail
    5000,   // delay_after_successful_attack
    150,     // deauth_packets_sent
    50,    // delay_after_deauth
    50,    // delay_after_picking_target
    1000,   // delay_before_switching_target
    100,  // delay_after_client_found
    true,   // sound_on_events
    true,   // deauth_on
    5000,  // handshake_wait_time
    true,   // add_to_whitelist_on_success
    false,  // add_to_whitelist_on_fail
    true,   // activate_sniffer_on_deauth
    0,  // client_sniffing_time  - not used in code
    150,    // deauth_packet_delay
    3000,   // delay_after_no_clients_found
    15000,   // client_discovery_timeout
    5000    // gps_fix_timeout
};

n_personality n_pwnagotchi_personality = {
    15000,   // eapol_timeout (ms) - time to wait for handshake
    50,     // deauth_packets_count - number of deauth packets to send
    50,     // deauth_packet_interval (ms) - delay between packets
    2000,   // pmkid_attack_timeout (ms) - time to wait for PMKID response
    1000,    // delay_between_attacks (ms) - delay before attacking next AP
    true,    // sound_on_handshake - beep when handshake captured
    true,    // sound_on_pmkid - beep when PMKID captured
    -75,     // rssi_threshold (dBm) - minimum RSSI to attack (-100 to 0)
    false,   // enable_wardriving - enable GPS logging during attacks
    5000,    // gps_timeout_ms - timeout for GPS fix
    100,     // wardrive_scan_interval_ms - default ms between wardrive cycles
    false     // enable_pmkid_attack - enable PMKID attack
};

bool initPersonality(){
    #ifdef USE_LITTLEFS
    if (!FSYS.begin()) {
        logMessage("LittleFS init failed");
        return false;
    }
    #else
    if (!FSYS.begin(SD_CS, sdSPI, 1000000)) {
        logMessage("SD card init failed");
        return false;
    }
    #endif
    bool personalityChanged = false;
    JsonDocument personalityDoc;
    
    if(FSYS.exists(PERSONALITY_FILE)) {
        logMessage("Personality file found, loading data");
        File file = FSYS.open(PERSONALITY_FILE, FILE_READ);
        if (!file) {
            logMessage("Failed to open personality file");
            return false;
        }

        DeserializationError error = deserializeJson(personalityDoc, file);
        file.close();

        if (error) {
            logMessage("deserializeJson() failed: ");
            logMessage(error.c_str());
            return false;
        }

        // Load each option, fallback to default if missing
        if (personalityDoc["nap_time"].is<uint16_t>()) pwnagotchi.nap_time = personalityDoc["nap_time"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_wifi_scan"].is<uint16_t>()) pwnagotchi.delay_after_wifi_scan = personalityDoc["delay_after_wifi_scan"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_no_networks_found"].is<uint16_t>()) pwnagotchi.delay_after_no_networks_found = personalityDoc["delay_after_no_networks_found"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_attack_fail"].is<uint16_t>()) pwnagotchi.delay_after_attack_fail = personalityDoc["delay_after_attack_fail"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_successful_attack"].is<uint16_t>()) pwnagotchi.delay_after_successful_attack = personalityDoc["delay_after_successful_attack"];
        else personalityChanged = true;

        if (personalityDoc["deauth_packets_sent"].is<uint16_t>()) pwnagotchi.deauth_packets_sent = personalityDoc["deauth_packets_sent"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_deauth"].is<uint16_t>()) pwnagotchi.delay_after_deauth = personalityDoc["delay_after_deauth"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_picking_target"].is<uint16_t>()) pwnagotchi.delay_after_picking_target = personalityDoc["delay_after_picking_target"];
        else personalityChanged = true;

        if (personalityDoc["delay_before_switching_target"].is<uint16_t>()) pwnagotchi.delay_before_switching_target = personalityDoc["delay_before_switching_target"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_client_found"].is<uint16_t>()) pwnagotchi.delay_after_client_found = personalityDoc["delay_after_client_found"];
        else personalityChanged = true;

        if (personalityDoc["sound_on_events"].is<bool>()) pwnagotchi.sound_on_events = personalityDoc["sound_on_events"];
        else personalityChanged = true;

        if (personalityDoc["deauth_on"].is<bool>()) pwnagotchi.deauth_on = personalityDoc["deauth_on"];
        else personalityChanged = true;

        if (personalityDoc["handshake_wait_time"].is<uint16_t>()) pwnagotchi.handshake_wait_time = personalityDoc["handshake_wait_time"];
        else personalityChanged = true;

        if (personalityDoc["add_to_whitelist_on_success"].is<bool>()) pwnagotchi.add_to_whitelist_on_success = personalityDoc["add_to_whitelist_on_success"];
        else personalityChanged = true;

        if (personalityDoc["add_to_whitelist_on_fail"].is<bool>()) pwnagotchi.add_to_whitelist_on_fail = personalityDoc["add_to_whitelist_on_fail"];
        else personalityChanged = true;

        if (personalityDoc["activate_sniffer_on_deauth"].is<bool>()) pwnagotchi.activate_sniffer_on_deauth = personalityDoc["activate_sniffer_on_deauth"];
        else personalityChanged = true;

        if (personalityDoc["client_sniffing_time"].is<uint16_t>()) pwnagotchi.client_sniffing_time = personalityDoc["client_sniffing_time"];
        else personalityChanged = true;

        if (personalityDoc["deauth_packet_delay"].is<uint16_t>()) pwnagotchi.deauth_packet_delay = personalityDoc["deauth_packet_delay"];
        else personalityChanged = true;

        if (personalityDoc["delay_after_no_clients_found"].is<uint16_t>()) pwnagotchi.delay_after_no_clients_found = personalityDoc["delay_after_no_clients_found"];
        else personalityChanged = true;

        if (personalityDoc["client_discovery_timeout"].is<uint16_t>()) pwnagotchi.client_discovery_timeout = personalityDoc["client_discovery_timeout"];
        else personalityChanged = true;
        
        if (personalityDoc["gps_fix_timeout"].is<uint16_t>()) pwnagotchi.gps_fix_timeout = personalityDoc["gps_fix_timeout"];
        else personalityChanged = true;
    }
    else {
        logMessage("No personality file found, creating with default values");
        personalityChanged = true;
    }

    // Always update config with all required keys
    personalityDoc["nap_time"] = pwnagotchi.nap_time;
    personalityDoc["delay_after_wifi_scan"] = pwnagotchi.delay_after_wifi_scan;
    personalityDoc["delay_after_no_networks_found"] = pwnagotchi.delay_after_no_networks_found;
    personalityDoc["delay_after_successful_attack"] = pwnagotchi.delay_after_successful_attack;
    personalityDoc["deauth_packets_sent"] = pwnagotchi.deauth_packets_sent;
    personalityDoc["delay_after_deauth"] = pwnagotchi.delay_after_deauth;
    personalityDoc["delay_after_picking_target"] = pwnagotchi.delay_after_picking_target;
    personalityDoc["delay_before_switching_target"] = pwnagotchi.delay_before_switching_target;
    personalityDoc["delay_after_client_found"] = pwnagotchi.delay_after_client_found;
    personalityDoc["sound_on_events"] = pwnagotchi.sound_on_events;
    personalityDoc["deauth_on"] = pwnagotchi.deauth_on;
    personalityDoc["handshake_wait_time"] = pwnagotchi.handshake_wait_time;
    personalityDoc["add_to_whitelist_on_success"] = pwnagotchi.add_to_whitelist_on_success;
    personalityDoc["add_to_whitelist_on_fail"] = pwnagotchi.add_to_whitelist_on_fail;
    personalityDoc["activate_sniffer_on_deauth"] = pwnagotchi.activate_sniffer_on_deauth;
    personalityDoc["client_sniffing_time"] = pwnagotchi.client_sniffing_time;
    personalityDoc["deauth_packet_delay"] = pwnagotchi.deauth_packet_delay;
    personalityDoc["delay_after_no_clients_found"] = pwnagotchi.delay_after_no_clients_found;
    personalityDoc["delay_after_attack_fail"] = pwnagotchi.delay_after_attack_fail;
    personalityDoc["client_discovery_timeout"] = pwnagotchi.client_discovery_timeout;
    personalityDoc["gps_fix_timeout"] = pwnagotchi.gps_fix_timeout;
    
    if (personalityChanged) {
        logMessage("Personality updated with missing/default values, saving...");
        FConf = FSYS.open(PERSONALITY_FILE, FILE_WRITE, true);
        if (FConf) {
            String output;
            serializeJsonPretty(personalityDoc, output);
            FConf.print(output);
            FConf.close();
            logMessage("Personality saved successfully");
        } else {
            logMessage("Failed to open personality file for writing");
            return false;
        }
    }
    return true;
}

// SD mutex definition
SemaphoreHandle_t sdMutex = NULL;


bool savePersonality(){
    JsonDocument personalityDoc;
    personalityDoc["nap_time"] = pwnagotchi.nap_time;
    personalityDoc["delay_after_wifi_scan"] = pwnagotchi.delay_after_wifi_scan;
    personalityDoc["delay_after_no_networks_found"] = pwnagotchi.delay_after_no_networks_found;
    personalityDoc["delay_after_successful_attack"] = pwnagotchi.delay_after_successful_attack;
    personalityDoc["deauth_packets_sent"] = pwnagotchi.deauth_packets_sent;
    personalityDoc["delay_after_deauth"] = pwnagotchi.delay_after_deauth;
    personalityDoc["delay_after_picking_target"] = pwnagotchi.delay_after_picking_target;
    personalityDoc["delay_before_switching_target"] = pwnagotchi.delay_before_switching_target;
    personalityDoc["delay_after_client_found"] = pwnagotchi.delay_after_client_found;
    personalityDoc["sound_on_events"] = pwnagotchi.sound_on_events;
    personalityDoc["deauth_on"] = pwnagotchi.deauth_on;
    personalityDoc["handshake_wait_time"] = pwnagotchi.handshake_wait_time;
    personalityDoc["add_to_whitelist_on_success"] = pwnagotchi.add_to_whitelist_on_success;
    personalityDoc["add_to_whitelist_on_fail"] = pwnagotchi.add_to_whitelist_on_fail;
    personalityDoc["activate_sniffer_on_deauth"] = pwnagotchi.activate_sniffer_on_deauth;
    personalityDoc["client_sniffing_time"] = pwnagotchi.client_sniffing_time;
    personalityDoc["deauth_packet_delay"] = pwnagotchi.deauth_packet_delay;
    personalityDoc["delay_after_no_clients_found"] = pwnagotchi.delay_after_no_clients_found;
    personalityDoc["delay_after_attack_fail"] = pwnagotchi.delay_after_attack_fail;
    personalityDoc["client_discovery_timeout"] = pwnagotchi.client_discovery_timeout;
    personalityDoc["gps_fix_timeout"] = pwnagotchi.gps_fix_timeout;

    logMessage("Personality JSON data creation successful, proceeding to save");
    FConf = FSYS.open(PERSONALITY_FILE, FILE_WRITE, false);
    if (FConf) {
        String output;
        serializeJsonPretty(personalityDoc, output);
        FConf.print(output);
        FConf.close();
        logMessage("Personality saved successfully");
        return true;
    } else {
        logMessage("Failed to open personality file for writing");
        return false;
    }
}

bool initNewPersonality(){
    #ifdef USE_LITTLEFS
    if (!FSYS.begin()) {
        logMessage("LittleFS init failed");
        return false;
    }
    #else
    if (!FSYS.begin(SD_CS, sdSPI, 1000000)) {
        logMessage("SD card init failed");
        return false;
    }
    #endif
    bool personalityChanged = false;
    JsonDocument personalityDoc;
    
    if(FSYS.exists(NEW_PERSONALITY_FILE)) {
        logMessage("New personality file found, loading data");
        File file = FSYS.open(NEW_PERSONALITY_FILE, FILE_READ);
        if (!file) {
            logMessage("Failed to open new personality file");
            return false;
        }

        DeserializationError error = deserializeJson(personalityDoc, file);
        file.close();

        if (error) {
            logMessage("deserializeJson() failed: ");
            logMessage(error.c_str());
            return false;
        }

        // Load each option, fallback to default if missing
        if (personalityDoc["eapol_timeout"].is<uint16_t>()) n_pwnagotchi_personality.eapol_timeout = personalityDoc["eapol_timeout"];
        else personalityChanged = true;

        if (personalityDoc["deauth_packets_count"].is<uint16_t>()) n_pwnagotchi_personality.deauth_packets_count = personalityDoc["deauth_packets_count"];
        else personalityChanged = true;

        if (personalityDoc["deauth_packet_interval"].is<uint16_t>()) n_pwnagotchi_personality.deauth_packet_interval = personalityDoc["deauth_packet_interval"];
        else personalityChanged = true;

        if (personalityDoc["pmkid_attack_timeout"].is<uint16_t>()) n_pwnagotchi_personality.pmkid_attack_timeout = personalityDoc["pmkid_attack_timeout"];
        else personalityChanged = true;

        if (personalityDoc["delay_between_attacks"].is<uint16_t>()) n_pwnagotchi_personality.delay_between_attacks = personalityDoc["delay_between_attacks"];
        else personalityChanged = true;

        if (personalityDoc["sound_on_handshake"].is<bool>()) n_pwnagotchi_personality.sound_on_handshake = personalityDoc["sound_on_handshake"];
        else personalityChanged = true;

        if (personalityDoc["sound_on_pmkid"].is<bool>()) n_pwnagotchi_personality.sound_on_pmkid = personalityDoc["sound_on_pmkid"];
        else personalityChanged = true;

        if (personalityDoc["rssi_threshold"].is<int>()) n_pwnagotchi_personality.rssi_threshold = personalityDoc["rssi_threshold"];
        else personalityChanged = true;

        if (personalityDoc["enable_wardriving"].is<bool>()) n_pwnagotchi_personality.enable_wardriving = personalityDoc["enable_wardriving"];
        else personalityChanged = true;

        if (personalityDoc["gps_timeout_ms"].is<uint16_t>()) n_pwnagotchi_personality.gps_timeout_ms = personalityDoc["gps_timeout_ms"];
        else personalityChanged = true;

        if (personalityDoc["wardrive_scan_interval_ms"].is<uint16_t>()) n_pwnagotchi_personality.wardrive_scan_interval_ms = personalityDoc["wardrive_scan_interval_ms"];
        else personalityChanged = true;

        if (personalityDoc["enable_pmkid_attack"].is<bool>()) n_pwnagotchi_personality.enable_pmkid_attack = personalityDoc["enable_pmkid_attack"];
        else personalityChanged = true;
    }
    else {
        logMessage("No new personality file found, creating with default values");
        personalityChanged = true;
    }

    // Always update config with all required keys
    personalityDoc["eapol_timeout"] = n_pwnagotchi_personality.eapol_timeout;
    personalityDoc["deauth_packets_count"] = n_pwnagotchi_personality.deauth_packets_count;
    personalityDoc["deauth_packet_interval"] = n_pwnagotchi_personality.deauth_packet_interval;
    personalityDoc["pmkid_attack_timeout"] = n_pwnagotchi_personality.pmkid_attack_timeout;
    personalityDoc["delay_between_attacks"] = n_pwnagotchi_personality.delay_between_attacks;
    personalityDoc["sound_on_handshake"] = n_pwnagotchi_personality.sound_on_handshake;
    personalityDoc["sound_on_pmkid"] = n_pwnagotchi_personality.sound_on_pmkid;
    personalityDoc["rssi_threshold"] = n_pwnagotchi_personality.rssi_threshold;
    personalityDoc["enable_wardriving"] = n_pwnagotchi_personality.enable_wardriving;
    personalityDoc["gps_timeout_ms"] = n_pwnagotchi_personality.gps_timeout_ms;
    personalityDoc["wardrive_scan_interval_ms"] = n_pwnagotchi_personality.wardrive_scan_interval_ms;
    personalityDoc["enable_pmkid_attack"] = n_pwnagotchi_personality.enable_pmkid_attack;
    
    if (personalityChanged) {
        logMessage("New personality updated with missing/default values, saving...");
        FConf = FSYS.open(NEW_PERSONALITY_FILE, FILE_WRITE, true);
        if (FConf) {
            String output;
            serializeJsonPretty(personalityDoc, output);
            FConf.print(output);
            FConf.close();
            logMessage("New personality saved successfully");
        } else {
            logMessage("Failed to open new personality file for writing");
            return false;
        }
    }
    return true;
}

bool saveNewPersonality(){
    JsonDocument personalityDoc;
    personalityDoc["eapol_timeout"] = n_pwnagotchi_personality.eapol_timeout;
    personalityDoc["deauth_packets_count"] = n_pwnagotchi_personality.deauth_packets_count;
    personalityDoc["deauth_packet_interval"] = n_pwnagotchi_personality.deauth_packet_interval;
    personalityDoc["pmkid_attack_timeout"] = n_pwnagotchi_personality.pmkid_attack_timeout;
    personalityDoc["delay_between_attacks"] = n_pwnagotchi_personality.delay_between_attacks;
    personalityDoc["sound_on_handshake"] = n_pwnagotchi_personality.sound_on_handshake;
    personalityDoc["sound_on_pmkid"] = n_pwnagotchi_personality.sound_on_pmkid;
    personalityDoc["rssi_threshold"] = n_pwnagotchi_personality.rssi_threshold;
    personalityDoc["enable_wardriving"] = n_pwnagotchi_personality.enable_wardriving;
    personalityDoc["wardrive_scan_interval_ms"] = n_pwnagotchi_personality.wardrive_scan_interval_ms;
    personalityDoc["gps_timeout_ms"] = n_pwnagotchi_personality.gps_timeout_ms;
    personalityDoc["enable_pmkid_attack"] = n_pwnagotchi_personality.enable_pmkid_attack;

    logMessage("New personality JSON data creation successful, proceeding to save");
    FConf = FSYS.open(NEW_PERSONALITY_FILE, FILE_WRITE, false);
    if (FConf) {
        String output;
        serializeJsonPretty(personalityDoc, output);
        FConf.print(output);
        FConf.close();
        logMessage("New personality saved successfully");
        return true;
    } else {
        logMessage("Failed to open new personality file for writing");
        return false;
    }
}

#include "WiFi.h"

bool configChanged = false;
uint8_t menu_display_mode = 0;  // 0=list, 1=grid

bool initVars() {
    // create SD mutex to protect FSYS operations
    if (sdMutex == NULL) {
        sdMutex = xSemaphoreCreateMutex();
        if (sdMutex == NULL) {
            logMessage("Failed to create SD mutex");
            return false;
        }
    }
    #ifdef USE_LITTLEFS
    if (!FSYS.begin()) {
        logMessage("LittleFS init failed");
        return false;
    }
    #else
    if (!FSYS.begin(SD_CS, sdSPI, 1000000)) {
        logMessage("SD card init failed");
        return false;
    }
    #endif

    if(FSYS.exists("/M5Gotchi")) {
        logMessage("/M5Gotchi directory exists");
    } else {
        logMessage("/M5Gotchi directory does not exist, creating...");
        if (FSYS.mkdir("/M5Gotchi")) {
            logMessage("/M5Gotchi directory created successfully");
            initColorSettings();
            initUi();
            drawInfoBox("WARNING!", "Some files are not in the wrong places. Don't worry I'll fix them now.","",  false, false);
            // Migrate files and folders to /M5Gotchi directory
            logMessage("Starting file migration to /M5Gotchi...");

            // Migrate individual config files
            if (FSYS.exists("/M5gothi.conf")) {
                FSYS.rename("/M5gothi.conf", "/M5Gotchi/M5gothi.conf");
                logMessage("Migrated M5gothi.conf");
            }
            if (FSYS.exists("/personality.conf")) {
                FSYS.rename("/personality.conf", "/M5Gotchi/personality.conf");
                logMessage("Migrated personality.conf");
            }
            if (FSYS.exists("/new_personality.conf")) {
                FSYS.rename("/new_personality.conf", "/M5Gotchi/new_personality.conf");
                logMessage("Migrated new_personality.conf");
            }
            if (FSYS.exists("/cracked.json")) {
                FSYS.rename("/cracked.json", "/M5Gotchi/cracked.json");
                logMessage("Migrated cracked.json");
            }
            if (FSYS.exists("/uploaded.conf")) {
                FSYS.rename("/uploaded.conf", "/M5Gotchi/uploaded.conf");
                logMessage("Migrated uploaded.conf");
            }

            // Migrate directories with all their content
            const char* dirsToMigrate[] = {"/handshake", "/wardriving", "/fonts", "/temp", "/moods", "/pwngrid"};
            for (const char* dir : dirsToMigrate) {
                if (FSYS.exists(dir)) {
                    String newPath = String("/M5Gotchi") + dir;
                    FSYS.rename(dir, newPath);
                    logMessage("Migrated directory: " + String(dir));
                }
            }

            logMessage("File migration completed successfully");
        } else {
            logMessage("Failed to create /M5Gotchi directory");
            return false;
        }
    }

    String macAddr = WiFi.macAddress();
    originalMacAddress = macAddr;
    logMessage("Original MAC Address: " + macAddr);

    
    JsonDocument config;

    if (FSYS.exists(NEW_CONFIG_FILE)) {
        logMessage("Conf file found, loading data");
        File file = FSYS.open(NEW_CONFIG_FILE, FILE_READ);
        if (!file) {
            logMessage("Failed to open config file");
            return false;
        }

        DeserializationError error = deserializeJson(config, file);
        file.close();

        if (error) {
            logMessage("deserializeJson() failed: ");
            logMessage(error.c_str());
            initColorSettings();
            initUi();
            drawInfoBox("CRITICALL ERROR!", "Config file is corrupted and will be recreated. All settings will be lost!","",  false, false);
            delay(5000);
            FSYS.remove(NEW_CONFIG_FILE);
            ESP.restart();
            return false;
        }

        // Load each option, fallback to default if missing
        if (config["Hostname"].is<const char*>()) hostname = String(config["Hostname"].as<const char*>());
        else configChanged = true;

        if (config["sound"].is<bool>()) sound = config["sound"];
        else configChanged = true;

        if (config["brightness"].is<int>()) brightness = config["brightness"];
        else configChanged = true;

        if (config["autoDimEnabled"].is<bool>()) autoDimEnabled = config["autoDimEnabled"];
        else configChanged = true;

        if (config["autoDimTimeout"].is<uint16_t>()) autoDimTimeout = config["autoDimTimeout"];
        else configChanged = true;

        if (config["autoDimMinBrightness"].is<uint8_t>()) autoDimMinBrightness = config["autoDimMinBrightness"];
        else configChanged = true;

        if (config["pwned_ap"].is<uint16_t>()&& !config["system_stats_menu_mode"].is<uint8_t>()) pwned_ap = config["pwned_ap"];
        else if (config["pwned_ap"].is<String>()) {
            uint16_t tmpVal = 0;
            if (decryptStatsValue16(config["pwned_ap"].as<String>(), originalMacAddress, tmpVal)) {
                pwned_ap = tmpVal;
            }
            if (tmpVal == 0 && !config["pwned_ap"].is<uint16_t>()) configChanged = true;
        }
        else configChanged = true;

        // legacy single saved network keys
        if (config["savedApSSID"].is<const char*>()) savedApSSID = String(config["savedApSSID"].as<const char*>());
        else configChanged = true;

        if (config["savedAPPass"].is<const char*>()) savedAPPass = String(config["savedAPPass"].as<const char*>());
        else configChanged = true;

        // new: savedNetworks as array of {ssid, pass, connectOnStart}
        if (config["savedNetworks"].is<JsonArray>()) {
            JsonArray arr = config["savedNetworks"].as<JsonArray>();
            savedNetworks.clear();
            for (JsonObject net : arr) {
                SavedNetwork n;
                n.ssid = net["ssid"].is<const char*>() ? String(net["ssid"].as<const char*>()) : "";
                n.pass = net["pass"].is<const char*>() ? String(net["pass"].as<const char*>()) : "";
                n.connectOnStart = net["connectOnStart"].is<bool>() ? net["connectOnStart"].as<bool>() : false;
                savedNetworks.push_back(n);
            }
        }

        if (config["whitelist"].is<const char*>()) whitelist = String(config["whitelist"].as<const char*>());
        else configChanged = true;

        if (config["auto_mode_on_startup"].is<bool>()) {pwnagothiModeEnabled = config["auto_mode_on_startup"];
        } else configChanged = true;

        if (config["bg_color"].is<const char*>()) bg_color = String(config["bg_color"].as<const char*>());
        else configChanged = true;

        if (config["tx_color"].is<const char*>()) tx_color = String(config["tx_color"].as<const char*>());
        else configChanged = true;

        if (config["skip_eapol_check"].is<bool>()) skip_eapol_check = config["skip_eapol_check"].as<bool>();
        else configChanged = true;

        if (config["wpa_sec_api_key"].is<const char*>()) wpa_sec_api_key = String(config["wpa_sec_api_key"].as<const char*>());
        else configChanged = true;

        if(config["lite_mode_wpa_sec_sync_on_startup"].is<bool>()) lite_mode_wpa_sec_sync_on_startup = config["lite_mode_wpa_sec_sync_on_startup"].as<bool>();
        else configChanged = true;

        if(config["sync_pwned_on_boot"].is<bool>()) sync_pwned_on_boot = config["sync_pwned_on_boot"].as<bool>();
        else configChanged = true;

        if(config["menu_display_mode"].is<uint8_t>()) menu_display_mode = config["menu_display_mode"].as<uint8_t>();
        else configChanged = true;

        if(config["sd_logging"].is<bool>()) sd_logging = config["sd_logging"].as<bool>();
        else configChanged = true;

        if(config["toogle_pwnagothi_with_gpio0"].is<bool>()) toogle_pwnagothi_with_gpio0 = config["toogle_pwnagothi_with_gpio0"].as<bool>();
        else configChanged = true;

        if(config["stealth_mode"].is<bool>()) stealth_mode = config["stealth_mode"].as<bool>();
        else configChanged = true;

        if(config["pwngrid_indentity"].is<const char*>()) pwngrid_indentity = String(config["pwngrid_indentity"].as<const char*>());
        else configChanged = true;

        if(config["advertise_pwngrid"].is<bool>()) advertisePwngrid = config["advertise_pwngrid"].as<bool>();
        else configChanged = true;

        if(config["lastTokenRefresh"].is<uint64_t>()) lastTokenRefresh = config["lastTokenRefresh"].as<uint64_t>();
        else configChanged = true;

        if(config["wiggle_api_key"].is<const char*>()) wiggle_api_key = String(config["wiggle_api_key"].as<const char*>());
        else configChanged = true;

        if(config["hintsDisplayed"].is<uint64_t>()) hintsDisplayed = config["hintsDisplayed"].as<uint64_t>();
        else configChanged = true;

        if (config["serial_overlay"].is<bool>()) serial_overlay = config["serial_overlay"].as<bool>();
        else configChanged = true;

        if (config["coords_overlay"].is<bool>()) coords_overlay = config["coords_overlay"].as<bool>();
        else configChanged = true;
        
        if (config["skip_file_manager_checks_in_dev"].is<bool>()) skip_file_manager_checks_in_dev = config["skip_file_manager_checks_in_dev"].as<bool>();
        else configChanged = true;

        if(config["checkUpdatesAtNetworkStart"].is<bool>()) checkUpdatesAtNetworkStart = config["checkUpdatesAtNetworkStart"].as<bool>();
        else configChanged = true;

        if(config["connectWiFiOnStartup"].is<bool>()) connectWiFiOnStartup = config["connectWiFiOnStartup"].as<bool>();
        else configChanged = true;

        if(config["gpsTx"].is<uint8_t>()) gpsTx = config["gpsTx"].as<uint8_t>();
        else configChanged = true;

        if(config["gpsRx"].is<uint8_t>()) gpsRx = config["gpsRx"].as<uint8_t>();
        else configChanged = true;

        if(config["useCustomGPSPins"].is<bool>()) useCustomGPSPins = config["useCustomGPSPins"].as<bool>();
        else configChanged = true;

        if(config["gpsBaudRate"].is<uint32_t>()) gpsBaudRate = config["gpsBaudRate"].as<uint32_t>();
        else configChanged = true;

        if(config["getLocationAfterPwn"].is<bool>()) getLocationAfterPwn = config["getLocationAfterPwn"].as<bool>();
        else configChanged = true;

        if(config["lastSessionDeauths"].is<uint>()&& !config["system_stats_menu_mode"].is<uint8_t>()) lastSessionDeauths = config["lastSessionDeauths"].as<uint>();
        else if(config["lastSessionDeauths"].is<String>()) {
            // Try to decrypt if MAC is available
            uint tmpVal = 0;
            if (decryptStatsValue32(config["lastSessionDeauths"].as<String>(), originalMacAddress, tmpVal)) {
                lastSessionDeauths = tmpVal;
            }
            // If decryption fails, mark for re-encryption on save
            if (tmpVal == 0 && !config["lastSessionDeauths"].is<uint>()) configChanged = true;
        }
        else configChanged = true;
        
        if(config["lastSessionTime"].is<long>()&& !config["system_stats_menu_mode"].is<uint8_t>()) lastSessionTime = config["lastSessionTime"].as<long>();
        else if(config["lastSessionTime"].is<String>()) {
            uint64_t tmpVal = 0;
            if (decryptStatsValue(config["lastSessionTime"].as<String>(), originalMacAddress, tmpVal)) {
                lastSessionTime = (long)tmpVal;
            }
            if (tmpVal == 0 && !config["lastSessionTime"].is<long>()) configChanged = true;
        }
        else configChanged = true;

        if(config["lastSessionPeers"].is<uint8_t>()&& !config["system_stats_menu_mode"].is<uint8_t>()) lastSessionPeers = config["lastSessionPeers"].as<uint8_t>();
        else if(config["lastSessionPeers"].is<String>()) {
            uint16_t tmpVal = 0;
            if (decryptStatsValue16(config["lastSessionPeers"].as<String>(), originalMacAddress, tmpVal)) {
                lastSessionPeers = (uint8_t)tmpVal;
            }
            if (tmpVal == 0 && !config["lastSessionPeers"].is<uint8_t>()) configChanged = true;
        }
        else configChanged = true;

        if(config["allTimeDeauths"].is<uint32_t>()&& !config["system_stats_menu_mode"].is<uint8_t>()) allTimeDeauths = config["allTimeDeauths"].as<uint32_t>();
        else if(config["allTimeDeauths"].is<String>()) {
            uint32_t tmpVal = 0;
            if (decryptStatsValue32(config["allTimeDeauths"].as<String>(), originalMacAddress, tmpVal)) {
                allTimeDeauths = tmpVal;
            }
            if (tmpVal == 0 && !config["allTimeDeauths"].is<uint32_t>()) configChanged = true;
        }
        else configChanged = true;

        if(config["allTimeEpochs"].is<uint32_t>()&& !config["system_stats_menu_mode"].is<uint8_t>()) allTimeEpochs = config["allTimeEpochs"].as<uint32_t>();
        else if(config["allTimeEpochs"].is<String>()) {
            uint32_t tmpVal = 0;
            if (decryptStatsValue32(config["allTimeEpochs"].as<String>(), originalMacAddress, tmpVal)) {
                allTimeEpochs = tmpVal;
            }
            if (tmpVal == 0 && !config["allTimeEpochs"].is<uint32_t>()) configChanged = true;
        }
        else configChanged = true;

        if(config["allTimePeers"].is<uint16_t>()&& !config["system_stats_menu_mode"].is<uint8_t>()) allTimePeers = config["allTimePeers"].as<uint16_t>();
        else if(config["allTimePeers"].is<String>()) {
            uint16_t tmpVal = 0;
            if (decryptStatsValue16(config["allTimePeers"].as<String>(), originalMacAddress, tmpVal)) {
                allTimePeers = tmpVal;
            }
            if (tmpVal == 0 && !config["allTimePeers"].is<uint16_t>()) configChanged = true;
        }
        else configChanged = true;

        if(config["allSessionTime"].is<long long>() && !config["system_stats_menu_mode"].is<uint8_t>()) allSessionTime = config["allSessionTime"].as<long long>();
        else if(config["allSessionTime"].is<String>()) {
            uint64_t tmpVal = 0;
            if (decryptStatsValue(config["allSessionTime"].as<String>(), originalMacAddress, tmpVal)) {
                allSessionTime = (long long)tmpVal;
            }
            if (tmpVal == 0 && !config["allSessionTime"].is<long long>()) configChanged = true;
        }
        else configChanged = true;

        if(config["prev_level"].is<uint16_t>()) prev_level = config["prev_level"].as<uint16_t>();
        else configChanged = true;

        if(config["randomise_mac_at_boot"].is<bool>()) randomise_mac_at_boot = config["randomise_mac_at_boot"].as<bool>();
        else configChanged = true;

        if(config["add_new_units_to_friends"].is<bool>()) add_new_units_to_friends = config["add_new_units_to_friends"].as<bool>();
        else configChanged = true;

        if(config["lastSessionCaptures"].is<uint>()) lastSessionCaptures = config["lastSessionCaptures"].as<uint>();
        else configChanged = true;

        if(config["check_inbox_at_startup"].is<bool>()) check_inbox_at_startup = config["check_inbox_at_startup"].as<bool>();
        else configChanged = true;

        if(configChanged) {
            logMessage("Config file missing values, will be updated");
        }
    } else {
        logMessage("Conf file not found, creating one");
        configChanged = true;
    }

    // Always update config with all required keys
    config["Hostname"] = hostname;
    config["sound"] = sound;
    config["brightness"] = brightness;
    config["autoDimEnabled"] = autoDimEnabled;
    config["autoDimTimeout"] = autoDimTimeout;
    config["autoDimMinBrightness"] = autoDimMinBrightness;
    config["pwned_ap"] = encryptStatsValue16(pwned_ap, originalMacAddress);
    config["savedApSSID"] = savedApSSID;
    config["savedAPPass"] = savedAPPass;
    // Save new networks array
    JsonArray nets = config.createNestedArray("savedNetworks");
    for (auto &n : savedNetworks) {
        JsonObject net = nets.createNestedObject();
        net["ssid"] = n.ssid;
        net["pass"] = n.pass;
        net["connectOnStart"] = n.connectOnStart;
    }
    config["whitelist"] = whitelist;
    config["auto_mode_on_startup"] = pwnagothiModeEnabled;
    config["bg_color"] = bg_color;
    config["tx_color"] = tx_color;
    config["skip_eapol_check"] = skip_eapol_check;
    config["wpa_sec_api_key"] = wpa_sec_api_key;
    config["lite_mode_wpa_sec_sync_on_startup"] = lite_mode_wpa_sec_sync_on_startup;
    config["sd_logging"] = sd_logging;
    config["toogle_pwnagothi_with_gpio0"] = toogle_pwnagothi_with_gpio0;
    config["stealth_mode"] = stealth_mode;
    config["pwngrid_indentity"] = pwngrid_indentity;
    config["advertise_pwngrid"] = advertisePwngrid;
    config["lastTokenRefresh"] = lastTokenRefresh;
    config["wiggle_api_key"] = wiggle_api_key;
    config["hintsDisplayed"] = hintsDisplayed;
    config["dev_mode"] = dev_mode;
    config["serial_overlay"] = serial_overlay;
    config["coords_overlay"] = coords_overlay;
    config["skip_file_manager_checks_in_dev"] = skip_file_manager_checks_in_dev;
    config["checkUpdatesAtNetworkStart"] = checkUpdatesAtNetworkStart;
    config["connectWiFiOnStartup"] = connectWiFiOnStartup;
    config["gpsTx"] = gpsTx;
    config["gpsRx"] = gpsRx;
    config["useCustomGPSPins"] = useCustomGPSPins;
    config["gpsBaudRate"] = gpsBaudRate;
    config["getLocationAfterPwn"] = getLocationAfterPwn;
    // Encrypt sensitive stats using MAC address as key
    config["lastSessionDeauths"] = encryptStatsValue32(lastSessionDeauths, originalMacAddress);
    config["lastSessionCaptures"] = encryptStatsValue32(lastSessionCaptures, originalMacAddress);
    config["lastSessionTime"] = encryptStatsValue(lastSessionTime, originalMacAddress);
    config["lastSessionPeers"] = encryptStatsValue16(lastSessionPeers, originalMacAddress);
    config["allTimeDeauths"] = encryptStatsValue32(allTimeDeauths, originalMacAddress);
    config["allTimeEpochs"] = encryptStatsValue32(allTimeEpochs, originalMacAddress);
    config["allTimePeers"] = encryptStatsValue16(allTimePeers, originalMacAddress);
    config["allSessionTime"] = encryptStatsValue(allSessionTime, originalMacAddress);
    config["prev_level"] = prev_level;
    config["randomise_mac_at_boot"] = randomise_mac_at_boot;
    config["add_new_units_to_friends"] = add_new_units_to_friends;
    config["check_inbox_at_startup"] = check_inbox_at_startup;
    config["sync_pwned_on_boot"] = sync_pwned_on_boot;
    config["menu_display_mode"] = menu_display_mode;
    config["system_stats_menu_mode"] = 1; // Always save in list mode, grid mode is just a display option

    if (configChanged) {
        logMessage("Config updated with missing/default values, saving...");
        FConf = FSYS.open(NEW_CONFIG_FILE, FILE_WRITE, true);
        if (FConf) {
            String output;
            serializeJsonPretty(config, output);
            FConf.print(output);
            FConf.close();
            logMessage("Config saved successfully");
        } else {
            logMessage("Failed to open config file for writing");
            return false;
        }
    }
    logMessage("Loaded identity: " + pwngrid_indentity);
    return true;
}
bool saveSettings(){
    JsonDocument config;

    // --- Non-sensitive fields (no validation needed) ---
    config["Hostname"] = hostname;
    config["sound"] = sound;
    config["brightness"] = brightness;
    config["autoDimEnabled"] = autoDimEnabled;
    config["autoDimTimeout"] = autoDimTimeout;
    config["autoDimMinBrightness"] = autoDimMinBrightness;
    config["savedApSSID"] = savedApSSID;
    config["savedAPPass"] = savedAPPass;
    config["whitelist"] = whitelist;
    config["auto_mode_on_startup"] = pwnagothiModeEnabled;
    config["bg_color"] = bg_color;
    config["tx_color"] = tx_color;
    config["skip_eapol_check"] = skip_eapol_check;
    config["wpa_sec_api_key"] = wpa_sec_api_key;
    config["lite_mode_wpa_sec_sync_on_startup"] = lite_mode_wpa_sec_sync_on_startup;
    config["sd_logging"] = sd_logging;
    config["toogle_pwnagothi_with_gpio0"] = toogle_pwnagothi_with_gpio0;
    config["stealth_mode"] = stealth_mode;
    config["pwngrid_indentity"] = pwngrid_indentity;
    config["advertise_pwngrid"] = advertisePwngrid;
    config["lastTokenRefresh"] = lastTokenRefresh;
    config["wiggle_api_key"] = wiggle_api_key;
    config["hintsDisplayed"] = hintsDisplayed;
    config["dev_mode"] = dev_mode;
    config["serial_overlay"] = serial_overlay;
    config["coords_overlay"] = coords_overlay;
    config["skip_file_manager_checks_in_dev"] = skip_file_manager_checks_in_dev;
    config["checkUpdatesAtNetworkStart"] = checkUpdatesAtNetworkStart;
    config["connectWiFiOnStartup"] = connectWiFiOnStartup;
    config["gpsTx"] = gpsTx;
    config["gpsRx"] = gpsRx;
    config["useCustomGPSPins"] = useCustomGPSPins;
    config["gpsBaudRate"] = gpsBaudRate;
    config["getLocationAfterPwn"] = getLocationAfterPwn;
    config["prev_level"] = prev_level;
    config["randomise_mac_at_boot"] = randomise_mac_at_boot;
    config["add_new_units_to_friends"] = add_new_units_to_friends;
    config["check_inbox_at_startup"] = check_inbox_at_startup;
    config["sync_pwned_on_boot"] = sync_pwned_on_boot;
    config["menu_display_mode"] = menu_display_mode;
    config["system_stats_menu_mode"] = 1;
    config["auto_mode_and_wardrive"] = auto_mode_and_wardrive;

    // savedNetworks array
    JsonArray nets = config.createNestedArray("savedNetworks");
    for (auto &n : savedNetworks) {
        JsonObject net = nets.createNestedObject();
        net["ssid"] = n.ssid;
        net["pass"] = n.pass;
        net["connectOnStart"] = n.connectOnStart;
    }

    // --- Sensitive/encrypted fields with validation ---
    // Helper lambda to encrypt and validate, falling back to reading the
    // existing value from the config file on disk if encryption fails.
    // This prevents overwriting a good encrypted value with an empty string.
    auto safeEncrypt16 = [&](const char* key, uint16_t value) -> bool {
        String enc = encryptStatsValue16(value, originalMacAddress);
        if (enc.length() == 0) {
            fLogMessage("[settings] saveSettings: encryption failed for key '%s', aborting save\n", key);
            return false;
        }
        config[key] = enc;
        return true;
    };

    auto safeEncrypt32 = [&](const char* key, uint32_t value) -> bool {
        String enc = encryptStatsValue32(value, originalMacAddress);
        if (enc.length() == 0) {
            fLogMessage("[settings] saveSettings: encryption failed for key '%s', aborting save\n", key);
            return false;
        }
        config[key] = enc;
        return true;
    };

    auto safeEncrypt64 = [&](const char* key, uint64_t value) -> bool {
        String enc = encryptStatsValue(value, originalMacAddress);
        if (enc.length() == 0) {
            fLogMessage("[settings] saveSettings: encryption failed for key '%s', aborting save\n", key);
            return false;
        }
        config[key] = enc;
        return true;
    };

    // Bail out early if any encryption step fails — never persist partial/empty values
    if (!safeEncrypt16("pwned_ap",           pwned_ap))           return false;
    if (!safeEncrypt32("lastSessionDeauths", lastSessionDeauths)) return false;
    if (!safeEncrypt32("lastSessionCaptures",lastSessionCaptures)) return false; 
    if (!safeEncrypt64("lastSessionTime",    (uint64_t)lastSessionTime))  return false;
    if (!safeEncrypt16("lastSessionPeers",   (uint16_t)lastSessionPeers)) return false;
    if (!safeEncrypt32("allTimeDeauths",     allTimeDeauths))     return false;
    if (!safeEncrypt32("allTimeEpochs",      allTimeEpochs))      return false;
    if (!safeEncrypt16("allTimePeers",       allTimePeers))       return false;
    if (!safeEncrypt64("allSessionTime",     (uint64_t)allSessionTime))   return false;

    // --- Write to disk ---
    logMessage("[settings] saveSettings: all fields validated, writing to disk");

    FConf = FSYS.open(NEW_CONFIG_FILE, FILE_WRITE, false);
    if (!FConf) {
        logMessage("[settings] saveSettings: failed to open config file for writing");
        return false;
    }

    String output;
    serializeJsonPretty(config, output);
    size_t written = FConf.print(output);
    FConf.close();

    if (written != output.length()) {
        fLogMessage("[settings] saveSettings: write incomplete (%u of %u bytes)\n",
                    (unsigned)written, (unsigned)output.length());
        return false;
    }

    logMessage("[settings] saveSettings: config saved successfully");
    return true;
}

bool addSavedNetwork(const String &ssid, const String &pass, bool connectOnStart){
    // update existing if present
    for(auto &e : savedNetworks){
        if(e.ssid == ssid){
            e.pass = pass;
            e.connectOnStart = connectOnStart ? true : e.connectOnStart;
            if(connectOnStart){ savedApSSID = e.ssid; savedAPPass = e.pass; }
            return saveSettings();
        }
    }
    SavedNetwork n;
    n.ssid = ssid;
    n.pass = pass;
    n.connectOnStart = connectOnStart;
    savedNetworks.push_back(n);
    if(connectOnStart){
        // Update single savedAp compatibility
        savedApSSID = ssid;
        savedAPPass = pass;
    }
    return saveSettings();
}

bool removeSavedNetwork(size_t idx){
    if(idx >= savedNetworks.size()) return false;
    savedNetworks.erase(savedNetworks.begin() + idx);
    // ensure savedAp compatibility - set to first connectOnStart or first network
    savedApSSID = "";
    savedAPPass = "";
    for(auto &n : savedNetworks){
        if(n.connectOnStart){
            savedApSSID = n.ssid;
            savedAPPass = n.pass;
            break;
        }
    }
    if(savedApSSID == "" && savedNetworks.size() > 0){
        savedApSSID = savedNetworks[0].ssid;
        savedAPPass = savedNetworks[0].pass;
    }
    return saveSettings();
}

bool setSavedNetworkConnectOnStart(size_t idx, bool enabled){
    if(idx >= savedNetworks.size()) return false;
    savedNetworks[idx].connectOnStart = enabled;
    if(enabled){
        savedApSSID = savedNetworks[idx].ssid;
        savedAPPass = savedNetworks[idx].pass;
    } else {
        // find another connectOnStart; else clear
        bool found = false;
        for(size_t i=0;i<savedNetworks.size();i++){
            if(savedNetworks[i].connectOnStart){
                savedApSSID = savedNetworks[i].ssid;
                savedAPPass = savedNetworks[i].pass;
                found = true;
                break;
            }
        }
        if(!found){
            if(savedNetworks.size()>0){
                savedApSSID = savedNetworks[0].ssid;
                savedAPPass = savedNetworks[0].pass;
            } else {
                savedApSSID = "";
                savedAPPass = "";
            }
        }
    }
    return saveSettings();
}

void attemptConnectSavedNetworks(){
    logMessage("Scanning for available networks...");
    int networksFound = WiFi.scanNetworks();
    logMessage("Found " + String(networksFound) + " networks");

    // ── legacy fallback ──────────────────────────────────────────────────────
    if(savedNetworks.size() == 0){
        if(savedApSSID.length() > 0){
            for(int i = 0; i < networksFound; i++){
                if(WiFi.SSID(i) == savedApSSID){
                    logMessage("Connecting to " + savedApSSID);
                    WiFi.scanDelete();          // free BEFORE begin(); no longer needed
                    WiFi.begin(savedApSSID.c_str(), savedAPPass.c_str());
                    unsigned long start = millis();
                    while(millis() - start < 10000 && WiFi.status() != WL_CONNECTED)
                        delay(500);
                    return;                     // scanDelete already called
                }
            }
        }
        WiFi.scanDelete();                      // network not found, still must free
        return;
    }
    else{
        logMessage("Using savedNetworks list with " + String(savedNetworks.size()) + " entries");
    }

    // ── build a set of visible SSIDs once, O(n) lookups instead of O(n²) ────
    // (also prevents touching scan buffer after it's freed)
    std::vector<String> visible;
    for(int i = 0; i < networksFound; i++)
        visible.push_back(WiFi.SSID(i));

    WiFi.scanDelete();                          // scan buffer no longer needed

    // ── connectOnStart networks first ────────────────────────────────────────
    logMessage("Attempting to connect to saved networks with connectOnStart=true");
    for(auto &n : savedNetworks){
        if(n.connectOnStart && std::find(visible.begin(), visible.end(), n.ssid) != visible.end()){
            logMessage("Connecting to " + n.ssid);
            WiFi.begin(n.ssid.c_str(), n.pass.c_str());
            unsigned long start = millis();
            while(millis() - start < 10000 && WiFi.status() != WL_CONNECTED)
                delay(500);
            if(WiFi.status() == WL_CONNECTED) return;
        }
    }

    // ── remaining saved networks ─────────────────────────────────────────────
    logMessage("Attempting to connect to remaining saved networks");
    for(auto &n : savedNetworks){
        if(std::find(visible.begin(), visible.end(), n.ssid) != visible.end()){
            logMessage("Connecting to " + n.ssid);
            WiFi.begin(n.ssid.c_str(), n.pass.c_str());
            unsigned long start = millis();
            while(millis() - start < 10000 && WiFi.status() != WL_CONNECTED)
                delay(500);
            if(WiFi.status() == WL_CONNECTED) return;
        }
    }
}