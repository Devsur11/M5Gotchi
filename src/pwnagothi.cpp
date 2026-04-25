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
#define CHANEL_HOP_INTERVAL_MS 200

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

void handleFileWrite(FileWriteRequest *req) {
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
    drawInfoBox("GPS locking", "Waiting for GPS lock...", "This may take a while.", false, false); 
    waitUntillLock();
    pwn::beginWardriving();
    logMessage("Pwnagothi auto mode init!");
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
                    tot_happy_epochs += wd.networksLogged;
                    lastSessionPeers = getPwngridTotalPeers();
                    lastSessionTime = millis();
                    allTimeEpochs += wd.networksLogged;
                } else {
                    logMessage("Wardrive: GPS not acquired or failed");
                    lastSessionTime = millis();
                }
            } else {
                tot_sad_epochs++;
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
        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            std::vector<wifiRTResults> localResults = g_wifiRTResults;
            xSemaphoreGive(wifiResultsMutex);
            tot_happy_epochs += localResults.size() / 2;
            attackTask(nullptr);

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
        vTaskDelay(10 / portTICK_PERIOD_MS);
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
    if(std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) != pwnedAPs.end()){
        return;
    }
    logMessage("Scoring AP: " + ap.ssid);
    if(random(0,100)<30){
        setMoodApSelected(ap.ssid);
    }
    else if(random(0, 10)<2){
        setMoodHappy();
    }
    else if(random(0, 10)<2){
        setMoodLooking(5);
    }
    else{
        setMoodSleeping();
    }
    if(halfScore<=10){
        halfScore++;
        pwnedAPs.push_back(ap.ssid);
        logMessage("AP " + ap.ssid + " added to pwned list. Half score: " + String(halfScore));
    }
    else{
        pwned_ap++;
        sessionCaptures++;
        setMoodToNewHandshake(1);
        halfScore = 0;
        pwnedAPs.push_back(ap.ssid);
        logMessage("AP " + ap.ssid + " fully pwned! Total pwned APs: " + String(pwned_ap));
    }
    if(pwnedAPs.size() > 500){
        //clear the list to save memory, but keep the count
        pwnedAPs.clear();
        pwnedAPs.shrink_to_fit();
        logMessage("Pwned AP list cleared to save memory.");
    }
}