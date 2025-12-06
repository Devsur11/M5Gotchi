#include "Arduino.h"
#include "WiFi.h"
#include "esp_wifi.h"
#include <vector>
#pragma once

struct wifiSpeedScan{
    String ssid;
    int rssi;
    int channel;
    bool secure;
    uint8_t bssid[6];
};

void addToWhitelist(const String &valueToAdd);
std::vector<String> parseWhitelist();
void pwnagothiLoop();
bool pwnagothiBegin();
void removeItemFromWhitelist(String valueToRemove);
void speedScanCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void speedScan();
void speedScanTestAndPrintResults();
void pwnagothiStealthLoop();
std::vector<wifiSpeedScan> getSpeedScanResults();