#include "Arduino.h"
#include "WiFi.h"
#include "esp_wifi.h"
#include <vector>
#pragma once

void addToWhitelist(const String &valueToAdd);
std::vector<String> parseWhitelist();
void pwnagothiLoop();
bool pwnagothiBegin();
void removeItemFromWhitelist(String valueToRemove);
void speedScanCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void speedScan();
void speedScanTestAndPrintResults();