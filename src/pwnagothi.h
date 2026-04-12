#include "Arduino.h"
#include "WiFi.h"
#include "esp_wifi.h"
#include <vector>
#pragma once

//idk what df Im doing
struct wifiSpeedScan{
    String ssid;
    int rssi;
    int channel;
    bool secure;
    uint8_t bssid[6];
};
struct FileWriteRequest;
extern QueueHandle_t fileWriteQueue;
void handleFileWrite(FileWriteRequest* req);
struct wifiRTResults{
    String ssid;
    int rssi;
    int channel;
    bool secure;
    uint8_t bssid[6];
    long lastSeen;
};
extern std::vector<wifiRTResults> g_wifiRTResults;
extern wifiRTResults ap; //network being currently attacked
extern TaskHandle_t pwnagotchiTaskHandle;
extern TaskHandle_t wardrivingTaskHandle;
void addToWhitelist(const String &valueToAdd);
std::vector<String> parseWhitelist();
void removeItemFromWhitelist(String valueToRemove);
void legacyLoop();

//legacy - kept for wardriving
std::vector<wifiSpeedScan> getSpeedScanResults();
void speedScan();

namespace pwn {
    bool begin();
    bool end();
    bool beginWardriving();
}

void task(void *parameter);
void attackTask(void *parameter);
void wardrivingTask(void *parameter);