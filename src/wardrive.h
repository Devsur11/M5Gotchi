#ifndef ESPBLASTER_WARDRIVE_H
#define ESPBLASTER_WARDRIVE_H
#include <Arduino.h>
#include <vector>
#include "pwnagothi.h"
#include "freertos/FreeRTOS.h"

extern SemaphoreHandle_t wardriveMutex;
struct wardriveStatus{
    bool success;
    bool gpsFixAcquired;
    double latitude;
    double longitude;
    double hdop;
    double altitude;
    String timestampIso;
    uint16_t networksLogged;
    uint8_t networksNow;
};
struct WigleEntry {
    String bssid;
    String ssid;
    String capabilities;
    String firstSeen;
    int channel;
    int frequency;
    int rssi;
    double lat;
    double lon;
    double alt;
    double accuracy;
    String rcois;
    String mfgid;
    String type;
};
struct WardriveSaveRequest {
    char filename[128];
    String body;         
    bool ensureWigleHeader;
};
extern QueueHandle_t wardriveSaveQueue;
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs);
void startWardriveSession(unsigned long gpsTimeoutMs);
bool uploadToWigle(const String& encodedToken, const char* csvPath, int* outHttpCode = nullptr);
void waitUntillLock();
bool waitForGpsLock(int rxPin, int txPin, unsigned long timeoutMs);

#endif