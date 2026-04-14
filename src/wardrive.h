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

// Request structure for delegating wardrive CSV saves to the main UI (core 0)
struct WardriveSaveRequest {
    char filename[128];   // target file path (workspace-relative, starts with /)
    String body;          // CSV rows (one or multiple lines) to append
    bool ensureWigleHeader; // if true, write Wigle CSV header when creating new file
};

extern QueueHandle_t wardriveSaveQueue;

// Append one CSV row per network to an SD file using a recent GPS fix read from Serial2.
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// - filename: path on SD to append rows (default: "/M5Gotchi/wardrive.csv")
// Returns true if at least one row was written successfully.
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs);

void startWardriveSession(unsigned long gpsTimeoutMs);

bool uploadToWigle(const String& encodedToken, const char* csvPath, int* outHttpCode = nullptr);

void waitUntillLock();

// Wait for a GPS fix on the provided RX/TX pins. Returns true if a valid fix
// was seen within timeoutMs milliseconds, false otherwise. This is intended
// for validating user-provided GPS pin settings before persisting them.
bool waitForGpsLock(int rxPin, int txPin, unsigned long timeoutMs);
#endif // ESPBLASTER_WARDRIVE_H