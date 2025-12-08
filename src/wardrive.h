#ifndef ESPBLASTER_WARDRIVE_H
#define ESPBLASTER_WARDRIVE_H

#include <Arduino.h>
#include <vector>
#include "pwnagothi.h"

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

// Append one CSV row per network to an SD file using a recent GPS fix read from Serial2.
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// - filename: path on SD to append rows (default: "/wardrive.csv")
// Returns true if at least one row was written successfully.
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs);

void startWardriveSession(unsigned long gpsTimeoutMs);

bool uploadToWigle(const String& encodedToken, const char* csvPath, int* outHttpCode = nullptr);

#endif // ESPBLASTER_WARDRIVE_H