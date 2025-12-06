// /home/devsur/Github/ESPBlaster/src/wardrive.h
//
// Header for wardrive.cpp
// See wardrive.cpp for implementation and usage notes.

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
    float hdop;
    float altitude;
    String timestampIso;
    uint16_t networksLogged;
    uint8_t networksNow;
};

// Append one CSV row per network to an SD file using a recent GPS fix read from Serial2.
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// - filename: path on SD to append rows (default: "/wardrive.csv")
// Returns true if at least one row was written successfully.
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks,
              unsigned long timeoutMs = 10000,
              const char* filename = "/wardrive.csv");

#endif // ESPBLASTER_WARDRIVE_H