#pragma once
#include <Arduino.h>
#include <WiFi.h>

bool GrabPMKIDForAP(const uint8_t* apBSSID, const String& ssid, int channel, int attempts = 20, int delayMs = 5, int timeoutMs = 5000);
