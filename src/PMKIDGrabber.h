#pragma once
#include <Arduino.h>
#include <WiFi.h>

bool runPMKIDAttack(const uint8_t *apBSSID, int channel);
void attackLoop();
void attackSetup();