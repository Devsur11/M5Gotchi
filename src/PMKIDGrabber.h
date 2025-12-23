#pragma once
#include <Arduino.h>
#include <WiFi.h>

bool GrabPMKIDForAP(const uint8_t *apBSSID, int channel, int timeoutMs);
static void writePMKID(const uint8_t *bssid, const uint8_t *pmkid);
static void genClientMAC();
static void setTarget(const uint8_t *bssid);
static void writePMKID(const uint8_t *bssid, const uint8_t *pmkid);
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
