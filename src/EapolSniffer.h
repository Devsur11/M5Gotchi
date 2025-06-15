#include <stdint.h>
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include <SD.h>
#pragma once
#include "logger.h"
bool isEAPOL(const wifi_promiscuous_pkt_t* packet);

struct PacketInfo {
    uint8_t srcMac[6];
    uint8_t destMac[6];
    String fileName; // Store the file name
};


// Function declarations
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
bool SnifferBegin(int userChannel, bool skipSDCardCheck = false /*ONLY For debugging purposses*/);;
void SnifferLoop();
int SnifferGetClientCount();
void SnifferSwitchChannel();
void SnifferEnd();
const PacketInfo* SnifferGetPacketInfoTable();
void SnifferDebugMode();
String getSSIDFromMac(const uint8_t* mac);
bool isNewHandshake();