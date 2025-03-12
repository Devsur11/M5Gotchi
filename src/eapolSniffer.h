#include <stdint.h>
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include <SD.h>


bool isEAPOL(const wifi_promiscuous_pkt_t* packet);

struct PacketInfo {
    uint8_t srcMac[6];
    uint8_t destMac[6];
    String fileName; // Store the file name
};

int clientCount;
bool autoChannelSwitch;
int currentChannel;
PacketInfo packetInfoTable[100];
int packetInfoCount;
char pcapFileName[32];
uint8_t clients[50][6];
int userChannel;

// Function declarations
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
bool SnifferBegin(int userChannel);
void SnifferLoop();
int SnifferGetClientCount();
void SnifferSwitchChannel();
void SnifferEnd();
const PacketInfo* SnifferGetPacketInfoTable();
