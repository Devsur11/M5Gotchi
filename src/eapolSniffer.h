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
bool SnifferBegin(int userChannel);
void SnifferLoop();
void SnifferHandlePacket(void* buf, wifi_promiscuous_pkt_type_t type);
void SnifferWritePcapHeader();
void SnifferWritePcapPacket(const uint8_t* packet, uint32_t packet_length);
bool SnifferAddClient(const uint8_t* mac);
void SnifferClearClients();
int SnifferGetClientCount();
const uint8_t* SnifferGetClient(int index);
void SnifferSwitchChannel();
void SnifferEnd();
void SnifferUpdatePcapFileName();
const PacketInfo* SnifferGetPacketInfoTable();
void SnifferCallbackDeauth(void* buf, wifi_promiscuous_pkt_type_t type);
bool isEAPOL(const wifi_promiscuous_pkt_t* packet);

