#include <stdint.h>
#include <Arduino.h>
#include <WiFi.h>
#include <esp_wifi.h>
#include <cstring>
#include <SD.h>

#ifndef EAPOL_SNIFFER_H
#define EAPOL_SNIFFER_H


struct PacketInfo {
    uint8_t srcMac[6];
    uint8_t destMac[6];
    String fileName; // Store the file name
};

class EapolSniffer {
public:
    EapolSniffer();

    bool begin(int userChannel = 0);
    void loop();
    void end();
    void clearClients();
    int getClientCount() const;
    const uint8_t* getClient(int index) const; // Added declaration
    const PacketInfo* getPacketInfoTable() const;

private:
    static void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    void handlePacket(void* buf, wifi_promiscuous_pkt_type_t type);
    void writePcapHeader();
    void writePcapPacket(const uint8_t* packet, uint32_t packet_length);
    bool addClient(const uint8_t* mac);
    void switchChannel();
    void updatePcapFileName();

    static EapolSniffer* instance;

    char pcapFileName[32];
    uint8_t clients[50][6];
    int clientCount;
    PacketInfo packetInfoTable[100];
    int packetInfoCount; // Keep track of added PacketInfo
    int currentChannel;
    int userChannel;
    bool autoChannelSwitch;
};

#endif
