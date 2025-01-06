#include "eapolSniffer.h"

void EapolSniffer::handlePacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;

    // Extract frame control fields
    uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    uint8_t frameType = (frameControl & 0x0C) >> 2;
    uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    // Handle EAPOL frames
    if (isEapolFrame(frame)) {
        processEapolFrame(pkt);
    }

    // Handle Beacon frames
    if (frameType == 0x00 && frameSubType == 0x08) { // Beacon frame
        processBeaconFrame(pkt);
    }
}

bool EapolSniffer::isEapolFrame(const uint8_t* frame) {
    // EAPOL EtherType is 0x888E
    uint16_t etherType = (frame[12] << 8) | frame[13];
    return etherType == 0x888E;
}

void EapolSniffer::processEapolFrame(const wifi_promiscuous_pkt_t* pkt) {
    const uint8_t* frame = pkt->payload;
    const uint8_t* receiverAddr = frame + 4;
    const uint8_t* senderAddr = frame + 10;

    // Log the EAPOL frame
    Serial.println("EAPOL frame detected!");
    Serial.print("Destination MAC: ");
    printMac(receiverAddr);
    Serial.print("Source MAC: ");
    printMac(senderAddr);

    // Save the EAPOL frame to PCAP
    writePcapPacket(pkt, false);

    // Add to PacketInfo table
    if (packetInfoCount < MAX_PACKET_INFO) {
        PacketInfo& info = packetInfoTable[packetInfoCount++];
        memcpy(info.receiverMac, receiverAddr, 6);
        memcpy(info.senderMac, senderAddr, 6);
        info.packetType = "EAPOL";
        snprintf(info.fileName, sizeof(info.fileName), "%s", currentPcapFileName.c_str());
    }
}

void EapolSniffer::processBeaconFrame(const wifi_promiscuous_pkt_t* pkt) {
    const uint8_t* frame = pkt->payload;
    const uint8_t* senderAddr = frame + 10;

    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);

    Serial.print("Beacon frame detected from: ");
    Serial.println(macStr);

    // Save Beacon frame to PCAP
    writePcapPacket(pkt, true);

    // Add to PacketInfo table
    if (packetInfoCount < MAX_PACKET_INFO) {
        PacketInfo& info = packetInfoTable[packetInfoCount++];
        memcpy(info.senderMac, senderAddr, 6);
        info.packetType = "Beacon";
        snprintf(info.fileName, sizeof(info.fileName), "%s", currentPcapFileName.c_str());
    }
}

void EapolSniffer::printMac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        Serial.printf("%02X", mac[i]);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
}
