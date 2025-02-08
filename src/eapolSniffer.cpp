#include "EapolSniffer.h"


bool SnifferBegin(int userChannel) {
  SD.begin();
    autoChannelSwitch = (userChannel == 0);

    // Set the initial channel
    currentChannel = autoChannelSwitch ? 1 : userChannel;

    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(SnifferCallbackDeauth);

    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    SnifferWritePcapHeader();
    return true;
}



void SnifferLoop() {
    static unsigned long lastSwitch = 0;
    unsigned long now = millis();

    // W trybie automatycznym przełącz kanał co 500 ms
    if (autoChannelSwitch && (now - lastSwitch > 500)) {
        SnifferSwitchChannel();
        lastSwitch = now;
    }
}


void SnifferPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  SnifferHandlePacket(buf, type);
}

void SnifferHandlePacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
        return; // Skip non-management or non-data packets
    }

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
/*
    if (len < 60) {
        Serial.println("Packet too short, skipping...");
        return; // Skip packets that are too short
    }
*/
    const uint8_t* payload = pkt->payload;
    uint16_t etherType = (payload[12] << 8) | payload[13]; // Extract EtherType

    if (etherType == 0x888E) {
        Serial.println("EAPOL packet detected!");
        SnifferWritePcapPacket(payload, len);

        // Save packet info
        if (packetInfoCount < 100) {
            memcpy(packetInfoTable[packetInfoCount].srcMac, payload + 10, 6); // Source MAC
            memcpy(packetInfoTable[packetInfoCount].destMac, payload + 4, 6); // Destination MAC
            packetInfoTable[packetInfoCount].fileName = pcapFileName;
            packetInfoCount++;
        } else {
            Serial.println("Packet info table full, skipping...");
        }
    } else {
        Serial.println("Non-EAPOL packet detected, skipping...");
    }
}



/*
void SnifferhandlePacket(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* hdr = pkt->payload;
    //Serial.println("Packet detected");

    if (type == WIFI_PKT_MGMT && hdr[0] == 0x88) { // EAPOL frame
        Serial.println("EAPOL detected");
        uint8_t* destMac = hdr + 4;
        uint8_t* srcMac = hdr + 10;

        // Zapis do tablicy packetInfoTable
        if (packetInfoCount < 100) { // Ograniczenie do 100 obiektów
            memcpy(packetInfoTable[packetInfoCount].srcMac, srcMac, 6);
            memcpy(packetInfoTable[packetInfoCount].destMac, destMac, 6);
            packetInfoTable[packetInfoCount].fileName = String(pcapFileName);
            packetInfoCount++;
        }

        // Tworzenie nowego pliku .pcap
        updatePcapFileName();

        File file = SD.open(pcapFileName, FILE_WRITE);
        if (file) {
            writePcapHeader();
            writePcapPacket(pkt->payload, pkt->rx_ctrl.sig_len);
            file.close();
        }
    }
}
*/
void SnifferWritePcapHeader() {
    struct {
        uint32_t magic_number = 0xa1b2c3d4;
        uint16_t version_major = 2;
        uint16_t version_minor = 4;
        uint32_t thiszone = 0;
        uint32_t sigfigs = 0;
        uint32_t snaplen = 0xffff;
        uint32_t network = 105;  // DLT_IEEE802_11
    } pcapHeader;

    File file = SD.open(pcapFileName, FILE_WRITE);
    if (file) {
        file.write((uint8_t*)&pcapHeader, sizeof(pcapHeader));
        file.close();
    }
}

void SnifferWritePcapPacket(const uint8_t* packet, uint32_t packet_length) {
    uint32_t timestamp = millis();
    uint32_t length = packet_length;

    File file = SD.open(pcapFileName, FILE_APPEND);
    if (file) {
        file.write((uint8_t*)&timestamp, sizeof(timestamp));
        file.write((uint8_t*)&timestamp, sizeof(timestamp));
        file.write((uint8_t*)&length, sizeof(length));
        file.write((uint8_t*)&length, sizeof(length));
        file.write(packet, packet_length);
        file.close();
    }
}

bool SnifferAddClient(const uint8_t* mac) {
    for (int i = 0; i < clientCount; i++) {
        if (memcmp(clients[i], mac, 6) == 0) {
            return false;
        }
    }

    if (clientCount < 50) {
        memcpy(clients[clientCount], mac, 6);
        clientCount++;
        return true;
    }
    return false;
}

void SnifferClearClients() {
    clientCount = 0;
}

int SnifferGetClientCount() {
    return packetInfoCount;
}

const uint8_t* SnifferGetClient(int index) {
    if (index >= 0 && index < clientCount) {
        return clients[index];
    }
    return nullptr; // Return null if index is out of bounds
}


void SnifferSwitchChannel() {
    if (autoChannelSwitch) {
        currentChannel++;
        if (currentChannel > 13) {
            currentChannel = 1; // Wracamy do kanału 1
        }
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("Switched to channel: %d\n", currentChannel);
    } else {
        esp_wifi_set_channel(userChannel, WIFI_SECOND_CHAN_NONE);
    }
}


void SnifferEnd() {
    // Wyłącz tryb promiscuous
    esp_wifi_set_promiscuous(false);

    // Wyłącz Wi-Fi
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);

    Serial.println("Sniffer and Wi-Fi have been turned off.");
}


void SnifferUpdatePcapFileName() {
    static int fileIndex = 0;
    snprintf(pcapFileName, sizeof(pcapFileName), "/eapol_%03d.pcap", fileIndex++);
}
const PacketInfo* SnifferGetPacketInfoTable() {
    return packetInfoTable;
}

void SnifferCallbackDeauth(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (isEAPOL(pkt)) {
        Serial.println("EAPOL Detected !!!!");

        // Use instance to access non-static members
        if (packetInfoCount < 100) {
            memcpy(packetInfoTable[packetInfoCount].srcMac, payload + 10, 6); // Source MAC
            memcpy(packetInfoTable[packetInfoCount].destMac, payload + 4, 6); // Destination MAC
            packetInfoTable[packetInfoCount].fileName = String(pcapFileName);
            packetInfoCount++;
        } else {
            Serial.println("Packet info table full, skipping...");
        }

        // Update PCAP file
        SnifferUpdatePcapFileName();
        File file = SD.open(pcapFileName, FILE_WRITE);
        if (file) {
            SnifferWritePcapHeader();
            SnifferWritePcapPacket(pkt->payload, len);
            file.close();
        }
    }
}

//HUGE Thanks to 7h30th3r0n3 for this function: https://github.com/7h30th3r0n3/Evil-M5Project

bool isEAPOL(const wifi_promiscuous_pkt_t* packet) {
  const uint8_t *payload = packet->payload;
  int len = packet->rx_ctrl.sig_len;

  // length check to ensure packet is large enough for EAPOL (minimum length)
  if (len < (24 + 8 + 4)) { // 24 bytes for the MAC header, 8 for LLC/SNAP, 4 for EAPOL minimum
    return false;
  }

  // check for LLC/SNAP header indicating EAPOL payload
  // LLC: AA-AA-03, SNAP: 00-00-00-88-8E for EAPOL
  if (payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03 &&
      payload[27] == 0x00 && payload[28] == 0x00 && payload[29] == 0x00 &&
      payload[30] == 0x88 && payload[31] == 0x8E) {
    return true;
  }

  // handle QoS tagging which shifts the start of the LLC/SNAP headers by 2 bytes
  // check if the frame control field's subtype indicates a QoS data subtype (0x08)
  if ((payload[0] & 0x0F) == 0x08) {
    // Adjust for the QoS Control field and recheck for LLC/SNAP header
    if (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03 &&
        payload[29] == 0x00 && payload[30] == 0x00 && payload[31] == 0x00 &&
        payload[32] == 0x88 && payload[33] == 0x8E) {
      return true;
    }
  }

  return false;
}
