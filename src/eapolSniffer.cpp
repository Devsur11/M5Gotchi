#include "EapolSniffer.h"

EapolSniffer* EapolSniffer::instance = nullptr;

EapolSniffer::EapolSniffer() 
    : clientCount(0), currentChannel(1), userChannel(0), autoChannelSwitch(false), packetInfoCount(0) {
    memset(clients, 0, sizeof(clients));
    memset(packetInfoTable, 0, sizeof(packetInfoTable));
    updatePcapFileName(); // Ustaw pierwszy plik .pcap
}


bool EapolSniffer::begin(int userChannel) {
    this->userChannel = userChannel;
    autoChannelSwitch = (userChannel == 0);

    // Ustawienie początkowego kanału
    currentChannel = autoChannelSwitch ? 1 : userChannel;

    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuousCallback);

    // Ustaw kanał w trybie ręcznym lub rozpocznij automatyczne przełączanie
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    writePcapHeader();
    return true;
}


void EapolSniffer::loop() {
    static unsigned long lastSwitch = 0;
    unsigned long now = millis();

    // W trybie automatycznym przełącz kanał co 500 ms
    if (autoChannelSwitch && (now - lastSwitch > 500)) {
        switchChannel();
        lastSwitch = now;
    }
}


void EapolSniffer::promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  //Serial.println("Packet");
    //if (instance) {
        instance->handlePacket(buf, type);
        //Serial.println("Called");
    //}
}

void EapolSniffer::handlePacket(void* buf, wifi_promiscuous_pkt_type_t type) {
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
        while(true){};
        writePcapPacket(payload, len);

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
void EapolSniffer::handlePacket(void* buf, wifi_promiscuous_pkt_type_t type) {
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
void EapolSniffer::writePcapHeader() {
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

void EapolSniffer::writePcapPacket(const uint8_t* packet, uint32_t packet_length) {
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

bool EapolSniffer::addClient(const uint8_t* mac) {
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

void EapolSniffer::clearClients() {
    clientCount = 0;
}

int EapolSniffer::getClientCount() const {
    return clientCount;
}

const uint8_t* EapolSniffer::getClient(int index) const {
    if (index >= 0 && index < clientCount) {
        return clients[index];
    }
    return nullptr; // Return null if index is out of bounds
}


void EapolSniffer::switchChannel() {
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


void EapolSniffer::end() {
    // Wyłącz tryb promiscuous
    esp_wifi_set_promiscuous(false);

    // Wyłącz Wi-Fi
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);

    Serial.println("Sniffer and Wi-Fi have been turned off.");
}


void EapolSniffer::updatePcapFileName() {
    static int fileIndex = 0;
    snprintf(pcapFileName, sizeof(pcapFileName), "/eapol_%03d.pcap", fileIndex++);
}
const PacketInfo* EapolSniffer::getPacketInfoTable() const {
    return packetInfoTable;
}
