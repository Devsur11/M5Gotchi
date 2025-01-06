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

void EapolSniffer::printMac(const uint8_t* mac) {
    for (int i = 0; i < 6; i++) {
        Serial.printf("%02X", mac[i]);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
}


void snifferCallbackDeauth(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  wifi_pkt_rx_ctrl_t ctrl = pkt->rx_ctrl;
  const uint8_t *frame = pkt->payload;
  const uint16_t frameControl = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);

  const uint8_t frameType = (frameControl & 0x0C) >> 2;
  const uint8_t frameSubType = (frameControl & 0xF0) >> 4;

  if (estUnPaquetEAPOL(pkt)) {
    Serial.println("EAPOL Detected !!!!");

    const uint8_t *receiverAddr = frame + 4;
    const uint8_t *senderAddr = frame + 10;

    Serial.print("Address MAC destination: ");
    printAddress(receiverAddr);
    Serial.print("Address MAC expedition: ");
    printAddress(senderAddr);

    enregistrerDansFichierPCAP(pkt, false);
    nombreDeEAPOL++;
    M5.Lcd.setCursor(M5.Display.width() - 36, 0);
    M5.Lcd.printf("H:");
    M5.Lcd.print(nombreDeHandshakes);
    if (nombreDeEAPOL < 99) {
      M5.Lcd.setCursor(M5.Display.width() - 36, 12);
    } else if (nombreDeEAPOL < 999) {
      M5.Lcd.setCursor(M5.Display.width() - 40, 12);
    } else {
      M5.Lcd.setCursor(M5.Display.width() - 52, 12);
    }
    M5.Lcd.printf("E:");
    M5.Lcd.print(nombreDeEAPOL);
  }

  if (frameType == 0x00 && frameSubType == 0x08) {
    const uint8_t *senderAddr = frame + 10; // Adresse source dans la trame beacon

    // Convertir l'adresse MAC en chaîne de caractères pour la comparaison
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
             senderAddr[0], senderAddr[1], senderAddr[2], senderAddr[3], senderAddr[4], senderAddr[5]);


    pkt->rx_ctrl.sig_len -= 4;  // Réduire la longueur du signal de 4 bytes
    enregistrerDansFichierPCAP(pkt, true);  // Enregistrer le paquet
  }

}

bool estUnPaquetEAPOL(const wifi_promiscuous_pkt_t* packet) {
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