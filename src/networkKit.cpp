#include "WString.h"
#include "M5Cardputer.h"
#include "ui.h"
#include "src.h"
#include "WiFi.h"
#include "networkKit.h"         

extern "C" {
#include "esp_wifi.h"
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
}

// Main function with non-constant SSID list passed as an argument
void broadcastFakeSSIDs(String ssidList[], int ssidCount, bool sound) {
  // Configuration
  const uint8_t channels[] = {1, 6, 11}; // Wi-Fi channels to broadcast on
  const bool wpa2 = true; // WPA2-enabled networks
  const bool appendSpaces = true; // Add spaces to SSIDs to make them 32 characters long
  bool keyboard_changed;

  // Initialize variables
  char emptySSID[32];
  uint8_t channelIndex = 0;
  uint8_t macAddr[6];
  uint8_t wifi_channel = 1;
  uint32_t currentTime = 0;
  uint32_t packetSize = 0;
  uint32_t packetCounter = 0;
  uint32_t attackTime = 0;
  uint32_t packetRateTime = 0;

  // Beacon packet template
  uint8_t beaconPacket[109] = {
    /*  0 - 3  */ 0x80, 0x00, 0x00, 0x00, // Type/Subtype: management beacon frame
    /*  4 - 9  */ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: broadcast
    /* 10 - 15 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Source MAC (randomized later)
    /* 16 - 21 */ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // BSSID (same as Source MAC)
    /* 22 - 23 */ 0x00, 0x00, // Fragment & sequence number (done by SDK)
    /* 24 - 31 */ 0x83, 0x51, 0xf7, 0x8f, 0x0f, 0x00, 0x00, 0x00, // Timestamp
    /* 32 - 33 */ 0xe8, 0x03, // Interval (1s)
    /* 34 - 35 */ 0x31, 0x00, // Capabilities Information (set later)
    /* 36 - 37 */ 0x00, 0x20, // SSID tag and length (32 bytes)
    /* 38 - 69 */ 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
                 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, // SSID (empty by default)
    /* 70 - 71 */ 0x01, 0x08, // Supported Rates tag and length
    /* 72 - 79 */ 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c, // Supported Rates
    /* 80 - 81 */ 0x03, 0x01, // DS Parameter Set tag and length (Channel)
    /* 82 */      0x01,       // Current Channel (set later)
    /* 83 - 108*/ 0x30, 0x18, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
                 0x02, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x00, 0x0f, 0xac, 
                 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00 // RSN Information (WPA2)
  };

  // Prepare empty SSID with spaces
  for (int i = 0; i < 32; i++) {
    emptySSID[i] = ' ';
  }

  // Set packet size depending on WPA2 status
  packetSize = sizeof(beaconPacket);
  if (!wpa2) {
    beaconPacket[34] = 0x21; // Change capabilities for non-WPA2
    packetSize -= 26; // Reduce packet size by removing RSN Information
  }

  // Generate random MAC address
  auto randomMac = [&macAddr]() {
    for (int i = 0; i < 6; i++) {
      macAddr[i] = random(256);
    }
  };

  // Function to switch to the next channel
  auto nextChannel = [&wifi_channel, &channelIndex, &channels]() {
    if (sizeof(channels) > 1) {
      uint8_t ch = channels[channelIndex];
      channelIndex = (channelIndex + 1) % (sizeof(channels));
      wifi_channel = ch;
      esp_wifi_set_channel(wifi_channel, WIFI_SECOND_CHAN_NONE);
    }
  };

  // Begin setup: Serial communication, set Wi-Fi mode, randomize MAC, etc.
  Serial.println("Hello, NodeMCU! Broadcasting fake SSIDs...");

  WiFi.mode(WIFI_MODE_STA); // Set to station mode

  // Set initial Wi-Fi channel
  esp_wifi_set_channel(channels[0], WIFI_SECOND_CHAN_NONE);

  // Main broadcast loop
  while (true) {
    M5.update();
    M5Cardputer.update();
    if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){return ;}
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    currentTime = millis();

    if (currentTime - attackTime > 100) { // Repeat every 100 ms
      attackTime = currentTime;

      // Move to the next channel
      nextChannel();

      for (int ssidIndex = 0; ssidIndex < ssidCount; ssidIndex++) {
        //if(ssidList[ssidIndex].compareTo("")){ssidIndex++;}
        String ssid = ssidList[ssidIndex];
        int ssidLen = ssid.length();

        // Randomize MAC address for each SSID
        randomMac();
        macAddr[5] = ssidIndex;

        // Copy MAC address into the beacon packet
        memcpy(&beaconPacket[10], macAddr, 6);
        memcpy(&beaconPacket[16], macAddr, 6);

        // Reset the SSID in the packet to spaces
        memcpy(&beaconPacket[38], emptySSID, 32);

        // Copy the actual SSID into the beacon frame
        memcpy(&beaconPacket[38], ssid.c_str(), ssidLen);

        // Set the current channel in the beacon frame
        beaconPacket[82] = wifi_channel;

        // Send the beacon packet
        if (appendSpaces) {
          for (int k = 0; k < 3; k++) {
            packetCounter += esp_wifi_80211_tx(WIFI_IF_STA, beaconPacket, packetSize, 0) == 0;
            delay(1);
          }
        } else {
          uint16_t tmpPacketSize = (109 - 32) + ssidLen;
          uint8_t* tmpPacket = new uint8_t[tmpPacketSize];

          // Copy the first part of the beacon packet
          memcpy(&tmpPacket[0], &beaconPacket[0], 37 + ssidLen);
          tmpPacket[37] = ssidLen; // Update SSID length
          memcpy(&tmpPacket[38 + ssidLen], &beaconPacket[70], 39);

          for (int k = 0; k < 3; k++) {
            packetCounter += esp_wifi_80211_tx(WIFI_IF_STA, tmpPacket, tmpPacketSize, 0) == 0;
            delay(1);
          }

          delete tmpPacket;
        }
      }
    }

    // Output packet rate every second
    if (currentTime - packetRateTime > 1000) {
      packetRateTime = currentTime;
      drawInfoBox("Beacon spam", "Packets/sec: " + String(packetCounter) , "Press ENTER to stop", false, false);
      Serial.print("Packets/s: ");
      Serial.println(packetCounter);
      packetCounter = 0;
    }
  }
}
