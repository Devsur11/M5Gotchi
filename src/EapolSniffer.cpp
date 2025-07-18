#include "EapolSniffer.h"
#include <map>
#include "src.h"
#include "settings.h"

long lastpacketsend;
File file;
File currentPcapFile;
int clientCount;
bool autoChannelSwitch;
int currentChannel;
PacketInfo packetInfoTable[100];
int packetInfoCount;
char pcapFileName[32];
uint8_t clients[50][6];
int userChannel;
const unsigned long HANDSHAKE_TIMEOUT = 5000;

struct pcap_hdr_s {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
} __attribute__((packed));

struct pcaprec_hdr_s {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
} __attribute__((packed));

typedef struct {
  size_t    len;
  uint8_t  *data;
  uint32_t  ts_sec;
  uint32_t  ts_usec;
} CapturedPacket;

QueueHandle_t packetQueue;
volatile uint32_t packetCount = 0;

uint32_t handshakeFileCount = 0;
unsigned long lastHandshakeMillis = 0;
const unsigned long handshakeTimeout = 5000;

struct APFileContext {
  String apName;
  File file;
};

std::map<String, APFileContext> apFiles;

void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) {
    return;
  }

  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  const uint8_t* payload = pkt->payload;

  if (!((payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03) ||
        (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03))) {
    return;
  }

  logMessage("EAPOL Detected");
  if (len == 0 || len > MAX_PKT_SIZE) return;

  CapturedPacket *p = (CapturedPacket*) malloc(sizeof(CapturedPacket));
  if (!p) return;
  p->data = (uint8_t *) malloc(len);
  if (!p->data) {
    free(p);
    return;
  }

  memcpy(p->data, pkt->payload, len);
  p->len = len;

  uint64_t ts = esp_timer_get_time();
  p->ts_sec = ts / 1000000;
  p->ts_usec = ts % 1000000;

  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xQueueSendFromISR(packetQueue, &p, &xHigherPriorityTaskWoken);
  if (xHigherPriorityTaskWoken) {
    portYIELD_FROM_ISR();
  }
}

bool SnifferBegin(int userChannel, bool skipSDCardCheck /*ONLY For debugging purposses*/) {
  autoChannelSwitch = (userChannel == 0);
  currentChannel = autoChannelSwitch ? 1 : userChannel;
  if(!skipSDCardCheck) {
    if (!SD.begin(SD_CS, sdSPI, 1000000)) {
      logMessage("SD card init failed");
      return false;
    }
    File testFile = SD.open("/test_write.txt", FILE_WRITE);
    if (testFile) {
      testFile.println("Test OK");
      testFile.close();
      logMessage("Test file written.");
    } else {
      logMessage("Failed to write test file.");
      return false;
    }
  } else {
    logMessage("Skipping SD card check for debugging purposes.");
  }

  packetQueue = xQueueCreate(32, sizeof(CapturedPacket*));
  if (packetQueue == NULL) {
    logMessage("Packet queue creation failed");
    return false;
  }
  
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
  return true;
}

char apName[18];

void SnifferLoop() {
  CapturedPacket *packet = NULL;
  if (xQueueReceive(packetQueue, &packet, 10 / portTICK_PERIOD_MS) == pdTRUE) {
    
    //strncpy(apName, getSSIDFromMac(packet->data + 10).c_str(), sizeof(apName) - 1);  <- too long for the buffer
    //apName[sizeof(apName) - 1] = '\0';
    //sprintf(apName, "%02X_%02X_%02X_%02X_%02X_%02X",
    //        packet->data[10], packet->data[11], packet->data[12],
    //        packet->data[13], packet->data[14], packet->data[15]);
    
    String apKey = String(apName);
    ///<> is statment controling when new file will be created
    if (isNewHandshake()) {
      delay(1000); // <- delay for making sure none of the packets are missing fue to recierving turned off
      strncpy(apName, getSSIDFromMac(packet->data + 10).c_str(), sizeof(apName) - 1);
      apName[sizeof(apName) - 1] = '\0';
      char filename[64];
      snprintf(filename, sizeof(filename), "/handshake/handshake_%s_ID_%i.pcap", apName, random(999));

      if (!SD.exists("/handshake")) {
        SD.mkdir("/handshake");
      }

      file = SD.open(filename, FILE_WRITE, true);
      if (!file) {
        logMessage("[ERROR] fopen failed: " + String(filename));
        free(packet->data);
        free(packet);
        return;
      }

      pcap_hdr_s globalHeader;
      globalHeader.magic_number = 0xa1b2c3d4;
      globalHeader.version_major = 2;
      globalHeader.version_minor = 4;
      globalHeader.thiszone = 0;
      globalHeader.sigfigs = 0;
      globalHeader.snaplen = 65535;
      globalHeader.network = 105;
      file.write((uint8_t*)&globalHeader, sizeof(globalHeader));
      file.flush();

      apFiles[apKey] = {apKey, file};
      logMessage("New handshake file created: " + String(filename));
      if (packetCount < 100) {
        memcpy(packetInfoTable[packetCount].srcMac, packet->data + 10, 6);
        memcpy(packetInfoTable[packetCount].destMac, packet->data + 4, 6);
        packetInfoTable[packetCount].fileName = String(apName);
        packetCount++;
        logMessage("Packet info added to table: " + String(packetCount));
      } else {
        logMessage("Packet info table full, skipping...");
      } 
    }

    //File &file = apFiles[apKey].file;
    logMessage("Processing packet for AP: " + String(apName));

    pcaprec_hdr_s recHeader;
    recHeader.ts_sec   = packet->ts_sec;
    recHeader.ts_usec  = packet->ts_usec;
    recHeader.incl_len = packet->len;
    recHeader.orig_len = packet->len;

    file.write((uint8_t*)&recHeader, sizeof(recHeader));
    logMessage("Adding packet header to file for AP: " + String(apName));
    file.write(packet->data, packet->len);
    logMessage("Packet data written to file for AP: " + String(apName));
    file.flush();
    logMessage("flush() called for file: " + String(apName));

    lastHandshakeMillis = millis();
    free(packet->data);
    free(packet);
    
  }

  static unsigned long lastSwitch = 0;
  unsigned long now = millis();
  if (autoChannelSwitch && (now - lastSwitch > 500)) {
    SnifferSwitchChannel();
    lastSwitch = now;
  }
}

int SnifferGetClientCount() {
    return packetCount;
}

void SnifferSwitchChannel() {
    if (autoChannelSwitch) {
        currentChannel++;
        if (currentChannel > 13) {
            currentChannel = 1;
        }
        esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
        Serial.printf("Switched to channel: %d\n", currentChannel);
    } else {
        esp_wifi_set_channel(userChannel, WIFI_SECOND_CHAN_NONE);
    }
}

void SnifferEnd() {
    esp_wifi_set_promiscuous(false);
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);

    for (auto &entry : apFiles) {
      if (entry.second.file) {
        entry.second.file.close();
      }
    }

    apFiles.clear();

    logMessage("Sniffer and Wi-Fi have been turned off.");
}

const PacketInfo* SnifferGetPacketInfoTable() {
    return packetInfoTable;
}

void SnifferDebugMode(){
  delay(10000);
  SnifferBegin(6, true);
  logMessage("Sniffer started in debug mode on channel 6.");
  while (true) {
    SnifferLoop();
  }
}

String getSSIDFromMac(const uint8_t* mac) {
    logMessage("Searching SSID for MAC: " + String(mac[0], HEX) + ":" + String(mac[1], HEX) + ":" +
               String(mac[2], HEX) + ":" + String(mac[3], HEX) + ":" + String(mac[4], HEX) + ":" + String(mac[5], HEX));
    char ssid[18];
    esp_wifi_set_promiscuous(false);
    WiFi.mode(WIFI_STA);
    WiFi.scanNetworks(true);
    while(WiFi.scanComplete() == WIFI_SCAN_RUNNING) {
        delay(10);
    }
    int numNetworks = WiFi.scanComplete();
    if (numNetworks < 0) {
        logMessage("WiFi scan failed");
        WiFi.mode(WIFI_STA);
        esp_wifi_set_promiscuous(true);
        return String();
    }
    for (int i = 0; i < numNetworks; i++) {
        if (memcmp(WiFi.BSSID(i), mac, 6) == 0) {
            WiFi.SSID(i).toCharArray(ssid, sizeof(ssid));
            WiFi.mode(WIFI_STA);
            esp_wifi_set_promiscuous(true);
            return String(ssid);
        }
    }
    logMessage("SSID not found for MAC: " + String(mac[0], HEX) + ":" + String(mac[1], HEX) + ":" +
               String(mac[2], HEX) + ":" + String(mac[3], HEX) + ":" + String(mac[4], HEX) + ":" + String(mac[5], HEX));
    WiFi.mode(WIFI_STA);
    esp_wifi_set_promiscuous(true);
    return String(ssid);
}

bool isNewHandshake(){
  unsigned long currentMillis = millis();
  if (currentMillis - lastHandshakeMillis > HANDSHAKE_TIMEOUT) {
    lastHandshakeMillis = currentMillis;
    return true;
  }
  return false;
}