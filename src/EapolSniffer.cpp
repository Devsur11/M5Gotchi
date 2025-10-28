#include "networkKit.h"
#include "EapolSniffer.h"
#include <map>
#include "src.h"
#include "settings.h"
#include "pwnagothi.h"

long lastpacketsend;
File file;
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
unsigned long lastHandshakeMillis = 0;
const unsigned long handshakeTimeout = 5000;
uint8_t eapolCount = 0; // count EAPOL frames in sequence

struct APFileContext {
  String apName;
  File file;
};

bool beaconDetected = false;
const uint8_t* beaconFrame;
uint16_t beaconFrameLen = 0;
std::map<String, APFileContext> apFiles;
bool targetAPSet = false;
uint8_t targetBSSID[6];

void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) {
        return;
    }

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    const uint8_t *payload = pkt->payload;

    if (len < 24) return; // too short for frame control + MAC header

    // ---- Parse frame control ----
    uint16_t fc = payload[0] | (payload[1] << 8);
    uint8_t ftype    = (fc >> 2) & 0x3;   // 0=mgmt,1=ctrl,2=data
    uint8_t fsubtype = (fc >> 4) & 0xF;

    // ---- Extract BSSID from beacon ----
    // In beacon frame: BSSID = addr3 = offset 16..21
    const uint8_t *beaconBSSID = &beaconFrame[16];

    // ---- Detect beacon ----
    if (ftype == 0 && fsubtype == 8 && !beaconDetected) { // mgmt + beacon
        if (targetAPSet) {
            // BSSID in beacon frame is addr3 at offset 16..21
            const uint8_t *bssid = &payload[16];
            if (memcmp(bssid, targetBSSID, 6) != 0) {
                logMessage("Ignoring beacon from non-target AP.");
                return; // not the targeted AP
            }
        }
        if (!beaconDetected) {
            beaconDetected = true;
            logMessage("Beacon frame detected.");

            // Real beacon length = len - 4 (ESP32 adds ghost 4 bytes)
            uint16_t beaconLen = (len > 4) ? len - 4 : len;

            beaconFrame = (uint8_t *) malloc(beaconLen);
            if (!beaconFrame) return;
            memcpy((void*)beaconFrame, payload, beaconLen);
            beaconFrameLen = beaconLen; // save corrected length
        }
        return; // skip further processing
    }

    // ---- Only continue if beacon captured ----
    if (!beaconDetected) return;

    

    // ---- Look for EAPOL ----
    if (len >= 32) {
        // EAPOL header signature
        if ((payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03) ||
            (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03)) {

            // ---- Extract source/dest BSSID to match ----
            // In data frames: addr1 = dst, addr2 = src, addr3 = BSSID
            const uint8_t *pktBSSID = &payload[16];
            logMessage("EAPOL Source:" + macToString(pktBSSID));

            if (memcmp(pktBSSID, beaconBSSID, 6) != 0) {
                logMessage("EAPOL Detected, but bssids do not match.");
                return; // not our AP
            }

            logMessage("EAPOL Detected");
            
            eapolCount = eapolCount + getEAPOLOrder((uint8_t*)payload);
            logMessage("EAPOL count: " + String(eapolCount));
            if (len == 0 || len > MAX_PKT_SIZE) return;

            CapturedPacket *p = (CapturedPacket*) malloc(sizeof(CapturedPacket));
            if (!p) return;
            p->data = (uint8_t *) malloc(len);
            if (!p->data) {
                free(p);
                return;
            }

            memcpy(p->data, payload, len);
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
    }
}

void setTargetAP(uint8_t* bssid) {
    logMessage("Target for sniffer set to: " + macToString(bssid));
    memcpy(targetBSSID, bssid, 6);
    targetAPSet = true;
}

void clearTargetAP() {
    logMessage("Target for sniffer cleared");
    memset(targetBSSID, 0, 6);
    targetAPSet = false;
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
  esp_wifi_set_promiscuous_filter(nullptr); // no filter
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
  logMessage("Activating Sniffer or chanel: " + String(userChannel));
  return true;
}

char apName[18];

uint8_t* savedPackets[10];
int savedPacketCount = 0;

int SnifferPendingPackets() {
    return uxQueueMessagesWaiting(packetQueue);
}

void SnifferLoop() {
    // persistent lengths for cached packets to ensure correct write sizes
    static size_t savedPacketLens[10] = {0};

    CapturedPacket *packet = NULL;
    if (xQueueReceive(packetQueue, &packet, 10 / portTICK_PERIOD_MS) == pdTRUE) {
        String apKey = String(apName);
        logMessage("Processing captured packet for AP");
        //logMessage(String(isNewHandshake()) + ", for new file");
        if (isNewHandshake()) { 
            logMessage("New handshake sequence detected.");
            // at least Msg1 + Msg2 captured before saving
            if (!skip_eapol_check){
                if (!(eapolCount >= 10)){ //msg1 + msg2 + msg3 + msg4 = 10
                    vTaskDelay(3000 / portTICK_PERIOD_MS);
                    if(!(eapolCount >= 10)){
                        eapolCount = 0; // reset for next sequence
                        logMessage("Incomplete handshake sequence, skipping...");
                        free(packet->data);
                        free(packet);

                        return;
                    }
                }
            }
            else{
                logMessage("Skipping EAPOL check as per settings.");
            }
            logMessage("Complete handshake sequence captured. Proceeding to save.");
            vTaskDelay(1000 / portTICK_PERIOD_MS);

            eapolCount = 0; // reset for next sequence

            strncpy(apName, getSSIDFromMac(packet->data + 10).c_str(), sizeof(apName) - 1);
            apName[sizeof(apName) - 1] = '\0';

            // Get BSSID from packet (addr3, offset 16..21)
            char bssidStr[18];
            const uint8_t* bssid = packet->data + 16;
            snprintf(bssidStr, sizeof(bssidStr), "%02X_%02X_%02X_%02X_%02X_%02X",
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);

            char filename[64];
            snprintf(filename, sizeof(filename), "/handshake/%s_%s_ID_%i.pcap",
                     bssidStr, apName, random(999));

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

            // global PCAP header
            pcap_hdr_s globalHeader;
            globalHeader.magic_number  = 0xa1b2c3d4;
            globalHeader.version_major = 2;
            globalHeader.version_minor = 4;
            globalHeader.thiszone      = 0;
            globalHeader.sigfigs       = 0;
            globalHeader.snaplen       = 65535;
            globalHeader.network       = 105; // LINKTYPE_IEEE802_11
            file.write((uint8_t*)&globalHeader, sizeof(globalHeader));
            file.flush();

            apFiles[apKey] = {apKey, file};
            logMessage("New handshake file created: " + String(filename));

            if (packetCount < 100) {
                memcpy(packetInfoTable[packetCount].srcMac, packet->data + 10, 6);
                memcpy(packetInfoTable[packetCount].destMac, packet->data + 4, 6);
                packetInfoTable[packetCount].fileName = String(apName);
                packetCount++;
            } else {
                logMessage("Packet info table full, skipping...");
            }

            // ===== beacon fix: cut ESP ghost 4 bytes =====
            if (beaconDetected && beaconFrame != nullptr) {
                pcaprec_hdr_s beaconHeader;
                uint64_t ts = esp_timer_get_time();
                beaconHeader.ts_sec  = ts / 1000000;
                beaconHeader.ts_usec = ts % 1000000;

                uint16_t beaconLen = beaconFrameLen; // already corrected in cb
                beaconHeader.incl_len = beaconLen;
                beaconHeader.orig_len = beaconLen;
                file.write((uint8_t*)&beaconHeader, sizeof(beaconHeader));
                file.write(beaconFrame, beaconLen);
                file.flush();
                logMessage("Beacon frame written as first packet.");
            }
        }

        // ===== add captured packet or cache one, if no saveable file is present=====
        if (file) {
            logMessage("Writing captured packet to file.");
            // write saved packets first
            for(uint8_t i = 0; i < savedPacketCount; i++) {
                if (savedPackets[i]) {
                    logMessage("Writing cached packet to file.");
                    pcaprec_hdr_s recHeader;
                    uint64_t ts = esp_timer_get_time();
                    recHeader.ts_sec   = ts / 1000000;
                    recHeader.ts_usec  = ts % 1000000;
                    size_t len = savedPacketLens[i];
                    if (len == 0) len = packet->len; // fallback safety
                    recHeader.incl_len = len;
                    recHeader.orig_len = len;
                    file.write((uint8_t*)&recHeader, sizeof(recHeader));
                    file.write(savedPackets[i], len);
                    file.flush();
                    free(savedPackets[i]);
                    savedPackets[i] = nullptr;
                    savedPacketLens[i] = 0;
                }
            }
            logMessage("Writing current packet to file.");
            savedPacketCount = 0;
            pcaprec_hdr_s recHeader;
            recHeader.ts_sec   = packet->ts_sec;
            recHeader.ts_usec  = packet->ts_usec;
            recHeader.incl_len = packet->len;
            recHeader.orig_len = packet->len;
            file.write((uint8_t*)&recHeader, sizeof(recHeader));
            file.write(packet->data, packet->len);
            file.flush();
        }
        else{
            logMessage("File not open, cannot write packet, caching packet.");
            if (savedPacketCount < 10) {
                savedPackets[savedPacketCount] = (uint8_t *) malloc(packet->len);
                if (savedPackets[savedPacketCount]) {
                    memcpy(savedPackets[savedPacketCount], packet->data, packet->len);
                    savedPacketLens[savedPacketCount] = packet->len;
                    savedPacketCount++;
                }
            }
        }
        logMessage("Packet written.");
        lastHandshakeMillis = millis();
        free(packet->data);
        free(packet);
    }

    // channel hop
    static unsigned long lastSwitch = 0;
    unsigned long now = millis();
    if (autoChannelSwitch && (now - lastSwitch > 500)) {
        SnifferSwitchChannel();
        lastSwitch = now;
    }
}

bool isEapolFrame(const uint8_t *data, uint16_t len) {
    if (len < 32) return false;

    uint16_t fc = data[0] | (data[1] << 8);
    int hdrlen = ieee80211_hdrlen(fc);
    if (len < hdrlen + 8) return false; // not enough room for LLC+EAPOL

    const uint8_t *llc = data + hdrlen;
    // LLC SNAP should be: AA AA 03 00 00 00 88 8E
    if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
        llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
        llc[6] == 0x88 && llc[7] == 0x8E) {
        return true;
    }
    return false;
}

uint8_t getEAPOLOrder(uint8_t *buf) {
    uint16_t key_info = (buf[39] << 8) | buf[40];  // always big-endian

    bool mic     = key_info & (1 << 8);
    bool ack     = key_info & (1 << 7);
    bool install = key_info & (1 << 6);
    bool secure  = key_info & (1 << 9);

    if (!mic && ack && !install) {
        logMessage("EAPOL Message 1 detected");
        return 1; // Message 1
    }
    if (mic && !ack && !install && !secure) {
        logMessage("EAPOL Message 2 detected");
        return 2; // Message 2
    }
    if (mic && ack && install) {
        logMessage("EAPOL Message 3 detected");
        return 3; // Message 3
    }
    if (mic && !ack && !install && secure) {
        logMessage("EAPOL Message 4 detected");
        return 4; // Message 4
    }

    logMessage("Unknown EAPOL message type");
    return 0; // Unknown
}


static inline int ieee80211_hdrlen(uint16_t fc)
{
    int hdrlen = 24; // base
    uint8_t type    = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;

    if (type == 2) { // data
        if ((fc & 0x0080)) { // QoS flag
            hdrlen += 2;
        }
    }
    if (fc & 0x8000) { // HT control present
        hdrlen += 4;
    }
    return hdrlen;
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
    WiFi.disconnect(false);

    for (auto &entry : apFiles) {
      if (entry.second.file) {
        entry.second.file.close();
      }
    }
    apFiles.clear();
    packetCount = 0;
    beaconDetected = false;
    eapolCount = 0;

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
    
    // WiFi.mode(WIFI_STA);
    // WiFi.scanNetworks(true);
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