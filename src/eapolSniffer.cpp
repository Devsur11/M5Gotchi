#include "EapolSniffer.h"
#define MAX_PKT_SIZE 3000
long lastpacketsend;

// Global variable used to hold the current handshake file handle.
// When a new handshake capture begins, we create (and keep open) a file in which we write the
// PCAP global header and subsequent per–packet records until a timeout occurs.
File currentPcapFile;

int clientCount;
bool autoChannelSwitch;
int currentChannel;
PacketInfo packetInfoTable[100];
int packetInfoCount;
char pcapFileName[32];
uint8_t clients[50][6];
int userChannel;

// Define the handshake timeout in milliseconds (here 2000ms as in your original logic)
const unsigned long HANDSHAKE_TIMEOUT = 2000;

// PCAP Global Header (24 bytes)
// (Packed to avoid any structure padding.)
struct pcap_hdr_s {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snaplen;        /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
} __attribute__((packed));

// PCAP Per-Packet Record Header (16 bytes)
struct pcaprec_hdr_s {
  uint32_t ts_sec;   /* timestamp seconds */
  uint32_t ts_usec;  /* timestamp microseconds */
  uint32_t incl_len; /* number of octets of packet saved in file */
  uint32_t orig_len; /* actual length of packet */
} __attribute__((packed));

// Structure to hold a captured packet that we queue for writing
typedef struct {
  size_t    len;
  uint8_t  *data;
  uint32_t  ts_sec;
  uint32_t  ts_usec;
} CapturedPacket;

// Global variables for packet capture
QueueHandle_t packetQueue;  // FreeRTOS queue for passing captured packets
volatile uint32_t packetCount = 0;  // Total number of captured packets

// Global variables for handshake file management
uint32_t handshakeFileCount = 0;  // A counter used to create unique filenames
unsigned long lastHandshakeMillis = 0; // Timestamp (millis) of the last handshake packet received
const unsigned long handshakeTimeout = 5000; // If no handshake packet is received within 5 sec, close current file

// WiFi promiscuous callback function
// IRAM_ATTR places this function in IRAM for faster execution.
void IRAM_ATTR wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  // Process only valid WiFi packet types (management, data, or control)
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA && type != WIFI_PKT_CTRL) {
    return;
  }
  
  // The ESP32 supplies a pointer to a wifi_promiscuous_pkt_t structure.
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint16_t len = pkt->rx_ctrl.sig_len;
  const uint8_t* payload = pkt->payload;
  
  // Filter for EAPOL frames by checking for the LLC/SNAP header pattern.
  // (This filter may be adjusted based on your needs.)
  if (!((payload[24] == 0xAA && payload[25] == 0xAA && payload[26] == 0x03) ||
        (payload[26] == 0xAA && payload[27] == 0xAA && payload[28] == 0x03))) {
    return;
  }
  Serial.println("EAPOL Detected");
  if (len == 0 || len > MAX_PKT_SIZE) return;
  
  // Allocate a structure to hold this packet.
  CapturedPacket *p = (CapturedPacket*) malloc(sizeof(CapturedPacket));
  if (!p) return;
  p->data = (uint8_t *) malloc(len);
  if (!p->data) {
    free(p);
    return;
  }
  
  // Copy the raw packet data.
  memcpy(p->data, pkt->payload, len);
  p->len = len;
  
  // Get a timestamp (in microseconds since boot) and break it into seconds and microseconds.
  uint64_t ts = esp_timer_get_time(); // returns microseconds
  p->ts_sec = ts / 1000000;
  p->ts_usec = ts % 1000000;
  
  // Send the pointer to the packet to our queue.
  BaseType_t xHigherPriorityTaskWoken = pdFALSE;
  xQueueSendFromISR(packetQueue, &p, &xHigherPriorityTaskWoken);
  if (xHigherPriorityTaskWoken) {
    portYIELD_FROM_ISR();
  }
}
char filename[32];
bool SnifferBegin(int userChannel) {
  autoChannelSwitch = (userChannel == 0);
  // Set the initial channel
  currentChannel = autoChannelSwitch ? 1 : userChannel;

  SD.begin();

  // Create a FreeRTOS queue to hold captured packets.
  packetQueue = xQueueCreate(32, sizeof(CapturedPacket*));
  if (packetQueue == NULL) {
    while (1) {
      delay(1000);
    }
  }
  // Set WiFi to station mode and disconnect from any AP.
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  // Enable WiFi promiscuous mode on channel 11.
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
  return true;
}

void SnifferLoop() {
  CapturedPacket *packet = NULL;
  
  // Check if any captured packet is waiting in the queue.
  if (xQueueReceive(packetQueue, &packet, 10 / portTICK_PERIOD_MS) == pdTRUE) {
    
    // If no current handshake file is open, start a new one.
    if (!currentPcapFile) {
      char filename[32];
      sprintf(filename, "/handshake_%u.pcap", handshakeFileCount++);
      currentPcapFile = SD.open(filename, FILE_WRITE);
      if (!currentPcapFile) {
        // Free the packet memory and return early.
        free(packet->data);
        free(packet);
        return;
      }
      // Write the PCAP global header to the new file.
      pcap_hdr_s globalHeader;
      globalHeader.magic_number = 0xa1b2c3d4;
      globalHeader.version_major = 2;
      globalHeader.version_minor = 4;
      globalHeader.thiszone = 0;
      globalHeader.sigfigs = 0;
      globalHeader.snaplen = 65535;  // maximum number of bytes captured per packet
      globalHeader.network = 105;    // DLT_IEEE802_11 (raw 802.11 frames)
      currentPcapFile.write((uint8_t*)&globalHeader, sizeof(globalHeader));
      currentPcapFile.flush();
    }
    
    // Prepare the PCAP per-packet header.
    pcaprec_hdr_s recHeader;
    recHeader.ts_sec   = packet->ts_sec;
    recHeader.ts_usec  = packet->ts_usec;
    recHeader.incl_len = packet->len;
    recHeader.orig_len = packet->len;
    
    // Write the record header and the packet data to the current file.
    currentPcapFile.write((uint8_t*)&recHeader, sizeof(recHeader));
    currentPcapFile.write(packet->data, packet->len);
    currentPcapFile.flush();
    if (packetCount < 100) {
      
      memcpy(packetInfoTable[packetCount].srcMac, packet + 10, 6); // Source MAC
      memcpy(packetInfoTable[packetCount].destMac, packet + 4, 6); // Destination MAC
      packetInfoTable[packetCount].fileName = String(filename);
    } else {
      Serial.println("Packet info table full, skipping...");
    }
    
    // Update the timestamp for the last handshake packet.
    lastHandshakeMillis = millis();
    
    // Free the dynamically allocated memory for this packet.
    free(packet->data);
    free(packet);
  }
  
  // If a handshake file is open and we've exceeded the handshake timeout,
  // close the file. (This marks the end of a handshake capture.)
  if (currentPcapFile && (millis() - lastHandshakeMillis > handshakeTimeout)) {
    packetCount++;
    currentPcapFile.close();
    currentPcapFile = File(); // Reset the file object.
  }
    static unsigned long lastSwitch = 0;
    unsigned long now = millis();

    // In auto channel mode, switch channels every 500 ms
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


const PacketInfo* SnifferGetPacketInfoTable() {
    return packetInfoTable;
}
