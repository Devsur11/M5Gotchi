#include "pwngrid.h"
#include "mood.h"
#include <vector>

static const size_t PWNGRID_MAX_PEERS = 64;
std::vector<pwngrid_peer> pwngrid_peers;
String pwngrid_last_friend_name = "";
uint16_t pwngrid_last_pwned_session_amount = 0;
uint16_t pwngrid_last_pwned_amount = 0;
String lastPeerFace = "";

uint16_t getPwngridLastSessionPwnedAmount() { return pwngrid_last_pwned_session_amount; }
uint8_t getPwngridTotalPeers() { return (uint8_t)pwngrid_peers.size(); }
String getPwngridLastFriendName() { return pwngrid_last_friend_name; }
uint16_t getPwngridLastPwnedAmount() { return pwngrid_last_pwned_amount; }
pwngrid_peer *getPwngridPeers() { return pwngrid_peers.empty() ? nullptr : pwngrid_peers.data(); }
String getLastPeerFace() { return lastPeerFace; }

void pwngridAdvertiseLoop(void *pvParameters) {
    while (true) {
        // Periodically call pwngridAdvertise
        uint8_t channel = 0; // Example: channel 1
        String face = getCurrentMoodFace();
        pwngridAdvertise(channel, face);

        // Delay for a specific time before calling again
        vTaskDelay(1000 / portTICK_PERIOD_MS); // Adjust the delay (in milliseconds) as needed
    }
}

// Had to remove Radiotap headers, since its automatically added
// Also had to remove the last 4 bytes (frame check sequence)
const uint8_t pwngrid_beacon_raw[] = {
    0x80, 0x00,                          // FC
    0x00, 0x00,                          // Duration
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // DA (broadcast)
    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,  // SA
    0xa1, 0x00, 0x64, 0xe6, 0x0b, 0x8b,  // BSSID
    0x40, 0x43,  // Sequence number/fragment number/seq-ctl
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Timestamp
    0x64, 0x00,                                      // Beacon interval
    0x11, 0x04,                                      // Capability info
    // 0xde (AC = 222) + 1 byte payload len + payload (AC Header)
    // For each 255 bytes of the payload, a new AC header should be set
};

const int raw_beacon_len = sizeof(pwngrid_beacon_raw);

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len,
                            bool en_sys_seq);

esp_err_t pwngridAdvertise(uint8_t channel, String face) {
  if(!(pwngrid_indentity.length() > 10)){
    return ESP_ERR_NOT_SUPPORTED;
  }
  if (!advertisePwngrid){
    return ESP_OK;
  }
  JsonDocument pal_json;
  String pal_json_str = "";

  pal_json["pal"] = true;  // Also detect other Palnagotchis
  pal_json["name"] = hostname;
  pal_json["face"] = face;
  pal_json["epoch"] = 1;
  pal_json["grid_version"] = "1.10.3";
  pal_json["identity"] = pwngrid_indentity;
  pal_json["pwnd_run"] = sessionCaptures;
  pal_json["pwnd_tot"] = pwned_ap;
  pal_json["session_id"] = "22:00:64:e6:0b:8b";
  pal_json["timestamp"] = 0;
  pal_json["uptime"] = 0;
  pal_json["version"] = "1.8.4";
  pal_json["policy"]["advertise"] = true;
  pal_json["policy"]["bond_encounters_factor"] = 20000;
  pal_json["policy"]["bored_num_epochs"] = 0;
  pal_json["policy"]["sad_num_epochs"] = 0;
  pal_json["policy"]["excited_num_epochs"] = 9999;

  serializeJson(pal_json, pal_json_str);
  // Use the actual byte length of the serialized string (handles multi-byte UTF-8)
  size_t pal_json_len = pal_json_str.length();
  if (pal_json_len == 0) {
    return ESP_ERR_INVALID_ARG;
  }

  // Calculate number of AC headers needed (2 bytes each)
  size_t headers = (pal_json_len + 254) / 255; // ceil(pal_json_len/255)
  size_t header_len = headers * 2;
  size_t total_len = raw_beacon_len + pal_json_len + header_len;

  uint8_t *pwngrid_beacon_frame = (uint8_t *)malloc(total_len);
  if (!pwngrid_beacon_frame) {
    return ESP_ERR_NO_MEM;
  }

  memcpy(pwngrid_beacon_frame, pwngrid_beacon_raw, raw_beacon_len);

  // Iterate through json string and copy it to beacon frame
  int frame_byte = raw_beacon_len;
  for (size_t i = 0; i < pal_json_len; i++) {
    // Write AC and len tags before every 255 bytes
    if (i == 0 || (i % 255) == 0) {
      pwngrid_beacon_frame[frame_byte++] = 0xde;  // AC = 222
      uint8_t payload_len = 255;
      if (pal_json_len - i < 255) {
        payload_len = pal_json_len - i;
      }

      pwngrid_beacon_frame[frame_byte++] = payload_len;
    }

    // Append json byte to frame (keep raw UTF-8 bytes)
    pwngrid_beacon_frame[frame_byte++] = (uint8_t)pal_json_str[i];
  }

  delay(102);
  // https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/network/esp_wifi.html#_CPPv417esp_wifi_80211_tx16wifi_interface_tPKvib
  // Send only the used portion of the buffer (frame_byte)
  esp_err_t result = esp_wifi_80211_tx(WIFI_IF_AP, pwngrid_beacon_frame,
                                       frame_byte, false);
  free(pwngrid_beacon_frame);
  return result;
}

void pwngridAddPeer(JsonDocument &json, signed int rssi) {
  String identity = json["identity"].as<String>();

  // Update existing peer if present
  for (size_t i = 0; i < pwngrid_peers.size(); i++) {
    if (pwngrid_peers[i].identity == identity) {
      auto &p = pwngrid_peers[i];
      p.rssi = rssi;
      p.last_ping = millis();
      p.gone = false;
      p.name = json["name"].as<String>();
      p.face = json["face"].as<String>();
      p.epoch = json["epoch"].as<int>();
      p.grid_version = json["grid_version"].as<String>();
      p.pwnd_run = json["pwnd_run"].as<int>();
      p.pwnd_tot = json["pwnd_tot"].as<int>();
      p.session_id = json["session_id"].as<String>();
      p.timestamp = json["timestamp"].as<int>();
      p.uptime = json["uptime"].as<int>();
      p.version = json["version"].as<String>();

      pwngrid_last_friend_name = p.name;
      lastPeerFace = p.face;
      pwngrid_last_pwned_amount = p.pwnd_tot;
      pwngrid_last_pwned_session_amount = p.pwnd_run;
      return;
    }
  }

  // New peer - construct and insert (or replace if we hit the cap)
  pwngrid_peer newp;
  newp.rssi = rssi;
  newp.last_ping = millis();
  newp.gone = false;
  newp.name = json["name"].as<String>();
  newp.face = json["face"].as<String>();
  newp.epoch = json["epoch"].as<int>();
  newp.grid_version = json["grid_version"].as<String>();
  newp.identity = identity;
  newp.pwnd_run = json["pwnd_run"].as<int>();
  newp.pwnd_tot = json["pwnd_tot"].as<int>();
  newp.session_id = json["session_id"].as<String>();
  newp.timestamp = json["timestamp"].as<int>();
  newp.uptime = json["uptime"].as<int>();
  newp.version = json["version"].as<String>();

  if (pwngrid_peers.size() < PWNGRID_MAX_PEERS) {
    pwngrid_peers.push_back(newp);
  } else {
    // Try to find a gone peer to reuse
    int idx = -1;
    for (size_t i = 0; i < pwngrid_peers.size(); i++) {
      if (pwngrid_peers[i].gone) { idx = (int)i; break; }
    }
    if (idx == -1) {
      // Replace the oldest peer
      uint32_t oldest = UINT32_MAX;
      for (size_t i = 0; i < pwngrid_peers.size(); i++) {
        if ((uint32_t)pwngrid_peers[i].last_ping < oldest) { oldest = pwngrid_peers[i].last_ping; idx = (int)i; }
      }
      if (idx == -1) idx = 0;
    }
    pwngrid_peers[idx] = newp;
  }

  pwngrid_last_friend_name = newp.name;
  lastPeerFace = newp.face;
  pwngrid_last_pwned_amount = newp.pwnd_tot;
  pwngrid_last_pwned_session_amount = newp.pwnd_run;
}

const int away_threshold = 120000;

void checkPwngridGoneFriends() {
  for (size_t i = 0; i < pwngrid_peers.size(); i++) {
    // Check if peer is away for more then
    int away_secs = pwngrid_peers[i].last_ping - millis();
    if (away_secs > away_threshold) {
      pwngrid_peers[i].gone = true;
      return;
    }
  }
}

typedef struct {
  int16_t fctl;
  int16_t duration;
  uint8_t da;
  uint8_t sa;
  uint8_t bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;

typedef struct {
  uint8_t payload[0];
  WifiMgmtHdr hdr;
} wifi_ieee80211_packet_t;

void getMAC(char *addr, uint8_t *data, uint16_t offset) {
  sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset + 0],
          data[offset + 1], data[offset + 2], data[offset + 3],
          data[offset + 4], data[offset + 5]);
}

void pwnSnifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *snifferPacket = (wifi_promiscuous_pkt_t *)buf;
  WifiMgmtHdr *frameControl = (WifiMgmtHdr *)snifferPacket->payload;

  String src = "";
  String essid = "";

  if (type == WIFI_PKT_MGMT) {
    // Remove frame check sequence bytes
    int len = snifferPacket->rx_ctrl.sig_len - 4;
    int fctl = ntohs(frameControl->fctl);
    const wifi_ieee80211_packet_t *ipkt =
        (wifi_ieee80211_packet_t *)snifferPacket->payload;
    const WifiMgmtHdr *hdr = &ipkt->hdr;

    // if ((snifferPacket->payload[0] == 0x80) && (buf == 0)) {
    if ((snifferPacket->payload[0] == 0x80)) {
      char addr[] = "00:00:00:00:00:00";
      getMAC(addr, snifferPacket->payload, 10);
      src.concat(addr);
      if (src == "de:ad:be:ef:de:ad") {
        // Just grab the first 255 bytes of the pwnagotchi beacon
        // because that is where the name is
        for (int i = 38; i < len; i++) {
          uint8_t b = (uint8_t)snifferPacket->payload[i];

          // If we find an AC header marker, skip it and its length byte
          if (b == 0xde) {
            i++; // skip the next length byte
            continue;
          }

          // Accept printable characters (>= 0x20) and common whitespace,
          // and preserve UTF-8 bytes (>= 0x80 are >= 0x20 anyway)
          if (b >= 0x20 || b == '\n' || b == '\r' || b == '\t') {
            essid.concat((char)b);
          }
        }

        JsonDocument sniffed_json;  // ArduinoJson v6s
        auto result = deserializeJson(sniffed_json, essid);

        if (result == ArduinoJson::DeserializationError::Ok) {
          pwngridAddPeer(sniffed_json, snifferPacket->rx_ctrl.rssi);
        } else if (result == ArduinoJson::DeserializationError::IncompleteInput) {
          logMessage("Deserialization error: incomplete input");
        } else if (result == ArduinoJson::DeserializationError::NoMemory) {
          logMessage("Deserialization error: no memory");
        } else if (result == ArduinoJson::DeserializationError::InvalidInput) {
          logMessage("Deserialization error: invalid input");
        } else if (result == ArduinoJson::DeserializationError::TooDeep) {
          logMessage("Deserialization error: too deep");
        } else {
          logMessage(essid);
          logMessage("Deserialization error");
        }
      }
    }
  }
}

#include "WiFi.h"

void initPwngrid() {  
  wifi_init_config_t WIFI_INIT_CONFIG = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&WIFI_INIT_CONFIG);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_APSTA);
  WiFi.softAP("pwngrid", NULL, 1, 1, 1);
  esp_wifi_start();
  esp_wifi_set_promiscuous_rx_cb(&pwnSnifferCallback);
  esp_wifi_set_promiscuous(true);
  delay(1);
  //check if task is already created
  if (xTaskGetHandle("pwngridTx") == NULL) {
    logMessage("Starting pwngrid advertise task");
  }
  else {
    return;
  }

  xTaskCreatePinnedToCore(
        pwngridAdvertiseLoop,      // Function to be executed
        "pwngridTx",    // Name of the task
        8192,                      // Stack size (in bytes) — increased to avoid stack overflow
        NULL,                      // Parameters to pass to the task
        1,                         // Priority (1 is the lowest priority)
        NULL,                      // Task handle
        1                          // Core to run the task on (0 or 1)
    );
}