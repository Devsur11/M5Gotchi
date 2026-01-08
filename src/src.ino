#include "M5Cardputer.h"
#include "M5Unified.h"
#include "ui.h"
#include "settings.h"
#include "mood.h"
#include "pwnagothi.h"
#include "moodLoader.h"
#include "Arduino.h"
#include "pwngrid.h"
#include "api_client.h"
#include "esp_task_wdt.h"
#include "src.h"
#ifdef ENABLE_COREDUMP_LOGGING
#include "esp_core_dump.h"
#define MQTT_MAX_PACKET_SIZE 4096  //IMPORTANT: Increase MQTT max packet size for coredump chunks
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "esp_system.h"
#if __has_include(<esp_chip_info.h>)
#include <esp_chip_info.h>
#endif
#include "mbedtls/base64.h"
#endif
#include "githubUpdater.h"
#include "wpa_sec.h"
#include "esp_partition.h"
#include "fontDownloader.h"

bool firstSoundEnable;
bool isSoundPlayed = false;

#ifdef ENABLE_COREDUMP_LOGGING

extern const char emqxsl_root_cert_pem_start[] asm("_binary_certs_emqxsl_ca_pem_start");
extern const char emqxsl_root_cert_pem_end[] asm("_binary_certs_emqxsl_ca_pem_end");

WiFiClientSecure espClient;
PubSubClient client(espClient);

/* Core dump location retrieved via esp_core_dump_image_get() */
size_t coredump_addr = 0;
size_t coredump_size = 0;
const size_t chunkSize = 1024; // 1 KiB chunks to reduce memory pressure and improve reliability

#ifndef MQTT_HOST
#error "MQTT_HOST not defined. Please build using the build_with_mqtt.sh script"
#endif
#ifndef MQTT_PORT
#error "MQTT_PORT not defined. Please build using the build_with_mqtt.sh script"
#endif
#ifndef MQTT_USERNAME
#error "MQTT_USERNAME not defined. Please build using the build_with_mqtt.sh script"
#endif
#ifndef MQTT_PASSWORD
#error "MQTT_PASSWORD not defined. Please build using the build_with_mqtt.sh script"
#endif

const char* mqttServer = MQTT_HOST;
const int mqttPort = MQTT_PORT;
const char* mqttUser = MQTT_USERNAME;
const char* mqttPassword = MQTT_PASSWORD;
const char* mqttTopic = "device/coredump";

void connectMQTT() {
  espClient.setCACert(emqxsl_root_cert_pem_start);
  client.setServer(mqttServer, mqttPort);
  int retries = 0;
  const int maxRetries = 3;
  while (!client.connected() && retries < maxRetries) {
    if (client.connect("ESP32S3Client", mqttUser, mqttPassword)) {
      logMessage("MQTT Connected");
      client.publish(mqttTopic, ("hello from esp32, mac: " + String(originalMacAddress)).c_str(), false);
      return;
    }
    retries++;
    logMessage("MQTT connection failed, retrying...");
    delay(1000);
  }
  if (!client.connected()) {
    logMessage("MQTT connection failed after all retries");
  }
}

static uint32_t checksum32(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  for (size_t i = 0; i < len; ++i) {
    sum += data[i];
  }
  return sum;
}

// Ack tracking for upload confirmation
static volatile bool ackReceived = false;
static String ackUploadId = "";
static String ackStatus = "";
static unsigned ackReceivedChunks = 0;
static uint32_t ackChecksum = 0;
static String currentUploadId = "";

static String resetReasonToString(esp_reset_reason_t r) {
  switch (r) {
    case ESP_RST_UNKNOWN: return "UNKNOWN";
    case ESP_RST_POWERON: return "POWERON";
    case ESP_RST_EXT: return "EXT";
    case ESP_RST_SW: return "SW";
    case ESP_RST_PANIC: return "PANIC";
    case ESP_RST_INT_WDT: return "INT_WDT";
    case ESP_RST_TASK_WDT: return "TASK_WDT";
    case ESP_RST_WDT: return "WDT";
    case ESP_RST_DEEPSLEEP: return "DEEPSLEEP";
    case ESP_RST_BROWNOUT: return "BROWNOUT";
    case ESP_RST_SDIO: return "SDIO";
    default: return "OTHER";
  }
}

void mqttAckCallback(char* topic, byte* payload, unsigned int length) {
  String t(topic);
  String msg;
  for (unsigned int i = 0; i < length; ++i) msg += (char)payload[i];

  String ackPrefix = String(mqttTopic) + "/ack";
  if (!t.startsWith(ackPrefix)) return;

  // quick JSON-like parse (no dependency on ArduinoJson)
  int p = msg.indexOf("\"upload_id\"");
  if (p < 0) return;
  int c = msg.indexOf(':', p);
  if (c < 0) return;
  int s = msg.indexOf('"', c);
  if (s < 0) return;
  int e = msg.indexOf('"', s + 1);
  if (e < 0) return;
  String uid = msg.substring(s + 1, e);
  if (uid != currentUploadId) return;

  ackUploadId = uid;
  ackReceived = true;

  int st = msg.indexOf("\"status\"");
  if (st >= 0) {
    int cc = msg.indexOf(':', st);
    int s2 = msg.indexOf('"', cc);
    int e2 = msg.indexOf('"', s2 + 1);
    if (s2 >= 0 && e2 >= 0) ackStatus = msg.substring(s2 + 1, e2);
  }

  int rc = msg.indexOf("\"received_chunks\"");
  if (rc >= 0) {
    int cc = msg.indexOf(':', rc);
    if (cc >= 0) {
      int comma = msg.indexOf(',', cc);
      String num = (comma >= 0) ? msg.substring(cc + 1, comma) : msg.substring(cc + 1);
      ackReceivedChunks = (unsigned)num.toInt();
    }
  }

  int ck = msg.indexOf("\"checksum\"");
  if (ck >= 0) {
    int cc = msg.indexOf(':', ck);
    if (cc >= 0) {
      int comma = msg.indexOf(',', cc);
      String num = (comma >= 0) ? msg.substring(cc + 1, comma) : msg.substring(cc + 1);
      ackChecksum = (uint32_t)num.toInt();
    }
  }

  logMessage("Received ACK: upload=" + ackUploadId + " status=" + ackStatus + " chunks=" + String(ackReceivedChunks) + " checksum=" + String(ackChecksum));
}

bool sendCoredump() {
  size_t addr = 0;
  size_t size = 0;
  esp_err_t res = esp_core_dump_image_get(&addr, &size);
  if (res != ESP_OK || size == 0) {
    logMessage("No core dump image available");
    return true;
  }

  logMessage("Core dump image found via esp_core_dump_image_get");
  logMessage("Core dump addr: " + String(addr) + ", size: " + String(size));

  // Ensure client connected
  if (!client.connected()) {
    logMessage("MQTT client not connected, attempting to connect...");
    connectMQTT();
    if (!client.connected()) {
      logMessage("MQTT not connected, aborting coredump send");
      return false;
    }
  }

  // Prepare buffers
  size_t bufSize = chunkSize;
  uint8_t *buffer = (uint8_t*)malloc(bufSize);
  while (!buffer && bufSize > 128) {
    bufSize /= 2;
    buffer = (uint8_t*)malloc(bufSize);
  }
  if (!buffer) {
    logMessage("Failed to allocate coredump buffer");
    return false;
  }
  size_t maxB64 = (bufSize * 4 / 3) + 12;
  char *base64Out = (char*)malloc(maxB64);
  if (!base64Out) {
    logMessage("Failed to allocate base64 buffer");
    free(buffer);
    return false;
  }

  // Create upload id and set current
  currentUploadId = String(originalMacAddress) + "-" + String(millis());
  unsigned totalChunks = (unsigned)((size + bufSize - 1) / bufSize);

  // Get telemetry
  String resetStr = resetReasonToString(esp_reset_reason());
  esp_chip_info_t chip_info;
  esp_chip_info(&chip_info);
  const char *idf_ver = esp_get_idf_version();
  String buildTime = String(__DATE__) + " " + String(__TIME__);

  // Compose metadata JSON with extra telemetry (including user-requested settings)
  char meta[1536];
  snprintf(meta, sizeof(meta), "{\"upload_id\":\"%s\",\"mac\":\"%s\",\"board\":%d,\"version\":\"%s\",\"build_time\":\"%s\",\"reset_reason\":\"%s\",\"idf\":\"%s\",\"chip_model\":%d,\"chip_cores\":%d,\"chip_rev\":%d,\"size\":%u,\"chunks\":%u,\"addr\":%u,\"freeHeap\":%u,\"gps_tx\":%u,\"gps_rx\":%u,\"advertise_pwngrid\":%d,\"toggle_pwnagothi_with_gpio0\":%d,\"cardputer_adv\":%d,\"limitFeatures\":%d}",
           currentUploadId.c_str(), originalMacAddress.c_str(), (int)M5.getBoard(), CURRENT_VERSION, buildTime.c_str(), resetStr.c_str(), idf_ver, (int)chip_info.model, (int)chip_info.cores, (int)chip_info.revision, (unsigned)size, totalChunks, (unsigned)addr, (unsigned)ESP.getFreeHeap(), (unsigned)gpsTx, (unsigned)gpsRx, advertisePwngrid ? 1 : 0, toogle_pwnagothi_with_gpio0 ? 1 : 0, cardputer_adv ? 1 : 0, limitFeatures ? 1 : 0);

  char fullTopic[128];
  snprintf(fullTopic, sizeof(fullTopic), "%s/meta", mqttTopic);

  // Set callback and subscribe to ACK topic
  ackReceived = false;
  ackUploadId = "";
  ackStatus = "";
  ackReceivedChunks = 0;
  ackChecksum = 0;
  client.setCallback(mqttAckCallback);
  snprintf(fullTopic, sizeof(fullTopic), "%s/ack/#", mqttTopic);
  client.subscribe(fullTopic);
  // restore fullTopic to meta topic
  snprintf(fullTopic, sizeof(fullTopic), "%s/meta", mqttTopic);

  if (!client.publish(fullTopic, meta)) {
    logMessage("Failed to publish coredump metadata");
    free(base64Out);
    free(buffer);
    return false;
  }
  logMessage("Coredump metadata published: " + String(meta));

  unsigned seq = 0;
  uint32_t totalChecksum = 0;
  size_t offset = 0;

  // Use a single reusable send buffer to avoid repeated malloc/free and potential heap corruption
  static char *sendBuf = nullptr;
  static size_t sendBufSize = 0;

  while (offset < size) {
    size_t readLen = bufSize;
    if (offset + readLen > size) readLen = size - offset;

    if (spi_flash_read((uint32_t)(addr + offset), buffer, readLen) != ESP_OK) {
      logMessage("Flash read failed");
      break;
    }

    uint32_t chk = checksum32(buffer, readLen);
    totalChecksum += chk;

    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char*)base64Out, maxB64, &olen, buffer, readLen) != 0) {
      logMessage("Base64 encode failed");
      break;
    }

    char header[256];
    snprintf(header, sizeof(header), "{\"upload_id\":\"%s\",\"seq\":%u,\"len\":%u,\"checksum\":%u,\"total\":%u}",
             currentUploadId.c_str(), seq, (unsigned)readLen, (unsigned)chk, totalChunks);
    size_t headerLen = strlen(header);
    size_t required = headerLen + 1 + olen;
    if (sendBufSize < required) {
      // (re)allocate a buffer large enough for the biggest chunk seen so far
      char *nb = (char*)realloc(sendBuf, required);
      if (!nb) {
        logMessage("Failed to allocate send buffer for chunk");
        break;
      }
      sendBuf = nb;
      sendBufSize = required;
    }
    memcpy(sendBuf, header, headerLen);
    sendBuf[headerLen] = '\n';
    memset(sendBuf, 0, sendBufSize);
    memcpy(sendBuf + headerLen + 1, base64Out, olen);

    memcpy(sendBuf, header, headerLen);
    sendBuf[headerLen] = '\n';
    memcpy(sendBuf + headerLen + 1, base64Out, olen);

    // wipe ONLY the unused tail so no old garbage leaks
    size_t used = headerLen + 1 + olen;
    if (used < sendBufSize) {
        memset(sendBuf + used, 0, sendBufSize - used);
    }


    snprintf(fullTopic, sizeof(fullTopic), "%s/chunk", mqttTopic);
    bool ok = client.publish(fullTopic, sendBuf, (uint16_t)required);

    if (!ok) {
      logMessage("MQTT publish failed for chunk " + String(seq));
      // attempt reconnect once
      connectMQTT();
      if (!client.connected()) {
        logMessage("Reconnect failed, aborting coredump send");
        free(base64Out);
        free(buffer);
        return false;
      }
      ok = client.publish(fullTopic, sendBuf, (uint16_t)required);
      if (!ok) {
        logMessage("Retry publish failed for chunk " + String(seq));
        free(base64Out);
        free(buffer);
        return false;
      }
    }

    // Give the MQTT client a chance to process/send the packet before we reuse the buffer
    client.loop();
    delay(50);

    logMessage("Published chunk " + String(seq) + " (" + String(readLen) + " bytes, crc=" + String(chk) + ")");
    seq++;
    offset += readLen;
    delay(20);
  }
  // free the reusable sendBuf if it was allocated
  if (sendBuf) {
    free(sendBuf);
    sendBuf = nullptr;
    sendBufSize = 0;
  }

  // publish end message with final meta including total checksum
  char endMsg[512];
  snprintf(endMsg, sizeof(endMsg), "{\"upload_id\":\"%s\",\"status\":\"complete\",\"sent_chunks\":%u,\"checksum\":%u}", currentUploadId.c_str(), (unsigned)seq, (unsigned)totalChecksum);
  snprintf(fullTopic, sizeof(fullTopic), "%s/end", mqttTopic);
  client.publish(fullTopic, endMsg);
  logMessage("Coredump upload finished: " + String(endMsg));

  // Wait for ACK for a short period
  unsigned long waitStart = millis();
  const unsigned long ackTimeout = 10000; // 10s
  bool uploadVerified = false;
  while (millis() - waitStart < ackTimeout) {
    client.loop();
    if (ackReceived && ackUploadId == currentUploadId) {
      if (ackStatus == "ok" || ackStatus == "complete") {
        if (ackReceivedChunks == seq && ackChecksum == totalChecksum) {
          logMessage("Upload verified by server, chunks and checksum match");
          uploadVerified = true;
        } else {
          logMessage("Server ACK received but mismatch: ackChunks=" + String(ackReceivedChunks) + " ackChecksum=" + String(ackChecksum));
        }
      } else {
        logMessage("Server ACK received with status: " + ackStatus);
      }
      break;
    }
    delay(50);
  }

  if (uploadVerified) {
    // Erase core dump image after verified send
    esp_core_dump_image_erase();
    logMessage("Core dump erased after verified upload");
  } else {
    logMessage("No verification ACK received; keeping core dump for retry");
  }

  // cleanup
  free(base64Out);
  free(buffer);

  delay(200); // Ensure messages are flushed
  client.unsubscribe((String(mqttTopic) + "/ack/#").c_str());
  // Reset callback to noop
  client.setCallback(nullptr);

  if (!uploadVerified) {
    //disconnect and flush everything, just dont erase coredump
    client.disconnect();
    logMessage("MQTT disconnected, but core dump not erased");
  } else {
    client.disconnect();
    logMessage("MQTT disconnected");
  }
  return uploadVerified;
}


#endif // ENABLE_COREDUMP_LOGGING

void initM5() {
  auto cfg = M5.config();
  M5.begin(cfg);
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Keyboard.begin();
}

void setup() {
  Serial.begin(115200);
  printHeapInfo();
  logMessage("System booting...");
  initM5();
  logMessage("Board ID: " + String(M5.getBoard()));
  if(M5.getBoard() == m5::board_t::board_M5CardputerADV){
    cardputer_adv = true;
    logMessage("Cardputer ADV detected, enabling ADV features");
    pinMode(LORA_RST, OUTPUT);
    digitalWrite(LORA_RST, LOW);   // hold SX1262 in reset - this will ensure it doesn't interfere with SD card init
    delay(50);
  }
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  if(initVars()){}
  else{
    #ifndef SKIP_SD_CHECK
    initColorSettings();
    initUi();
    drawInfoBox("ERROR!", "SD card is needed to work.", "Insert it and restart", false, true);
    while(true){delay(10);}
    #endif
  }
  logMessage("Heap after vars init:");
  printHeapInfo();
  M5.Display.setBrightness(brightness);
  initColorSettings();
  initUi();
  preloadMoods();
  
  
  // Ensure mood text/face files exist and load them from SD
  if (!initMoodsFromSD()) {
    logMessage("Moods: failed to initialize from SD, using defaults");
  } else {
    logMessage("Moods: initialized from SD");
  }
  
  setMoodToStartup();
  updateUi(false, false);
  logMessage("Heap after mood preload:");
  printHeapInfo();
  
  if(randomise_mac_at_boot){
    //lets gen random mac to setup unique identity
    uint8_t mac[6];

    // generate random MAC
    for (int i = 0; i < 6; i++) {
      mac[i] = random(0, 256);
    }

    // fix MAC rules
    mac[0] &= 0xFE; // clear multicast bit
    mac[0] |= 0x02; // set locally administered bit

    esp_err_t err;

    // WiFi must NOT be started yet
    WiFi.mode(WIFI_STA); // this calls esp_wifi_init internally but not start

    err = esp_wifi_set_mac(WIFI_IF_STA, mac);
    if (err != ESP_OK) {
      fLogMessage("set_mac failed: %s\n", esp_err_to_name(err));
    }
  }

  // now start WiFi
  if (wifiMutex == NULL) {
    wifiMutex = xSemaphoreCreateMutex();
    if (wifiMutex == NULL) {
      logMessage("Failed to create WiFi mutex");
      abort(); // seriously, no point continuing
    }
  }

  logMessage("Generated and set random MAC address: " + String(WiFi.macAddress()));

  #ifdef ENABLE_COREDUMP_LOGGING
  esp_core_dump_init();
  #endif
  
  // Try to connect to any saved networks on startup if enabled
  bool newVersionAvailable = false;
  if(connectWiFiOnStartup){
    attemptConnectSavedNetworks();
    if(WiFi.status() == WL_CONNECTED){
      logMessage("Connected to WiFi on startup");
      delay(1000); //wait a second to ensure connection is stable
      //lets now check for updates and if it exists, inform the user
      if(checkUpdatesAtNetworkStart) {
        logMessage("Checking for updates on network start");
        if(check_for_new_firmware_version(false)) {
          logMessage("New firmware version available on startup");
          newVersionAvailable = true;
        } else {
          logMessage("No new firmware version found on startup");
        }
      }
      // Sync pwned networks if configured
      if(sync_pwned_on_boot){
        logMessage("Syncing cached pwned APs on boot");
        drawInfoBox("Sync", "Syncing cached PWNs", "This may take a while...", false, false);
        api_client::init(KEYS_FILE);
        bool ok = api_client::uploadCachedAPs();
        logMessage("Sync completed with status: " + String(ok ? "success" : "failure"));
      }
    } else {
      logMessage("Failed to connect to WiFi on startup");
    }
  }

  fontSetup();

  //
  if(advertisePwngrid) {
    logMessage("Pwngrid advertisement enabled");
    initPwngrid();
  } else {
    logMessage("Pwngrid advertisement disabled");
  }
  // ^ please leave this as it is, dont change its position, otherwise heap will corrupt(HOW!!?)

  // check if core dump exists
  #ifdef ENABLE_COREDUMP_LOGGING
  if (esp_core_dump_image_check() == ESP_OK) {
    if(true) { 
      sendCrashReport();
      drawInfoBox("", "", "", false, false);
      updateUi(false, false, true);
    }
    else{
      //lets clear coredump as config was changed
      esp_core_dump_image_erase();
      logMessage("Config changed, erasing existing core dump");
    }
  } else {
    logMessage("Core dump image not found");
  }
  #endif

  if(pwnagothiModeEnabled) {
    logMessage("Pwnagothi mode enabled");
    pwnagothiBegin();
  } else {
    logMessage("Pwnagothi mode disabled");
  }

  esp_task_wdt_deinit();
  esp_task_wdt_init(60, false); 


  //inbox check
  if(check_inbox_at_startup && WiFi.isConnected()){
    setGeneratingKeysMood();
    updateUi(false, false, true);
    logMessage("Checking inbox for new messages at startup");
    api_client::init(KEYS_FILE);
    int8_t messages = api_client::checkNewMessagesAmount();
    if(messages <= 0){}
    else{
      setNewMessageMood(messages);
      updateUi(false, false, true);
      delay(5000);
    }
  }

  //For everyone that sees this code and thinks why am I limiting features based on partition address:
  //The generic install provides a otadata partition that I can use for updates.
  //Custom installs may not have that partition, so to prevent bricking the device
  //I am disabling update functionality for custom installs.
  //If you are an advanced user and know what you are doing, feel free to remove this check.
  // Detect partition table layout
  const esp_partition_t *part_app0 = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
  const esp_partition_t *part_app1 = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
  const esp_partition_t *part_vfs = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, NULL);
  const esp_partition_t *part_spiffs = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_SPIFFS, NULL);
  const esp_partition_t *part_coredump = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, NULL);
  
  uint32_t app1_size = part_app1 ? part_app1->size : 0;

  logMessage("Partition layout detection:");
  logMessage("App0 size: " + String(part_app0->size, HEX));
  logMessage("App0 address: " + String(part_app0->address, HEX));
  logMessage("App1 address: " + String(part_app1->address, HEX));
  logMessage("App1 size: " + String(app1_size, HEX));
  if (part_vfs) {
    logMessage("VFS partition found at address: " + String(part_vfs->address, HEX));
  } else {
    logMessage("VFS partition not found");
  }
  if (part_spiffs) {
    logMessage("SPIFFS partition found at address: " + String(part_spiffs->address, HEX));
  } else {
    logMessage("SPIFFS partition not found");
  }
  if (part_coredump) {
    logMessage("Coredump partition found at address: " + String(part_coredump->address, HEX));
  } else {
    logMessage("Coredump partition not found");
  }
  
  //Generic:
  //Partition layout detection:
  //App0 size: 330000
  //App0 address: 10000
  //App1 address: 10000
  //App1 size: 330000
  //VFS partition not found
  //SPIFFS partition found at address: 670000
  //Coredump partition found at address: 7f0000
  logMessage("Evaluating install type for feature limitations...");
  setMoodToStatus();
  updateUi(true, false, true);
  logMessage("Evaluating install type for feature limitations...");
  if (part_spiffs && part_spiffs->address == 0x670000 && app1_size == 0x330000 && part_coredump && !part_vfs && part_app0->size == 0x330000) {
    logMessage("Generic install detected!");
    if(newVersionAvailable) {
      drawHintBox("A new firmware version is available!\nPlease update via the menu\nPlease note tha bugs from older version will not be reviewed!", 3);
    }
    logMessage("No feature limitations applied.");
    drawHintBox("Welcome to M5Gotchi!\nSet your device name in setting and explore!\nEnjoy your stay! (Regardless of your choice this will only be shown once)", 13);
    //now lets disable entirely hint 13 regardless of user choice
    hintsDisplayed |= (1 << 13);
    saveSettings();
    drawHintBox("Hi there!\nPress esc to open menu.\nUse arrows to navigate.\nSometimes keyboard.\nLook around, and enjoy!", 2);
    return;
  }
  else {
    drawHintBox("Welcome to M5Gotchi!\nSet your device name in setting and explore!\nEnjoy your stay! (Regardless of your choice this will only be shown once)", 13);
    //now lets disable entirely hint 13 regardless of user choice
    hintsDisplayed |= (1 << 13);
    saveSettings();
    logMessage("Custom install detected, removing update functionality to prevent bricking!");
    limitFeatures = true;
  }

  if(limitFeatures){
    drawHintBox("For the best experience please use M5Burner to install this firmware.", 1);
  }
  drawHintBox("Hi there!\nPress esc to open menu.\nUse arrows to navigate.\nSometimes keyboard.\nLook around, and enjoy!", 2);
  if(newVersionAvailable) {
    drawHintBox("A new firmware version is available!\nPlease update via the menu\nPlease note tha bugs from older version will not be reviewed!", 3);
  }
}

void loop() {
  M5.update();
  M5Cardputer.update();
  updateUi(true);
  if(M5Cardputer.Keyboard.isKeyPressed(KEY_OPT) && M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) && M5Cardputer.Keyboard.isKeyPressed(KEY_FN)){
    // Toggle dev menu instead of crashing the device
    drawInfoBox("DevTools", "Opening developer tools...", "", false, false);
    delay(200);
    runApp(99);
  }
}

void Sound(int frequency, int duration, bool sound){
  if(sound && isSoundPlayed==false){
    isSoundPlayed = true;
    M5Cardputer.Speaker.tone(frequency, duration);
  }
  else if (isSoundPlayed == true){
    isSoundPlayed = false;
  }
  isSoundPlayed = false;
}

void fontSetup(){
  if(SD.exists("/fonts/big.vlw") && SD.exists("/fonts/small.vlw")){
    logMessage("Fonts folder already exists, skipping download");
    return;
  }
  //lets check if wifi is connected
  if(WiFi.status() != WL_CONNECTED){
    logMessage("WiFi not connected, cannot download fonts");
    if(drawQuestionBox("Setup fonts?", "Fonts not present, install them now? WiFi is not connected, connect now?", "", "This will take a few seconds")){
      logMessage("User opted to connect to WiFi for font download");
      drawInfoBox("WiFi Setup", "Please connect to WiFi to download fonts.", "", false, false);
      runApp(43); //WiFi setup app
      setToMainMenu();
    }
  }
  if(WiFi.status() != WL_CONNECTED){
    logMessage("WiFi still not connected, aborting font download");
    drawInfoBox("Font Download", "WiFi not connected, cannot download fonts.", "", false, true);
    return;
  }
  //now lets check if fonts folder exists, if not create it
  if(!SD.exists("fonts")){
    if(drawQuestionBox("Setup fonts?", "Fonts not present, install them now? If not installed, moods will not display correctly.", "", "This will take a few seconds")){
      drawInfoBox("Downloading...", "Downloading fonts, please wait...", "", false, false);
      downloadFonts();
      drawInfoBox("Download complete", "Fonts downloaded successfully.", "", false, false);
    }
  }
}
