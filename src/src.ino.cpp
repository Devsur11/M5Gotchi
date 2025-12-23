# 1 "/tmp/tmppy7w_qyj"
#include <Arduino.h>
# 1 "/home/devsur/Github/ESPBlaster/src/src.ino"
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
#ifdef ENABLE_COREDUMP_LOGGING
#include "esp_core_dump.h"
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "esp_system.h"
#include "mbedtls/base64.h"
#endif
#include "githubUpdater.h"
#include "wpa_sec.h"
#include "esp_partition.h"
#include "fontDownloader.h"

const esp_partition_t *coredump_part =
    esp_partition_find_first(ESP_PARTITION_TYPE_DATA,
                             ESP_PARTITION_SUBTYPE_DATA_COREDUMP,
                             NULL);


bool firstSoundEnable;
bool isSoundPlayed = false;

#ifdef ENABLE_COREDUMP_LOGGING

extern const char emqxsl_root_cert_pem_start[] asm("_binary_certs_emqxsl_ca_pem_start");
extern const char emqxsl_root_cert_pem_end[] asm("_binary_certs_emqxsl_ca_pem_end");

WiFiClientSecure espClient;
PubSubClient client(espClient);


size_t coredump_addr = 0;
size_t coredump_size = 0;
const size_t chunkSize = 3 * 1024;

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
void connectMQTT();
void sendCoredump();
void initM5();
void setup();
void loop();
void Sound(int frequency, int duration, bool sound);
void fontSetup();
#line 65 "/home/devsur/Github/ESPBlaster/src/src.ino"
void connectMQTT() {
  espClient.setCACert(emqxsl_root_cert_pem_start);
  client.setServer(mqttServer, mqttPort);
  int retries = 0;
  const int maxRetries = 3;
  while (!client.connected() && retries < maxRetries) {
    if (client.connect("ESP32S3Client", mqttUser, mqttPassword)) {
      logMessage("MQTT Connected");
      client.publish(mqttTopic, ("hello from esp32, mac: " + String(WiFi.macAddress())).c_str(), false);
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

void sendCoredump() {
  size_t addr = 0;
  size_t size = 0;
  esp_err_t res = esp_core_dump_image_get(&addr, &size);
  if (res != ESP_OK || size == 0) {
    logMessage("No core dump image available");
    return;
  }

  logMessage("Core dump image found via esp_core_dump_image_get");
  logMessage("Core dump addr: " + String(addr) + ", size: " + String(size));

  uint8_t *buffer = (uint8_t*)malloc(chunkSize);
  if (!buffer) {
    logMessage("Failed to allocate coredump buffer");
    return;
  }

  size_t maxB64 = (chunkSize * 4 / 3) + 8;
  char *base64Out = (char*)malloc(maxB64);
  if (!base64Out) {
    logMessage("Failed to allocate base64 buffer");
    free(buffer);
    return;
  }

  size_t offset = 0;
  while (offset < size) {
    size_t readLen = chunkSize;
    if (offset + readLen > size) {
      readLen = size - offset;
    }


    if (spi_flash_read((uint32_t)(addr + offset), buffer, readLen) != ESP_OK) {
      logMessage("Flash read failed");
      break;
    }

    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char*)base64Out, maxB64, &olen, buffer, readLen) != 0) {
      logMessage("Base64 encode failed");
      break;
    }

    bool ok = client.publish(mqttTopic, base64Out, (uint16_t)olen);
    if (!ok) {
      logMessage("MQTT publish failed");
      return;
    }

    uint8_t state = client.state();
    logMessage("MQTT publish state: " + String(state));

    offset += readLen;
    delay(10);
  }

  free(base64Out);
  free(buffer);
  client.publish(mqttTopic, ("End from esp32, mac: " + String(WiFi.macAddress())).c_str(), true);
  logMessage("Core dump sent successfully");
  delay(500);
  client.disconnect();
  logMessage("MQTT disconnected");

  esp_core_dump_image_erase();
}

#endif

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
    digitalWrite(LORA_RST, LOW);
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



  if (!initMoodsFromSD()) {
    logMessage("Moods: failed to initialize from SD, using defaults");
  } else {
    logMessage("Moods: initialized from SD");
  }

  setMoodToStartup();
  updateUi(false, false);
  logMessage("Heap after mood preload:");
  printHeapInfo();
  wifion();

  #ifdef ENABLE_COREDUMP_LOGGING
  esp_core_dump_init();
  #endif


  bool newVersionAvailable = false;
  if(connectWiFiOnStartup){
    attemptConnectSavedNetworks();
    logMessage("Heap after attempting WiFi connect:");
    printHeapInfo();
    if(WiFi.status() == WL_CONNECTED){
      logMessage("Connected to WiFi on startup");
      delay(1000);
    } else {
      logMessage("Failed to connect to WiFi on startup");
    }

    logMessage(String(ESP.getFreeHeap()) + " bytes free heap before checking updates");
    if(checkUpdatesAtNetworkStart) {
      logMessage("Checking for updates on network start");
      if(check_for_new_firmware_version(false)) {
        logMessage("New firmware version available on startup");
        newVersionAvailable = true;
      } else {
        logMessage("No new firmware version found on startup");
      }
    }
  }
  logMessage("Heap after WiFi init:");
  printHeapInfo();
  fontSetup();
  logMessage("Heap after font setup:");
  printHeapInfo();

  initPwngrid();



  #ifdef ENABLE_COREDUMP_LOGGING
  if (esp_core_dump_image_check() == ESP_OK) {
    logMessage("Core dump image found");
    sendCrashReport();
  } else {
    logMessage("Core dump image not found");
  }
  #endif
  #ifdef LITE_VERSION
  #ifndef SKIP_AUTO_UPDATE
  if(checkUpdatesAtNetworkStart) {
    drawInfoBox("Update", "Checking for updates", "Please wait...", false, false);
    attemptConnectSavedNetworks();
    delay(5000);
      if(check_for_new_firmware_version(true)) {
      drawInfoBox("Update", "New firmware version available", "Downloading...", false, false);
      delay(1000);
      logMessage("New firmware version available, downloading...");
      if(ota_update_from_url(true)) {
        drawInfoBox("Update", "Update successful", "Restarting...", false, false);
        logMessage("Update successful, restarting...");
        delay(1000);
        ESP.restart();
      } else {
        logMessage("Update failed");
      }
    } else {
      drawInfoBox("Update", "No new firmware version found", "Booting...", false, false);
      logMessage("No new firmware version found, or wifi not connected");
      delay(1000);
    }
    if(WiFi.status() == WL_CONNECTED) {
      if(lite_mode_wpa_sec_sync_on_startup){
        logMessage("Syncing known networks with WPA_SEC");
        processWpaSec(wpa_sec_api_key.c_str());
      }
    }
  }
  #endif
  #endif

  logMessage("Heap after Pwngrid init:");
  printHeapInfo();

  if(pwnagothiModeEnabled) {
    logMessage("Pwnagothi mode enabled");
    pwnagothiBegin();
  } else {
    logMessage("Pwnagothi mode disabled");
  }
  initPwngrid();
  esp_task_wdt_deinit();
  esp_task_wdt_init(60, false);
# 306 "/home/devsur/Github/ESPBlaster/src/src.ino"
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
# 344 "/home/devsur/Github/ESPBlaster/src/src.ino"
  logMessage("Evaluating install type for feature limitations...");
  setMoodToStatus();
  if (part_spiffs && part_spiffs->address == 0x670000 && app1_size == 0x330000 && part_coredump && !part_vfs && part_app0->size == 0x330000) {
    logMessage("Generic install detected!");
    if(newVersionAvailable) {
      drawHintBox("A new firmware version is available!\nPlease update via the menu\nPlease note tha bugs from older version will not be reviewed!", 3);
    }
    logMessage("No feature limitations applied.");
    drawHintBox("Hi there!\nPress esc to open menu.\nUse arrows to navigate.\nSometimes keyboard.\nLook around, and enjoy!", 2);
    return;
  }
  else {
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
  if(M5Cardputer.Keyboard.isKeyPressed(KEY_OPT) && M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) && M5Cardputer.Keyboard.isKeyPressed(KEY_FN)){

    drawInfoBox("DevTools", "Opening developer tools...", "", false, false);
    delay(200);
    runApp(99);
  }
  updateUi(true);
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

  if(WiFi.status() != WL_CONNECTED){
    logMessage("WiFi not connected, cannot download fonts");
    if(drawQuestionBox("Setup fonts?", "Fonts not present, install them now? WiFi is not connected, connect now?", "", "This will take a few seconds")){
      logMessage("User opted to connect to WiFi for font download");
      drawInfoBox("WiFi Setup", "Please connect to WiFi to download fonts.", "", false, false);
      runApp(43);
    }
  }
  if(WiFi.status() != WL_CONNECTED){
    logMessage("WiFi still not connected, aborting font download");
    drawInfoBox("Font Download", "WiFi not connected, cannot download fonts.", "", false, true);
    return;
  }

  if(!SD.exists("fonts")){
    if(drawQuestionBox("Setup fonts?", "Fonts not present, install them now? If not installed, moods will not display correctly.", "", "This will take a few seconds")){
      drawInfoBox("Downloading...", "Downloading fonts, please wait...", "", false, false);
      downloadFonts();
      drawInfoBox("Download complete", "Fonts downloaded successfully.", "", false, false);
    }
  }
}