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
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include "esp_system.h"
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
const size_t chunkSize = 3 * 1024; // 3 KiB chunk size

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
  // Worst-case Base64 size for chunkSize bytes
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

    // Read raw bytes from flash at the returned address
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
    delay(10); // Slight delay to avoid flooding
  }

  free(base64Out);
  free(buffer);
  client.publish(mqttTopic, ("End from esp32, mac: " + String(WiFi.macAddress())).c_str(), true);
  logMessage("Core dump sent successfully");
  delay(500); // Ensure all messages are sent before disconnecting
  client.disconnect();
  logMessage("MQTT disconnected");
  // Erase core dump image after sending
  esp_core_dump_image_erase();
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
  wifion();

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
    } else {
      logMessage("Failed to connect to WiFi on startup");
    }
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

  if(pwnagothiModeEnabled) {
    logMessage("Pwnagothi mode enabled");
    pwnagothiBegin();
  } else {
    logMessage("Pwnagothi mode disabled");
  }

  initPwngrid();
  esp_task_wdt_deinit();
  esp_task_wdt_init(60, false); 


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
  // [4818][I][logger.cpp] Partition layout detection:
  // [4818][I][logger.cpp] App0 size: 330000
  // [4819][I][logger.cpp] App0 address: 10000
  // [4821][I][logger.cpp] App1 address: 10000
  // [4825][I][logger.cpp] App1 size: 330000
  // [4828][I][logger.cpp] VFS partition not found
  // [4832][I][logger.cpp] SPIFFS partition found at address: 670000
  // [4838][I][logger.cpp] Coredump partition found at address: 7f0000
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
