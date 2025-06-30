#pragma once
#include <Arduino.h>
#include <SPI.h>

#define CURRENT_VERSION "0.3.3"
#define NORMAL_JSON_URL "https://devsur11.github.io/m5gothi/firmware/firmware.json"
#define LITE_JSON_URL   "https://devsur11.github.io/m5gothi/firmware/lite.json"
#define TEMP_DIR        "/temp"
#define TEMP_JSON_PATH  TEMP_DIR "/update.json"
#define TEMP_BIN_PATH   TEMP_DIR "/update.bin"
//#define LITE_VERSION
#define SERIAL_LOGS
//#define BYPASS_SD_CHECK
//#define USE_EXPERIMENTAL_APPS
#define SD_CS    12  // G12
#define SD_MOSI  14  // G14
#define SD_SCK   40  // G40
#define SD_MISO  39  // G39
#define MAX_PKT_SIZE 3000
#define ROW_SIZE 40
#define PADDING 10

bool initVars();
bool saveSettings();

extern String hostname;
extern bool sound;
extern int brightness;
extern uint16_t pwned_ap;
extern SPIClass sdSPI;
extern String savedApSSID;
extern String savedAPPass;
extern String whitelist;
extern bool pwnagothiMode;
extern uint8_t sessionCaptures;
extern bool pwnagothiModeEnabled;