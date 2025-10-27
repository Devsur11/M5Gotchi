#include "M5Cardputer.h"
#include "M5Unified.h"
#include "ui.h"
#include "settings.h"
#include "mood.h"
#include "pwnagothi.h"
#include "moodLoader.h"
#include "Arduino.h"
#ifdef LITE_VERSION
#include "githubUpdater.h"
#include "wpa_sec.h"
#endif

uint8_t state;
uint8_t activity = 14;
unsigned long previousMillis = 0;  // Zmienna do przechowywania ostatniego czasu wykonania funkcjami
unsigned long interval = 120000;  // 2 minuty w milisekundach (2 * 60 * 1000)
bool firstSoundEnable;
bool isSoundPlayed = false;
uint32_t last_mood_switch = 10001;
uint8_t wakeUpList[] = {0, 1, 2};

void initM5() {
  auto cfg = M5.config();
  M5.begin(cfg);
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Keyboard.begin();
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_MODE_STA);
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);  
  logMessage("System booting...");
  initM5();
  initVars();
  M5.Display.setBrightness(brightness);
  initColorSettings();
  initUi();
  preloadMoods();
  if(initVars()){}
  else{
    #ifndef BYPASS_SD_CHECK
    drawInfoBox("ERROR!", "SD card is needed to work.", "Insert it and restart", false, true);
    while(true){delay(10);}
    #endif
  }
  wakeUp();
  #ifdef LITE_VERSION
  #ifndef SKIP_AUTO_UPDATE
  drawInfoBox("Update", "Checking for updates", "Please wait...", false, false);
  WiFi.begin(savedApSSID.c_str(), savedAPPass.c_str());
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
  #endif
  #endif

  if(pwnagothiModeEnabled) {
    logMessage("Pwnagothi mode enabled");
    pwnagothiBegin();
  } else {
    logMessage("Pwnagothi mode disabled");
  }
}

void wakeUp() {
  for (uint8_t i = 0; i <= 2; i++) {
    setMood(wakeUpList[i]);
    updateUi();
    delay(1250);
  }
}


void loop() {
  unsigned long currentMillis = millis();
  M5.update();
  M5Cardputer.update();
  if(M5Cardputer.Keyboard.isKeyPressed(KEY_OPT) && M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) && M5Cardputer.Keyboard.isKeyPressed(KEY_FN)){
    speedScanTestAndPrintResults();
    //esp_will_beg_for_its_life();
  }

  updateUi(true);
  if(!pwnagothiMode)  {
    if (currentMillis >= interval) {
      interval = interval + 120000;  // Zaktualizowanie czasu ostatniego wykonania funkcji
      updateActivity(false);  // Wykonanie funkcji co 2 minuty
      setMood(activity);
      logMessage("Mood changed");
    }
    setMood(activity);
  }
}

void updateActivity(bool reward = false) {
  if(reward){
    if(activity == 2 || activity == 26){
      activity = 10;
    }
    else{
      activity++;
    }
  }
  else{
    if(activity==0){  
    }
    else{
      activity--;
    }
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