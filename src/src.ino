#include "M5Cardputer.h"
#include "M5Unified.h"
#include "ui.h"
#include "settings.h"
#include "mood.h"
#include "pwnagothi.h"
#include "githubUpdater.h"

uint8_t state;
uint8_t activity = 14;
unsigned long previousMillis = 0;  // Zmienna do przechowywania ostatniego czasu wykonania funkcjami
unsigned long interval = 120000;  // 2 minuty w milisekundach (2 * 60 * 1000)
bool firstSoundEnable;
bool isSoundPlayed = false;
uint32_t last_mood_switch = 10001;
uint8_t wakeUpList[] = {0, 1, 2};
// Pin mapping from the official docs

void initM5() {
  auto cfg = M5.config();
  M5.begin(cfg);
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Keyboard.begin();
}

void setup() {
  Serial.begin(115200);
  initM5();
  initUi();
  sdSPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);  
  if(initVars()){}
  else{
    #ifndef BYPASS_SD_CHECK
    drawInfoBox("ERROR!", "SD card is needed to work.", "Insert it and restart", false, true);
    while(true){delay(10);}
    #endif
  }
  M5.Display.setBrightness(brightness);
  wakeUp();
  #ifdef LITE_VERSION
  drawInfoBox("Update", "Checking for updates", "Please wait...", false, false);
  WiFi.begin(savedApSSID.c_str(), savedAPPass.c_str());
  delay(5000);
  if(check_for_new_firmware_version(true)) {
    drawInfoBox("Update", "New firmware version available", "Downloading...", false, false);
    delay(1000);
    logMessage("New firmware version available");
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
  #endif

  if(pwnagothiMode) {
    pwnagothiMode = true;
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
  sleepFunction();
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
}