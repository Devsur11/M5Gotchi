#include "M5Cardputer.h"
#include "M5Unified.h"
#include "ui.h"


#define STATE_INIT 0
#define STATE_WAKE 1
#define STATE_HALT 255

uint8_t state;
uint8_t activity = 4;
unsigned long previousMillis = 0;  // Zmienna do przechowywania ostatniego czasu wykonania funkcjami
unsigned long interval = 120000;  // 2 minuty w milisekundach (2 * 60 * 1000)
bool firstSoundEnable;
bool isSoundPlayed = false;
uint32_t last_mood_switch = 10001;
//this decides what face/splash will be displayed based on acivity variable
uint8_t activity_level[] = {17,18,16,15,0,1,2,3,11,13,4,5,6,7,9,8,14,19,20,10,12,21};

void initM5() {
  auto cfg = M5.config();
  M5.begin(cfg);
  //M5.Display.begin();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Keyboard.begin();
}

void setup() {
  Serial.begin(115200);
  initM5();
  //SnifferDebugMode();
  initUi();
  wakeUp();
}

void wakeUp() {
  for (uint8_t i = 0; i <= 2; i++) {
    setMood(activity_level[activity]);
    activity++;
    updateUi();
    delay(1250);
  }
}


void loop() {
  unsigned long currentMillis = millis();
  M5.update();
  M5Cardputer.update();
  sleepFunction();
  // if(M5.BtnA.isPressed()){
  //   logMessage("Button A pressed");
  //   M5.Lcd.setBrightness(0);
  //   M5.Display.fillScreen(TFT_BLACK);
  //   delay(500);
  //   while(true){
  //     M5.update();
  //     M5Cardputer.update();
  //     if(M5.BtnA.isPressed()){break;}
  //   }
  //   M5.Lcd.setBrightness(returnBrightness());
  //   initUi();
  //   delay(500);
  // }
  updateUi(true);
  if (currentMillis >= interval) {
    interval = interval + 120000;  // Zaktualizowanie czasu ostatniego wykonania funkcji
    updateActivity();  // Wykonanie funkcji co 2 minuty
    //Serial.print("if triggered");
  }
  
}

void updateActivity() {
    if(activity==0){  
      return ;
    }
    else{
      activity = activity -1;
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