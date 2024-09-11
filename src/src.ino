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


uint8_t activity_level[] = {
  17,
  18,
  16,
  15,
  0,
  1,
  2,
  3,
  11,
  13,
  4,
  5,
  6,
  7,
  9,
  8,
  14,
  19,
  20,
  10,
  12,
  21
};
//this decides what face/splash will be displayed based on acivity variable

void initM5() {
  auto cfg = M5.config();
  M5.begin(cfg  );
  M5.Display.begin();
  M5Cardputer.begin(cfg);
  M5Cardputer.Keyboard.begin();
}

void setup() {
  Serial.begin(9600);
  initM5();
  initUi();
  state = STATE_INIT;
}

uint32_t last_mood_switch = 10001;

void wakeUp() {
  for (uint8_t i = 0; i < 3; i++) {
    setMood(activity_level[activity]);
    activity ++;
    updateUi();
    delay(1250);
  }
}


void loop() {
  unsigned long currentMillis = millis();
  //updateActivity();
  M5.update();
  M5Cardputer.update();
  if(M5Cardputer.BtnA.isPressed()){
    M5.Lcd.setBrightness(0);
    M5.Display.fillScreen(TFT_BLACK);
    delay(500);
    while(true){
      M5.update();
      M5Cardputer.update();
      if(M5Cardputer.BtnA.isPressed()){break;}
    }
    M5.Lcd.setBrightness(returnBrightness());
    initUi();
    delay(500);
  }
  if (state == STATE_HALT) {
    return;
  }

  if (state == STATE_INIT) {
    wakeUp();
    state = STATE_WAKE;
  }
  updateUi(true);
  if (currentMillis >= interval) {
    interval = interval + 120000;  // Zaktualizowanie czasu ostatniego wykonania funkcji
    updateActivity();  // Wykonanie funkcji co 2 minuty
    //Serial.print("if triggered");
  }
  
  if(activity > 21){
    activity = 5;
  }
  else
  {
    setMood(activity_level[activity]);
  }
  if(activityRewarded()){activity++;}
  //Serial.println(String(currentMillis));
  
}

void updateActivity() {
  //Serial.println("function triggered");
    if(activity==0){
      return ;
    }
    else{
      activity = activity -1;
    }
}
bool isSoundPlayed = true;
void Sound(int frequency, int duration, bool sound){
  if(sound && isSoundPlayed==false){
    M5Cardputer.Speaker.tone(frequency, duration);
    isSoundPlayed = true;
  }
  else if (isSoundPlayed == true){
    isSoundPlayed = false;
  }
}