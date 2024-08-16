#include "M5Cardputer.h"
#include "M5Unified.h"
#include "ui.h"

#define STATE_INIT 0
#define STATE_WAKE 1
#define STATE_HALT 255

uint8_t state;
uint8_t activity = 4;
long time_passed;
double time_;

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
  M5.begin();
  M5.Display.begin();
  M5Cardputer.begin(cfg);
  M5Cardputer.Keyboard.begin();
}

void setup() {
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
  updateActivity();
  M5.update();
  M5Cardputer.update();

  if (state == STATE_HALT) {
    return;
  }

  if (state == STATE_INIT) {
    wakeUp();
    state = STATE_WAKE;
  }
  updateUi(true);
}

void updateActivity() {
  time_passed = millis();
  time_ = (time_passed / 1000) / 60;
  if (time_==2) {
    time_ = 0;
    activity--;
    setMood(activity_level[activity]);
  }
}