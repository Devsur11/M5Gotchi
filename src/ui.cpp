#include "ui.h"

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
// M5Canvas canvas_peers_menu(&M5.Display);
// M5Cardputer.BtnA.isPressed() - go button

struct menu {
  char name[25];
  int command;
};

menu main_menu[] = {
    {"Wifi", 1},
    {"Bluetooth", 2},
    {"IR", 3},
    {"Pwngotchi", 4},
    {"Bad USB", 5},
    {"Settings", 6},
    
};

menu wifi_menu[] = {
    {"Select Networks", 20},
    {"Clone & Details", 21},
    {"Evil portal", 22},
    {"Deauth", 23},
    {"Sniffing", 24},
    {"Turn off wifi", 25},
};

menu settings_menu[] = {
    {"Change Hostname", 40},
    {"Display brightness", 41},
    {"Sound", 42},
    {"Connect to wifi", 43},
    {"Update system", 44},
    {"About", 45},
    {"Power off", 46},
};



int32_t display_w;
int32_t display_h;
int32_t canvas_h;
int32_t canvas_center_x;
int32_t canvas_top_h;
int32_t canvas_bot_h;
int32_t canvas_peers_menu_h;
int32_t canvas_peers_menu_w;
String hostname = "dfku"; //TODO: add support for sd card here
bool keyboard_changed = false;
int main_menu_len = sizeof(main_menu) / sizeof(menu);
int settings_menu_len = sizeof(settings_menu) / sizeof(menu);



uint8_t menu_current_cmd = 0;
uint8_t menu_current_opt = 0;
uint8_t menu_current_page = 1;


bool menu_open = false;
bool main_menu_ = false;
bool wifi_menu_ = false;
bool bluetooth_menu_ = false;
bool ir_menu_ = false;
bool pwngotchi_menu_ = false;
bool badusb_menu_ = false;
bool settings_menu_ = false;


void initUi() {
  M5.Display.setRotation(1);
  M5.Display.setTextFont(&fonts::Font0);
  M5.Display.setTextSize(1);
  M5.Display.fillScreen(TFT_WHITE);
  M5.Display.setTextColor(BLACK);
  M5.Display.setColor(BLACK);

  display_w = M5.Display.width();
  display_h = M5.Display.height();
  canvas_h = display_h * .8;
  canvas_center_x = display_w / 2;
  canvas_top_h = display_h * .1;
  canvas_bot_h = display_h * .1;
  canvas_peers_menu_h = display_h * .8;
  canvas_peers_menu_w = display_w * .8;

  canvas_top.createSprite(display_w, canvas_top_h);
  canvas_bot.createSprite(display_w, canvas_bot_h);
  canvas_main.createSprite(display_w, canvas_h);
}



bool toggleMenuBtnPressed() {
  return (keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed('`')));
}

bool isOkPressed() {
  return (keyboard_changed && M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER));
}

bool isNextPressed() {
  return keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed('.') );
}
bool isPrevPressed() {
  return keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed(';'));
}

void updateUi(bool show_toolbars) {
  keyboard_changed = M5Cardputer.Keyboard.isChange();

  if (toggleMenuBtnPressed()) {
    // If menu is open, return to main menu
    // If not, toggle menu
    if (menu_open == true) {
      menu_current_cmd = 0;
      menu_current_opt = 0;
      main_menu_ = false;
      wifi_menu_ = false;
      bluetooth_menu_ = false;
      ir_menu_ = false;
      pwngotchi_menu_ = false;
      badusb_menu_ = false;
      settings_menu_ = false;
      menu_current_page = 1;
      menu_open = 0;
    } else {
      menu_open = 1; 
      main_menu_ = 1;
    }
  }

  uint8_t mood_id = getCurrentMoodId();
  String mood_face = getCurrentMoodFace();
  String mood_phrase = getCurrentMoodPhrase();
  bool mood_broken = isCurrentMoodBroken();

  drawTopCanvas();
  drawBottomCanvas();

  if (menu_open) {
    drawMenu();
  } else {
    drawMood(mood_face, mood_phrase, mood_broken);
  }

  M5.Display.startWrite();
  if (show_toolbars) {
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
  }
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
}

void drawTopCanvas() {
  canvas_top.fillSprite(WHITE);
  canvas_top.setTextSize(1);
  canvas_top.setTextColor(BLACK);
  canvas_top.setColor(BLACK);
  canvas_top.setTextDatum(top_left);
  canvas_top.drawString("ESPBlaster v0.1", 0, 3);
  canvas_top.setTextDatum(top_right);
  /*            part of original code 
  char right_str[50] = "UPS 0%";
  sprintf(right_str, "UPS", M5.Power.getBatteryLevel());
  */
  canvas_top.drawString("UPS " + String(M5.Power.getBatteryLevel()) + "%" , display_w, 3);
  canvas_top.drawLine(0, canvas_top_h - 1, display_w, canvas_top_h - 1);
}

void drawBottomCanvas(uint8_t friends_run, uint8_t friends_tot,
                      String last_friend_name, signed int rssi) {
  canvas_bot.fillSprite(WHITE);
  canvas_bot.setTextSize(1);
  canvas_bot.setTextColor(BLACK);
  canvas_bot.setColor(BLACK);
  canvas_bot.setTextDatum(top_left);

/*
  char stats[25] = "FRND 0 (0)";
  if (friends_run > 0) {
    sprintf(stats, "FRND %d (%d) [%s] %s", friends_run, friends_tot,
            last_friend_name, "");
  }
*/

  canvas_bot.drawString(String(menu_current_page) + "  " + String(menu_current_opt), 0, 5);
  canvas_bot.setTextDatum(top_right);
  canvas_bot.drawString("READY", display_w, 5);
  canvas_bot.drawLine(0, 0, display_w, 0);
}

void drawMood(String face, String phrase, bool broken) {
  if (broken == true) {
    canvas_main.setTextColor(RED);
  } else {
    canvas_main.setTextColor(BLACK);
  }

  canvas_main.setTextSize(4);
  canvas_main.setTextDatum(middle_center);
  canvas_main.fillSprite(WHITE);
  canvas_main.drawString(face, canvas_center_x / 1.5, canvas_h / 3);
  //canvas_main.setTextDatum(bottom_right);
  canvas_main.setTextSize(1.5);
  canvas_main.drawString(hostname + "> " + phrase, canvas_center_x - 10, canvas_h - 35);
}

#define ROW_SIZE 40
#define PADDING 10

void drawMainMenu() {
  canvas_main.fillSprite(WHITE); //Clears main display
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(top_left);
  char display_str[50] = "";
  if(menu_current_page == 1){
   
  for (uint8_t i = 0; i < 5; i++) {
     sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ",
             main_menu[i].name);
     int y = PADDING + (i * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
  else if(menu_current_page == 2){
    for (uint8_t j = 0; j < (main_menu_len - 5) ; j++) {
     sprintf(display_str, "%s %s", (menu_current_opt == j+5) ? ">" : " ",
             main_menu[j+5].name);
     int y = PADDING + (j * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
}
/*
void drawNearbyMenu() {
  canvas_main.clear(BLACK);
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(GREEN);
  canvas_main.setColor(GREEN);
  canvas_main.setTextDatum(top_left);

  
    canvas_main.setTextColor(TFT_DARKGRAY);
    canvas_main.setCursor(0, PADDING);
    canvas_main.println("not yet");
  
}*/

void drawSettingsMenu() {
  canvas_main.fillSprite(WHITE);
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(top_left);

  char display_str[50] = "";
  if(menu_current_page == 1){
   
   for (uint8_t i = 0; i < 5; i++) {
     sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ",
             settings_menu[i].name);
     int y = PADDING + (i * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
  else if(menu_current_page == 2){
    for (uint8_t i = 5; i < settings_menu_len ; i++) {
     sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ",
             settings_menu[i].name);
     int y = PADDING + (i * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
}

void drawAboutMenu() {
  canvas_main.clear(WHITE);
}

void drawMenu() {
  if (isNextPressed()) {
    if (menu_current_opt < main_menu_len - 1 ) {
      menu_current_opt++;
    } else {
      menu_current_opt = 0;
    }
  }

  if (isPrevPressed()) {
    if (menu_current_opt > 0) {
      menu_current_opt--;
    }
    else {
      menu_current_opt = (main_menu_len - 1);
    }
  }

  if(menu_current_opt < 5 && menu_current_page != 1){
      menu_current_page= 1;
      //menu_current_opt--;
//   return false;
  } else if(menu_current_opt >= 5 && menu_current_page != 2){
      menu_current_page = 2;
      //menu_current_opt++;
//   return false;
  }

  if(menu_open == true && main_menu_ == true){
    drawMainMenu();
  }
  //uint8_t test = main_menu[1].command; - how to acces 2`nd column - for me
}

void runApp(uint8_t appID){

}
// bool check_prev_press() {
//   if (M5.Keyboard.isKeyPressed(ARROW_UP)) {
//     return true;
//   }
//
//   return false;
// }
//
// bool check_next_press() {
//   if (M5.Keyboard.isKeyPressed(ARROW_DOWN)) {
//     return true;
//   }
//
//   return false;
// }
