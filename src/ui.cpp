#include "ui.h"
#define ROW_SIZE 40
#define PADDING 10

// M5Canvas canvas_peers_menu(&M5.Display);
// M5Cardputer.BtnA.isPressed() - go button

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
M5Canvas bar_right(&M5.Display);

menu main_menu[] = {
    {"Wifi", 1},
    {"Bluetooth", 2},
    {"IR", 3},
    {"Pwngotchi", 4},
    {"Bad USB", 5},
    {"Settings", 6}
};

menu wifi_menu[] = {
    {"Select Networks", 20},
    {"Clone & Details", 21},
    {"Evil portal", 22},
    {"Deauth", 23},
    {"Sniffing", 24}
};

menu bluetooth_menu[] = {
    {"BLE Spam", 25},
    {"Connect to phone", 26},
    {"Emulate BT Speaker", 27},
    {"Chat", 28}, 
    {"Scan", 29},
    {"Turn off", 30}
};

menu IR_menu[] = {
    {"Saved remotes", 31},
    {"Send IR", 32},
    {"Recerve IR", 33},
    {"Learn new Remote", 34},
    {"Import from SD", 35}
};

menu pwngotchi_menu[] = {
    {"Turn on", 36},
    {"Turn off", 37},
    {"Whitelist", 38},
    {"Handshakes", 39}
};

menu settings_menu[] = {
    {"Change Hostname", 40},
    {"Display brightness", 41},
    {"Sound", 42},
    {"Connect to wifi", 43},
    {"Update system", 44},
    {"About", 45},
    {"Power off", 46}
};


uint8_t menu_current_pages = 1;
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
uint8_t menu_len;
uint8_t menu_current_opt = 0;
uint8_t menu_current_page = 1;
bool singlePage;
uint8_t menuID = 0;

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
  canvas_main.createSprite(display_w - (display_w * 0.02), canvas_h);
  bar_right.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );

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
    if (menuID == true) {
      menu_current_opt = 0;
      menu_current_page = 1;
      menuID = 0;
    } else {
      menuID = 1;
      menu_current_opt = 0;
      menu_current_page = 1;
    }
  }

  uint8_t mood_id = getCurrentMoodId();
  String mood_face = getCurrentMoodFace();
  String mood_phrase = getCurrentMoodPhrase();
  bool mood_broken = isCurrentMoodBroken();

  drawTopCanvas();
  drawBottomCanvas();
  

  if (menuID == 1) {
    menu_len = 6;
    drawMultiplePages(main_menu, 1, 6);
    drawMenu();
  } 
  else if (menuID == 2){
    drawSinglePage( wifi_menu , 2, 5);
    drawMenu();
  }
  else if (menuID == 3){
    drawMultiplePages( bluetooth_menu , 3, 6);
    drawMenu();
  }
  else if (menuID == 4){
    drawMultiplePages( IR_menu , 4, 5);
    drawMenu();
  }
  else if (menuID == 5){
    drawMultiplePages( pwngotchi_menu , 5, 4);
    drawMenu();
  }
  else if (menuID == 6){
    drawMultiplePages( settings_menu , 6, 7);
    drawMenu();
  }  
  else if (menuID == 0)
  {
    drawMood(mood_face, mood_phrase, mood_broken);
  }

  drawRightBar();

  M5.Display.startWrite();
  if (show_toolbars) {
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    
    //bar_right1.pushSprite(display_w * 0.98, 2*(canvas_top_h + 3));
  }
  if (menu_current_pages = 1 ){
    bar_right.pushSprite(display_w * 0.98, canvas_top_h + 5);
    for(uint8_t m = 0; m <= 3 ; m++){
      Serial.println("trigger");
      bar_right.pushSprite(display_w * 0.98, ( canvas_top_h + 5 ) + (m * ((canvas_h - 6)/4)) - 1 );
    }
  }
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
}

void drawRightBar() {
  if(menuID){
    bar_right.fillSprite(BLACK);}  
  else { 
    bar_right.fillSprite(WHITE);
  }
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

  canvas_bot.drawString(String(menu_current_page) + "  " + String(menu_current_opt) , 0, 5);
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


void drawSinglePage(menu toDraw[], uint8_t menuIDPriv, uint8_t menuSize ) {
  menu_current_pages = 1;
  menu_len = menuSize;
  menuID = menuIDPriv;
  singlePage = true;
  canvas_main.fillSprite(WHITE); //Clears main display
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(top_left);
  char display_str[50] = "";
   
  for (uint8_t i = 0; i < 5; i++) {
     sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ",
             toDraw[i].name);
     int y = PADDING + (i * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  
}

void drawMultiplePages(menu toDraw[], uint8_t menuIDPriv, uint8_t menuSize) {
  menuID = menuIDPriv;
  menu_len = menuSize;
  singlePage = false;
  canvas_main.fillSprite(WHITE); //Clears main display
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(top_left);
  char display_str[50] = "";
  if(menu_current_page == 1){
   
  for (uint8_t i = 0; i < 5; i++) {
     sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ",
             toDraw[i].name);
     int y = PADDING + (i * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
  else if(menu_current_page == 2){
    for (uint8_t j = 0; j < (menuSize - 5) ; j++) {
     sprintf(display_str, "%s %s", (menu_current_opt == j+5) ? ">" : " ",
             toDraw[j+5].name);
     int y = PADDING + (j * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
  else if(menu_current_page == 3){
    for (uint8_t k = 0; k < (menuSize - 10) ; k++) {
     sprintf(display_str, "%s %s", (menu_current_opt == k+10) ? ">" : " ",
             toDraw[k+10].name);
     int y = PADDING + (k * ROW_SIZE / 2);
     canvas_main.drawString(display_str, 0, y);
    }
  }
  else if(menu_current_page == 4){
    for (uint8_t l = 0; l < (menuSize - 15) ; l++) {
     sprintf(display_str, "%s %s", (menu_current_opt == l+15) ? ">" : " ",
             toDraw[l+15].name);
     int y = PADDING + (l * ROW_SIZE / 2);
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


void drawAboutMenu() {
  canvas_main.clear(WHITE);
}

void runApp(uint8_t appID){
  menu_current_opt = 0;
  menu_current_page = 1;
  menuID = 0; 
  if(appID){
    if(appID == 1){drawSinglePage(wifi_menu, 2, 5);}
    if(appID == 2){drawMultiplePages(bluetooth_menu, 3, 6);}
    if(appID == 3){drawSinglePage(IR_menu, 4, 5 );}
    if(appID == 4){drawSinglePage(pwngotchi_menu, 5 , 3 );}
    if(appID == 5){}
    if(appID == 6){drawMultiplePages( settings_menu , 6, 7);}
    if(appID == 7){}
    if(appID == 8){}
    if(appID == 9){}
    if(appID == 10){}
    if(appID == 11){}
    if(appID == 12){}
    if(appID == 13){}
    if(appID == 14){}
    if(appID == 15){}
    if(appID == 16){}
    if(appID == 17){}
    if(appID == 18){}
    if(appID == 19){}
    if(appID == 20){}
    if(appID == 21){}
    if(appID == 22){}
    if(appID == 23){}
    if(appID == 24){}
    if(appID == 25){}
    if(appID == 26){}
    if(appID == 27){}
    if(appID == 28){}
    if(appID == 29){}
    if(appID == 30){}
    if(appID == 31){}
    if(appID == 32){}
    if(appID == 33){}
    if(appID == 34){}
    if(appID == 35){}
    if(appID == 36){}
    if(appID == 37){}
    if(appID == 38){}
    if(appID == 39){}
    if(appID == 40){}
  }
  return;
}

void drawMenu() {
  if (isNextPressed()) {
    if (menu_current_opt < menu_len - 1 ) {
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
      menu_current_opt = (menu_len - 1);
    }
  }

  if(isOkPressed()){
    if(menuID == 1){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(main_menu[menu_current_opt].command);
    }
  }
  if(!singlePage){
    if(menu_current_opt < 5 && menu_current_page != 1){
        menu_current_page= 1;
      
    } else if(menu_current_opt >= 5 && menu_current_page != 2){
        menu_current_page = 2;
      
  }
  }
  //uint8_t test = main_menu[1].command; - how to acces 2`nd column - for me
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
