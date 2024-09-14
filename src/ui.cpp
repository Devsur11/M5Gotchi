#include "lgfx/v1/misc/enum.hpp"
#include "lgfx/v1/misc/DataWrapper.hpp"
#include "HWCDC.h"
#include <string>
#include "ui.h"
#include "src.h"
#include "updater.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>
#include <WiFi.h>
#include "customFont.h"

#define ROW_SIZE 40
#define PADDING 10
#define TOMTHUMB_USE_EXTENDED true
// M5Canvas canvas_peers_menu(&M5.Display);
// M5Cardputer.BtnA.isPressed() - go button

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
M5Canvas bar_right(&M5.Display);
M5Canvas bar_right2(&M5.Display);
M5Canvas bar_right3(&M5.Display);
M5Canvas bar_right4(&M5.Display);

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
    {"Emulate BT Keyboard", 27},
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

const uint8_t bitmap1[] = {0x60, 0xE0, 0xE0, 0xC0, 0x60};


bool appRunning;
bool userInputVar;
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
bool activityReward;
bool sound = 1;
uint8_t currentBrightness = 100;

bool activityRewarded(){return activityReward;}

void initUi() {
  M5.Display.setRotation(1);
  //M5.Display.setFont();
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
  bar_right2.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  bar_right3.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  bar_right4.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
}

uint8_t returnBrightness(){return currentBrightness;}

bool toggleMenuBtnPressed() {
  delay(10);
  return (keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed('`')));
}

bool isOkPressed() {
  delay(10);
  return (keyboard_changed && M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER));
}

bool isNextPressed() {
  delay(10);
  return keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed('.') );
}
bool isPrevPressed() {
  delay(10);
  return keyboard_changed && (M5Cardputer.Keyboard.isKeyPressed(';'));
}

void updateUi(bool show_toolbars) {
  keyboard_changed = M5Cardputer.Keyboard.isChange();
  if(keyboard_changed){Sound(10000, 100, sound);}               
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

  String mood_face = getCurrentMoodFace();
  String mood_phrase = getCurrentMoodPhrase();

  drawTopCanvas();
  drawBottomCanvas();
  if (userInputVar){
    //userInput();
  }
  
  if (menuID == 1) {
    menu_current_pages = 2;
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
    drawMood(mood_face, mood_phrase);
  }
  else if(appRunning){}

  drawRightBar();

  M5.Display.startWrite();
  if (show_toolbars) {
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    
    //bar_right1.pushSprite(display_w * 0.98, 2*(canvas_top_h + 3));
  }
  bar_right.pushSprite(display_w * 0.98, canvas_top_h + 5);
  bar_right2.pushSprite(display_w * 0.98, ( canvas_top_h + 5 ) + (1 * ((canvas_h - 6)/4)) - 1 );
  bar_right3.pushSprite(display_w * 0.98, ( canvas_top_h + 5 ) + (2 * ((canvas_h - 6)/4)) - 1 );
  bar_right4.pushSprite(display_w * 0.98, ( canvas_top_h + 5 ) + (3 * ((canvas_h - 6)/4)) - 1 );
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
}

void drawRightBar() {
  if(menuID){
    if(menu_current_pages == 1){
      bar_right.fillSprite(BLACK);
      bar_right2.fillSprite(BLACK);
      bar_right3.fillSprite(BLACK);
      bar_right4.fillSprite(BLACK);
    }
    else if(menu_current_pages == 2){
      if(menu_current_page ==1){
        bar_right.fillSprite(BLACK);
        bar_right2.fillSprite(BLACK);
        bar_right3.fillSprite(WHITE);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page ==2){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(WHITE);
        bar_right3.fillSprite(BLACK);
        bar_right4.fillSprite(BLACK);
      }
    }
    else if(menu_current_pages == 3){
      if (menu_current_page == 1){
        bar_right.fillSprite(BLACK);
        bar_right2.fillSprite(BLACK);
        bar_right3.fillSprite(WHITE);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page ==2){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(BLACK);
        bar_right3.fillSprite(BLACK);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page ==3){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(WHITE);
        bar_right3.fillSprite(BLACK);
        bar_right4.fillSprite(BLACK);
      }
    }
    else if(menu_current_pages == 4){
      if (menu_current_page == 1){
        bar_right.fillSprite(BLACK);
        bar_right2.fillSprite(WHITE);
        bar_right3.fillSprite(WHITE);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page == 2){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(BLACK);
        bar_right3.fillSprite(WHITE);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page == 3){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(WHITE);
        bar_right3.fillSprite(BLACK);
        bar_right4.fillSprite(WHITE);
      }
      else if(menu_current_page == 4){
        bar_right.fillSprite(WHITE);
        bar_right2.fillSprite(WHITE);
        bar_right3.fillSprite(WHITE);
        bar_right4.fillSprite(BLACK);
      }
    }
  }  
  else { 
    bar_right.fillSprite(WHITE);
    bar_right2.fillSprite(WHITE);
    bar_right3.fillSprite(WHITE);
    bar_right4.fillSprite(WHITE);
  }
}

inline void resetSprite(){bar_right.fillSprite(WHITE);}

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
  String wifiStatus;
  if(WiFi.status() == WL_NO_SHIELD){
    wifiStatus = "off";
  }
  else if(WiFi.status() == WL_CONNECTED){
    wifiStatus = "connected";
  }
  else if(WiFi.status() ==  WL_IDLE_STATUS){
    wifiStatus = "IDLE";
  }
  else if(WiFi.status() == WL_CONNECT_FAILED){
    wifiStatus = "error";
  }
  else if(WiFi.status() ==  WL_CONNECTION_LOST){
    wifiStatus = "lost";
  }
  else if(WiFi.status() ==  WL_DISCONNECTED){
    wifiStatus = "disconnected";
  }
  canvas_bot.drawString("Wifi:" + wifiStatus + " (" + WiFi.localIP().toString() + ")", 0, 5);
  canvas_bot.setTextDatum(top_right);
  canvas_bot.drawString("READY", display_w, 5);
  canvas_bot.drawLine(0, 0, display_w, 0);
}

void drawMood(String face, String phrase) {
  canvas_main.fillSprite(WHITE);
  canvas_main.setTextSize(4);
  canvas_main.setTextDatum(top_left);
  canvas_main.setCursor(5, 10);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.drawString(face, 5 , 20);
  canvas_main.setTextSize(1.5);
  String hostname_blank = multiplyChar(' ', sizeof(hostname) / 4);
  canvas_main.setCursor(0, canvas_h - 35);
  canvas_main.println(hostname + "> " + phrase);
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

void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical) {
  appRunning = true;
  delay(150);
  canvas_main.clear(TFT_WHITE);
  canvas_main.setTextSize(3);
  if(isCritical){canvas_main.setColor(RED);}
  else {canvas_main.setColor(BLACK);}
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
  canvas_main.setTextSize(1.5);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(info, canvas_center_x, canvas_h / 2);
  canvas_main.drawString(info2, canvas_center_x, (canvas_h / 2) + 20);
  if(canBeQuit){
    canvas_main.setTextSize(1);
    canvas_main.drawString("To exit press OK", canvas_center_x, canvas_h * 0.9);
    while(true){
      drawBottomCanvas();
      M5.Display.startWrite();
      canvas_top.pushSprite(0, 0);
      canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
      canvas_main.pushSprite(0, canvas_top_h);
      M5.Display.endWrite();
      M5.update();
      M5Cardputer.update();
      if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){return ;}
    }
  }
  else{
    drawBottomCanvas();
    M5.Display.startWrite();
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    canvas_main.pushSprite(0, canvas_top_h);
    M5.Display.endWrite();
  }
  appRunning = false;
}

inline void trigger(uint8_t trigID){Serial.println("Trigger" + String(trigID));}

void runApp(uint8_t appID){
  Serial.println("App started running, ID:"+ String(appID));
  menu_current_opt = 0;
  menu_current_page = 1;
  menuID = 0; 
  if(appID){
    if(appID == 1){drawSinglePage(wifi_menu, 2, 5);}
    if(appID == 2){drawMultiplePages(bluetooth_menu, 3, 6);}
    if(appID == 3){drawSinglePage(IR_menu, 4, 5 );}
    if(appID == 4){drawSinglePage(pwngotchi_menu, 5 , 3 );}
    if(appID == 5){drawInfoBox("ERROR", "not implemented", "" ,  true, true);}
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
    if(appID == 40){
      String name = userInput("New value", "Change Hostname to:", 5);
      if(name != ""){
        hostname = name;
        return;
      }
      drawInfoBox("Name invalid", "Null inputed,", "operation abort", true, false);
    }
    if(appID == 41){
      String value = userInput("Brightness", "Change Brightness to (max 255):", 3);
      if(value == ""){
        drawInfoBox("Error", "Invalid Value", value , true, false);
        return;
      }
      //char setTo = value.toInt();
      uint8_t digit2;
      uint8_t digit3;
      uint16_t name;
      uint8_t digit1 = value.charAt(0) - 48;
      name =  digit1;
      if(value.charAt(1) >= 48){
        uint8_t digit2 = value.charAt(1) - 48;
        name = (digit1 * 10) + digit2;
      }
      if(value.charAt(2) >= 48){
        uint8_t digit3 = value.charAt(2) - 48;
        name = (digit1 * 100) + (digit2 * 10) + digit3;
      }
      
      if(name<=255 && name!=0){
        Serial.println(String(name));
        M5.Lcd.setBrightness(int(name));
        currentBrightness = int(name);
      }
      else
      drawInfoBox("Error", "Invalid Value", String(name) , true, false);
    }
    if(appID == 42){
      String selection[] = {"Off", "On"};
      delay(50);
      sound = drawMultiChoice("Sound", selection, 2, 6, 2);
    }
    if(appID == 43){
      WiFi.mode(WIFI_STA);
      int numNetworks = WiFi.scanNetworks();
      String wifinets[20];
      if (numNetworks == 0) {
        drawInfoBox("Info", "No wifi nearby", "Abort.", true, false);
        return;
      } else {
        // Przechodzimy przez wszystkie znalezione sieci i zapisujemy ich nazwy w liście
        for (int i = 0; i < numNetworks; i++) {
        String ssid = WiFi.SSID(i);
        
        wifinets[i] = String(ssid);
        Serial.println(wifinets[i]);
        }
      }
      uint8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks, 6, 3);
      //String ssid = userInput("Wifi SSID", "Enter wifi name to connect.", 30);
      String password = userInput("Password", "Enter wifi password" , 30);
      WiFi.begin(WiFi.SSID(wifisel), password);
      uint8_t counter;
      while (counter<=10 && !WiFi.isConnected()) {
        delay(1000);
        drawInfoBox("Connecting", "Please wait...", "You will be soon redirected ", false, false);
        counter++;
      }
      counter = 0;
      if(WiFi.isConnected()){
        drawInfoBox("Connected", "Connected succesfully to", String(WiFi.SSID()) , true, false);
      }
      else{
        drawInfoBox("Error", "Connection failed", "Maybe wrong password...", true, false);
      }
    }
    if(appID == 44){
      String tempMenu[] = {"From SD", "From WIFI"};
      uint8_t choice = drawMultiChoice("Update type", tempMenu, 2, 6, 4);
      if(choice == 0){updateFromSd();}
      else if(choice == 1){updateFromHTML();}
      }
    if(appID == 45){
      drawInfoBox("ESPBlaster","v0.1 by Devsur11  ", "www.github.com/Devsur11 ", true, false);
    }
    if(appID == 46){
      M5.Display.fillScreen(TFT_BLACK);
      esp_deep_sleep_start(); 
      }
    if(appID == 47){}
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
    else if(menuID == 2){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(wifi_menu[menu_current_opt].command);
    }
    else if(menuID == 3){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(bluetooth_menu[menu_current_opt].command);
    }
    else if(menuID == 4){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(IR_menu[menu_current_opt].command);
    }
    else if(menuID == 5){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(pwngotchi_menu[menu_current_opt].command);
    }
    else if(menuID == 6){
      //Serial.println(main_menu[menu_current_opt].command); - for debugging purposses
      runApp(settings_menu[menu_current_opt].command);
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

String userInput(String tittle, String desc, uint8_t maxLenght){
  uint8_t temp = 0;
  String textTyped;
  appRunning = true;
  delay(500);
  //bool loop = 1;
  canvas_main.clear(TFT_WHITE);
  canvas_main.setTextSize(3);
  canvas_main.setTextColor(BLACK);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
  canvas_main.setTextSize(1);
  canvas_main.drawString(desc, canvas_center_x, canvas_h * 0.9);
  while (true){
    M5.update();
    M5Cardputer.update();
    //auto i;
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i=='`' && status.fn){
        return  "";
      }
      textTyped = textTyped + i;
      temp ++;
      delay(250);
    }
    if (status.del && temp >=1) {
      textTyped.remove(textTyped.length() - 1);
      temp --;
      delay(250);
    }
    if (status.enter) {
      break;
    }
    
    if(temp > maxLenght){
      drawInfoBox("Error", "Can't type more than " + String(maxLenght), " characters" , true, false);
      textTyped.remove(textTyped.length() - 1);
      temp --;
      delay(250);
    }
    canvas_main.clear(TFT_WHITE);
    canvas_main.setTextSize(3);
    canvas_main.setTextColor(BLACK);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1);
    canvas_main.drawString(desc, canvas_center_x, canvas_h * 0.9);
    canvas_main.setTextSize(1.5);
    canvas_main.setCursor(0 , canvas_h /2);
    canvas_main.println(textTyped);
    M5.Display.startWrite();
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    canvas_main.pushSprite(0, canvas_top_h);
    M5.Display.endWrite();
  }
  //drawInfoBox("Confirm value:", textTyped, true, false);
  appRunning = false;
  trigger(3);
  return textTyped;
}

String multiplyChar(char toMultiply, uint8_t literations){
  String toReturn;
  char temp = toMultiply;
  for(uint8_t i = 1; i>=literations; i++){
    toReturn = toReturn + temp;
  }
  return toReturn;
}

bool drawQuestionBox(String tittle, String info, String info2) {
  appRunning = true;
  delay(150);
  canvas_main.clear(TFT_WHITE);
  canvas_main.setTextSize(3);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
  canvas_main.setTextSize(1.5);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(info, canvas_center_x, canvas_h / 2);
  canvas_main.drawString(info2, canvas_center_x, (canvas_h / 2) + 20);
  trigger(1);
  canvas_main.setTextSize(1);
  canvas_main.drawString("To confirm press OK, to abort press ESC", canvas_center_x, canvas_h * 0.9);
  while(true){
    M5.Display.startWrite();
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    canvas_main.pushSprite(0, canvas_top_h);
    M5.Display.endWrite();
    trigger(2);
    M5.update();
    M5Cardputer.update();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){
      appRunning = false;
      return true;
    }
    
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        return  false;
      }
    }
  }
  appRunning = false;
}

int drawMultiChoice(String tittle, String toDraw[], uint8_t menuSize , uint8_t prevMenuID, uint8_t prevOpt) {
  uint8_t tempOpt = 0;
  delay(100);
  menu_current_opt = 0;
  menu_current_pages = 1;
  menu_len = menuSize;
  singlePage = true;
  trigger(1);
  while(true){
    M5.update();
    M5Cardputer.update();  
    canvas_main.clear(TFT_WHITE);
    canvas_main.fillSprite(WHITE); //Clears main display
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(BLACK);
    canvas_main.setColor(BLACK);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, PADDING + 1);
    canvas_main.println(tittle);
    canvas_main.setTextSize(2);
    char display_str[50] = "";
    for (uint8_t i = 0; i < menuSize; i++) {
      sprintf(display_str, "%s %s", (menu_current_opt == i) ? ">" : " ", toDraw[i].c_str());
      int y = PADDING + (i * ROW_SIZE / 2) + 30;
      //trigger(5);
      canvas_main.drawString(display_str, 0, y);
    }
    //for this to work i need to push sprite whitch i did 
    M5.Display.startWrite();
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
    canvas_main.pushSprite(0, canvas_top_h);
    M5.Display.endWrite();
    if (isNextPressed()) {
      if (menu_current_opt < menu_len - 1 ) {
        menu_current_opt++;
        tempOpt++;
      } else {
        menu_current_opt = 0;
        tempOpt = 1;
      }
    }
    //trigger(4);
    if (isPrevPressed()) {
      if (menu_current_opt > 0) {
        menu_current_opt--;
        tempOpt--;
      }
      else {
        menu_current_opt = (menu_len - 1);
        tempOpt = (menu_len - 1);
      }
    }
    //trigger(5);
    if(!singlePage){
      if(menu_current_opt < 5 && menu_current_page != 1){
          menu_current_page= 1;
      } 
      else if(menu_current_opt >= 5 && menu_current_page != 2){
        menu_current_page = 2;
      }
    }
    //trigger(6);
    if(isOkPressed()){
      keyboard_changed = M5Cardputer.Keyboard.isChange();
      if(keyboard_changed){Sound(10000, 100, sound);}
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return tempOpt;
    }
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
  }
}