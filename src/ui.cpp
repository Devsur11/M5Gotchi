#include "M5Cardputer.h"
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
#define ROW_SIZE 40
#define PADDING 10

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
M5Canvas bar_right(&M5.Display);
M5Canvas bar_right2(&M5.Display);
M5Canvas bar_right3(&M5.Display);
M5Canvas bar_right4(&M5.Display);

String funny_ssids[] = {
  "Mom Use This One",
  "Abraham Linksys",
  "Benjamin FrankLAN",
  "Martin Router King",
  "John Wilkes Bluetooth",
  "Pretty Fly for a Wi-Fi",
  "Bill Wi the Science Fi",
  "I Believe Wi Can Fi",
  "Tell My Wi-Fi Love Her",
  "No More Mister Wi-Fi",
  "LAN Solo",
  "The LAN Before Time",
  "Silence of the LANs",
  "House LANister",
  "Winternet Is Coming",
  "Ping's Landing",
  "The Ping in the North",
  "This LAN Is My LAN",
  "Get Off My LAN",
  "The Promised LAN",
  "The LAN Down Under",
  "FBI Surveillance Van 4",
  "Area 51 Test Site",
  "Drive-By Wi-Fi",
  "Planet Express",
  "Wu Tang LAN",
  "Darude LANstorm",
  "Never Gonna Give You Up",
  "Hide Yo Kids, Hide Yo Wi-Fi",
  "Loading…",
  "Searching…",
  "VIRUS.EXE",
  "Virus-Infected Wi-Fi",
  "Starbucks Wi-Fi",
  "Text your mom for Password",
  "Yell NIGGA for Password",
  "The Password Is 1234",
  "Free Public Wi-Fi",
  "No Free Wi-Fi Here",
  "Get Your Own Damn Wi-Fi",
  "It Hurts When IP",
  "Dora the Internet Explorer",
  "404 Wi-Fi Unavailable",
  "Porque-Fi",
  "Titanic Syncing",
  "Test Wi-Fi Please Ignore",
  "Drop It Like It's Hotspot",
  "Life in the Fast LAN",
  "The Creep Next Door",
  "Ye Olde Internet"
};

String rickroll_ssids[]{
  "01 Never gona give you up",
  "02 Never gona let you down",
  "03 Never gona run around",
  "04 And desert you",
  "05 Never gona make you cry",
  "06 Never gona say goodbye",
  "07 Never gonna tell a lie ",
  "08 and hurt you",
};

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
    {"Acces point", 22},
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

bool sound = 1;
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
uint8_t currentBrightness = 100;
String wifiChoice;
uint8_t intWifiChoice;
bool apMode;
String loginCaptured = "";
String passCaptured = "";
bool cloned;

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

void drawBottomCanvas() {
  canvas_bot.fillSprite(WHITE);
  canvas_bot.setTextSize(1);
  canvas_bot.setTextColor(BLACK);
  canvas_bot.setColor(BLACK);
  canvas_bot.setTextDatum(top_left);
  String wifiStatus;
  if(WiFi.status() == WL_NO_SHIELD){
    wifiStatus = "off";
    if(apMode){canvas_bot.drawString("Wifi: AP  " + wifiChoice, 0, 5);}
    else {canvas_bot.drawString("Wifi:" + wifiStatus, 0, 5);}
  }
  else if(WiFi.status() == WL_CONNECTED){
    wifiStatus = "connected";
    canvas_bot.drawString("Wifi:" + wifiStatus + " (" + WiFi.localIP().toString() + ")", 0, 5);
  }
  else if(WiFi.status() ==  WL_IDLE_STATUS){
    wifiStatus = "IDLE";
    canvas_bot.drawString("Wifi:" + wifiStatus, 0, 5);
  }
  else if(WiFi.status() == WL_CONNECT_FAILED){
    wifiStatus = "error";
    canvas_bot.drawString("Wifi:" + wifiStatus, 0, 5);
  }
  else if(WiFi.status() ==  WL_CONNECTION_LOST){
    wifiStatus = "lost";
    canvas_bot.drawString("Wifi:" + wifiStatus, 0, 5);
  }
  else if(WiFi.status() ==  WL_DISCONNECTED){
    wifiStatus = "disconnected";
    canvas_bot.drawString("Wifi:" + wifiStatus, 0, 5);
  }
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
  //if(menu_current_page == 1){
   
  for (uint8_t j = 0; j < (menuSize - ((menu_current_page - 1) * 5)) ; j++) {
   sprintf(display_str, "%s %s", (menu_current_opt == j+( (menu_current_page - 1) * 5 ) ) ? ">" : " ",
           toDraw[j+ ( (menu_current_page - 1) * 5)].name);
   int y = PADDING + (j * ROW_SIZE / 2);
   canvas_main.drawString(display_str, 0, y);
  }
}

void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical) {
  appRunning = true;
  if(canBeQuit){delay(150);}
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
  drawRightBar();
  if(canBeQuit){
    canvas_main.setTextSize(1);
    canvas_main.drawString("To exit press OK", canvas_center_x, canvas_h * 0.9);
    while(true){
      drawBottomCanvas();
      pushAll();
      M5.update();
      M5Cardputer.update();
      if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){
        Sound(10000, 100, sound);
        return ;
      }
    }
  }
  else{
    drawBottomCanvas();
    pushAll();
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
    if(appID == 20){
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
      uint8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks, 2, 0);
      wifiChoice = WiFi.SSID(wifisel);
      intWifiChoice = wifisel;
      Serial.println("Selected wifi: "+ wifiChoice);
      drawInfoBox("Succes", wifiChoice, "Was selected", true, false);
    }
    if(appID == 21){
      if(wifiChoice.equals("")){
        drawInfoBox("Error", "No wifi selected", "Do it first", true, false);
      }
      else{
        drawWifiInfoScreen(WiFi.SSID(intWifiChoice), WiFi.BSSIDstr(intWifiChoice), String(WiFi.RSSI(intWifiChoice)));
      }
    }
    if(appID == 22){
      String appList[] = {"Phishing form", "Beacon spam", "AP mode", "Turn OFF"};
      uint8_t tempChoice = drawMultiChoice("What to do?", appList , 4 , 2 , 2);
      if(tempChoice==0){
        if(cloned){
          startPortal(wifiChoice);
        }
        else{
          String uinput = userInput("SSID?", "Enter wifi name for ap.", 30);
          startPortal(uinput);
        }
        delay(100);
        apMode = true;
        while(true){
          updatePortal();
          M5.update();
          M5Cardputer.update();
          Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
          if(!loginCaptured.equals("") && !passCaptured.equals("")){
            drawInfoBox("New victim!", loginCaptured, passCaptured, false, false);
          }
          else{
            drawInfoBox("Evil portal", "Evli portal active...", "Enter to exit", false, false);
          }
          keyboard_changed = M5Cardputer.Keyboard.isChange();
          if(keyboard_changed){Sound(10000, 100, sound);}    
          if (status.enter) {
            WiFi.eraseAP();
            WiFi.mode(WIFI_MODE_NULL);
            apMode = false;
            wifiChoice = "";
            break;
          }
        }
      }
      if(tempChoice == 1){
        String ssidMenu[] = {"Funny SSID", "Broken SSID", "Rick Roll", "Make your own :)"};
        uint8_t ssidChoice = drawMultiChoice("Select list", ssidMenu, 4 , 2 , 2);
        if(ssidChoice==0){
          broadcastFakeSSIDs( funny_ssids, 48, sound);
          }
        else if (ssidChoice==2){
          broadcastFakeSSIDs( rickroll_ssids, 8, sound);
          menu_current_opt = 0;
          menu_current_page = 1;
          menuID = 0;
          }
        else {
          String* BeaconList = makeList("Create spam list", 48, false, 30);
          broadcastFakeSSIDs( BeaconList , sizeof(BeaconList), sound);
        }
      }
      else if(tempChoice == 2){
        if(apMode){
          bool answear = drawQuestionBox("AP of?", "AP arleady running!", "Power AP off?");
          if (answear){
            WiFi.mode(WIFI_MODE_NULL);
            apMode = false;
            wifiChoice = "";
            return;
            }
        }
        WiFi.disconnect(true);
        WiFi.mode(WIFI_MODE_AP);
        if(cloned){
          String pass = userInput("Password", "Create password for AP", 30);
          bool result = WiFi.softAP(wifiChoice, pass);
          if(result){
            drawInfoBox("Succes", "AP started", "succesfully", true, false);
            apMode = true;
          }
          else {
            drawInfoBox("Error", "Something happend!", "Something happend!", true, false);
          }
          cloned = false;
          wifiChoice = "";
        }
        else{
          String apssid = userInput("AP name:", "Enter wifi name", 30);
          wifiChoice = apssid;
          String pass = userInput("Password", "Create password for AP", 30);
          bool result = WiFi.softAP(apssid, pass);
          if(result){
            drawInfoBox("Succes", "AP started", "succesfully", true, false);
            apMode = true;
          }
          else {
            drawInfoBox("Error", "Something happend!", "Something happend!", true, false);
          }
          cloned = false;
          wifiChoice = "";
        }
      }
      else if (tempChoice ==3) {
        bool answear = drawQuestionBox("Power AP off?", "Are you sure?", "");
        if (answear){
          WiFi.mode(WIFI_MODE_NULL);
          apMode = false;
          wifiChoice = "";
          }
      }
      menu_current_opt = 0;
      menu_current_page = 1;
      menuID = 0;
    }
    if(appID == 23){
      bool answwear = drawQuestionBox("WARNING!", "This is illegal to use not", "on your network! Continue?");
      if (answwear){
        if(!wifiChoice.equals("")){
          setMac(WiFi.BSSID(intWifiChoice));
          Serial.println("User inited deauth");
          initClientSniffing();
          String clients[10];
          int clientLen;
          while(true){
            get_clients_list(clients, clientLen);
            drawInfoBox("Searching...", "Found "+ String(clientLen)+ " clients", "ENTER for next step", false, false);
            updateM5();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              delay(500);
              break;
            }
          }
          uint8_t target = drawMultiChoice("Select target.", clients, clientLen, 0, 0);
          Serial.println("Selected target: " + clients[target]);
          esp_wifi_set_promiscuous(false);
          int PPS;
          delay(100);
          while(true){
            drawInfoBox("Deauth!", "Deauth active on target:", String(clients[target]) + "PPS: " + String(PPS), false, false);
            updateM5();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              delay(500);
              break;
            }
            send_deauth_packets(clients[target], 1);
            PPS++;
          }
          
          clearClients();
        }
        else{
          drawInfoBox("Error!", "No wifi selected!", "Select one first!", true, false);
        }
      }
    }
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
    else{
      return;
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
    pushAll();
  }
  //drawInfoBox("Confirm value:", textTyped, true, false);
  appRunning = false;
  Serial.println("Userinput returning: " + textTyped);
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

bool drawQuestionBox(String tittle, String info, String info2, String label) {
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
  canvas_main.setTextSize(1);
  canvas_main.drawString( label, canvas_center_x, canvas_h * 0.9);
  drawRightBar();
  while(true){
    pushAll();
    M5.update();
    M5Cardputer.update();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        return false;
      }
      else if(i=='y'){
        Serial.println("yes");
        return true;
      }
      else if(i=='n'){
        Serial.println("No");
        return false;
      }
    }
  }
  appRunning = false;
}

int drawMultiChoice(String tittle, String toDraw[], uint8_t menuSize , uint8_t prevMenuID, uint8_t prevOpt) {
  uint8_t tempOpt = 0;
  delay(100);
  menu_current_opt = 0;
  menu_current_page = 1;
  menu_current_pages = 1;
  menu_len = menuSize;
  singlePage = false;
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
    char display_str[100] = "";
    for (uint8_t j = 0; j < (menu_len - ((menu_current_page - 1) * 5)) ; j++) {
      sprintf(display_str, "%s %s", (tempOpt == j+( (menu_current_page - 1) * 5 ) ) ? ">" : " ",
             toDraw[j+ ( (menu_current_page - 1) * 5)].c_str());
      int y = PADDING + (j * ROW_SIZE / 2) + 20;
      canvas_main.drawString(display_str, 0, y);
    }
    pushAll();

    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i=='`'){
        Sound(10000, 100, sound);
        return  100;
      }
    }

    if (isNextPressed()) {
      if (menu_current_opt < menu_len - 1 ) {
        menu_current_opt++;
        tempOpt++;
      } else {
        menu_current_opt = 0;
        tempOpt = 0;
      }
    }
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
    if(!singlePage){
      if(menu_current_opt < 4 && menu_current_page != 1){
        menu_current_page = 1;
      } 
      else if(menu_current_opt >= 4 && menu_current_page != 2){
        menu_current_page = 2;
        menu_current_opt++;
        tempOpt++;
      }
    }
    if(isOkPressed()){
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return tempOpt;
    }
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
  }
}

String* makeList(String windowName, uint8_t appid, bool addln, uint8_t maxEntryLen){
  uint8_t writeID = 0;
  String list[] = {"Add element", "Remove element" , "Done", "Preview"};
  String* listToReturn = new String[30];
  while(true){
    delay(100);
    uint8_t choice = drawMultiChoice(windowName, list, 4 , 0, 0);
    if (choice==0){
      String tempText = userInput("Add value:", "", maxEntryLen);
      if(addln){
        listToReturn[writeID] = tempText + "\n";
        writeID++;
      }
      else{
        listToReturn[writeID] = tempText;
        writeID++;
      }
    }
    else if (choice==2){
      delay(100);
      return listToReturn;
    }
    
    else if (choice==1){
      String tempText = userInput("Position?:", "(number)", 2);
      listToReturn[tempText.toInt() - 1] = "";
    }
    else if (choice==3){
      delay(100);
      while(true){
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}  
        for(auto i : status.word){
          if(i=='`'){
            //*String toreturn[] = {"SYS:NONE"};
            //return toreturn;
          }
        }
        M5.update();
        M5Cardputer.update();
        if(isOkPressed()){break;}
        drawList(listToReturn, writeID);
        pushAll();
        drawMenu();
      }
    }
  }
}

void drawList(String toDraw[], uint8_t manu_size){
  menu_len = manu_size;
  
  singlePage = false;
  canvas_main.fillSprite(WHITE); //Clears main display
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(top_left);
  char display_str[50] = "";
  //if(menu_current_page == 1){
   
  for (uint8_t j = 0; j < (menu_len - ((menu_current_page - 1) * 5)) ; j++) {
   sprintf(display_str, "%s %s", (menu_current_opt == j+( (menu_current_page - 1) * 5 ) ) ? ">" : " ",
           toDraw[j+ ( (menu_current_page - 1) * 5)]);
   int y = PADDING + (j * ROW_SIZE / 2);
   canvas_main.drawString(display_str, 0, y);
  }
}


void logVictim(String login, String pass){
  loginCaptured = login;
  passCaptured = pass;
  return;
}

void drawWifiInfoScreen(String wifiName, String wifiMac, String wifiRRSI){
  canvas_main.fillSprite(WHITE);
  canvas_main.setTextSize(2);
  canvas_main.setTextColor(BLACK);
  canvas_main.setColor(BLACK);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString(wifiChoice, display_w/2, 25);
  canvas_main.setTextSize(1.5);
  canvas_main.drawString("Mac: " + wifiMac, display_w/2 , 50);
  canvas_main.drawString(wifiRRSI + " RRSI", display_w/2, 70);
  canvas_main.setTextSize(1);
  canvas_main.drawString("<To clone press C, ENTER to exit>", display_w/2, 100);
  drawRightBar();
  pushAll();
  delay(500);
  while(true){
    updateM5();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);} 
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i == 'c'){
        cloned = true;
        return;
      }
    }
    if(status.enter){
      return;
    }
  }
}

inline void pushAll(){
  drawRightBar();
  M5.Display.startWrite();
  canvas_top.pushSprite(0, 0);
  canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
}

inline void updateM5(){
  M5.update();
  M5Cardputer.update();
  keyboard_changed = M5Cardputer.Keyboard.isChange();
  if(keyboard_changed){Sound(10000, 100, sound);}   
}