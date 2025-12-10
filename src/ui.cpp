#include "M5Cardputer.h"
#include "lgfx/v1/misc/enum.hpp"
#include "lgfx/v1/misc/DataWrapper.hpp"
#include "HWCDC.h"
#include "Arduino.h"
#include <ArduinoJson.h>
#include "ui.h"
#include <FS.h>
#include <SD.h>
#include <WiFi.h>
#include "settings.h"
#include "pwnagothi.h"
#include "EapolSniffer.h"
#include "mood.h"
#include "updater.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>
#include "evilPortal.h"
#include "networkKit.h"
#include "src.h"
#include "logger.h"
#include "moodLoader.h"
#include "wpa_sec.h"
#include "pwngrid.h"
#include "api_client.h"
#include "sdmanager.h"
#include <vector>
#include "wardrive.h"

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
M5Canvas bar_right(&M5.Display);
M5Canvas bar_right2(&M5.Display);
M5Canvas bar_right3(&M5.Display);
M5Canvas bar_right4(&M5.Display);

#ifndef LITE_VERSION
static const char * const funny_ssids[] = {
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

static const char * const rickroll_ssids[]{
  "01 Never gona give you up",
  "02 Never gona let you down",
  "03 Never gona run around",
  "04 And desert you",
  "05 Never gona make you cry",
  "06 Never gona say goodbye",
  "07 Never gonna tell a lie ",
  "08 and hurt you",
};

static const char * const broken_ssids[]{
  "Broken_Wi-Fi",
  "Unstable_Network",
  "Corrupted_AP",
  "Glitchy_SSID",
  "???",
  "Error_404_AP",
  "NULL_NETWORK",
  "WiFi_Broken",
  "SSID_NOT_FOUND",
  "WiFi?WiFi!",
  "Unkn0wn",
  "WiFi_Failure",
  "Lost_Connection",
  "AP_Crash",
  "WiFi_Glitch",
  "SSID_#@!$%",
  "Network_Error",
  "WiFi_Bugged",
  "WiFi_???",
  "SSID_Broken",
};
#endif

// menuID 1
menu main_menu[] = {
    {"Manual mode", 1},
    {"Auto mode", 4},
    {"WPA-SEC companion", 55},
    #ifdef USE_EXPERIMENTAL_APPS
    {"Bluetooth", 2},
    {"IR", 3},
    {"Bad USB", 5},
    #endif
    {"Pwngrid companion", 7},
    {"Wardriving companion", 8},
    {"File manager", 70},
    {"Config", 6}
};

//menuID 2
menu wifi_menu[] = {
    {"Select Networks", 20},
    {"Clone & Details", 21},
    {"Acces point", 22},
    {"Deauth", 23},
    {"Sniffing", 24}
};
#ifdef USE_EXPERIMENTAL_APPS

//menuID 3
menu bluetooth_menu[] = {
    {"BLE Spam", 25},
    {"Connect to phone", 26},
    {"Emulate BT Keyboard", 27},
    {"Chat", 28}, 
    {"Scan", 29},
    {"Turn off", 30}
};

//menuID 4
menu IR_menu[] = {
    {"Saved remotes", 31},
    {"Send IR", 32},
    {"Recerve IR", 33},
    {"Learn new Remote", 34},
    {"Import from SD", 35}
};
#endif

//menuID 7
menu wpasec_menu[] = {
  {"Sync with server", 52},
  {"Check cracked results", 53},
  {"Change API key", 54}
};

menu wpasec_setup_menu[] = {
  {"Setup WPA-SEC API key", 54}
};

//menuID 5
menu pwngotchi_menu[] = {
    {"Switch to auto mode", 36},
    {"Whitelist editor", 38},
    {"Handshakes file list", 39},
    {"Personality editor", 57}
};

//menuID 6
menu settings_menu[] = {
  {"M5Gotchi auto mode on boot", 48},
  {"Change Hostname/name", 40},
  {"UI Theme", 50},
  {"Skip EAPOL integrity check", 49},
  {"Display brightness", 41},
  {"Keyboard Sound", 42},
  {"Advertise Pwngrid presence", 60},
  {"Connect to WiFi", 43},
  {"Connect to WiFi on startup", 29},
  {"GPS GPIO pins", 30},
  {"Log GPS data after handshake", 31},
  {"GO button press function", 59},
  {"Log to SD", 58},
  {"Update system", 44},
  {"Factory reset", 51},
  {"About M5Gotchi", 45},
  {"Power off system", 46},
  {"Reboot system", 56}
};

//menuID 8
menu pwngrid_menu[] = {
  {"Units met", 16},
  {"Messages inbox", 10},
  {"Quick message", 11},
  {"Frends list", 17},
  {"No new captured networks to send", 0},
  {"View identity/fingerprint", 13},
  {"Reset pwngrid/fingerprint", 15}
};

menu pwngrid_not_enrolled_menu[] = {
  {"Enroll with Pwngrid", 12}
};

//menuID 9 
menu wardrivingMenuWithWiggle[] = {
  {"Wardriving mode", 18},
  {"View logs", 19},
  {"Upload to Wiggle.net", 28},
  {"Reset Wiggle.net config", 27}
};

menu wardrivingMenuWithWiggleUnsett[] = {
  {"Wardriving mode", 18},
  {"View logs", 19},
  {"Set up Wiggle.net api key", 25},
};

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
bool keyboard_changed = false;
uint8_t menu_len;
uint8_t menu_current_opt = 0;
uint8_t menu_current_page = 1;  
bool singlePage;
uint8_t menuID = 0;
uint8_t currentBrightness = 100;
String wifiChoice;
uint8_t intWifiChoice;
bool apMode;
String loginCaptured = "";
String passCaptured = "";
bool cloned;
uint16_t bg_color_rgb565 ;//= TFT_WHITE;
uint16_t tx_color_rgb565 ;//= TFT_BLACK;
bool sleep_mode = false; 
SemaphoreHandle_t buttonSemaphore;

void esp_will_beg_for_its_life() {
  int *ptr = nullptr;
  *ptr = 42; // hehehe
}

void buttonTask(void *param) {
  bool dimmed = false;
  for (;;) {
    if (xSemaphoreTake(buttonSemaphore, portMAX_DELAY) == pdTRUE) {
      if(!toogle_pwnagothi_with_gpio0)
      {dimmed = !dimmed;
      if (dimmed) {
        M5Cardputer.Display.setBrightness(0);  // example dim value
      } else {
        M5Cardputer.Display.setBrightness(brightness);
      }}
      else{
        if(!pwnagothiMode){
          pwnagothiMode = true;
          pwnagothiBegin();
          logMessage("Pwnagothi mode activated");
        }
        else{
          pwnagothiMode = false;
          logMessage("Pwnagothi mode deactivated");
        }
      }
    }
  }
}

volatile unsigned long lastInterruptTime = 0;

void IRAM_ATTR handleInterrupt() {
  unsigned long now = millis();
  if (now - lastInterruptTime > 200) {  // 200ms debounce
    BaseType_t xHigherPriorityTaskWoken = pdFALSE;
    xSemaphoreGiveFromISR(buttonSemaphore, &xHigherPriorityTaskWoken);
    if (xHigherPriorityTaskWoken) {
      portYIELD_FROM_ISR();
    }
  }
  lastInterruptTime = now;
}

uint16_t RGBToRGB565(uint8_t r, uint8_t g, uint8_t b) {
  return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3);
}

uint16_t hexToRGB565(String hex) {
  if (hex.startsWith("#")) {
    hex = hex.substring(1);
  }
  if (hex.length() != 8) {
    logMessage("Invalid hex color format. Expected RRGGBBAA.");
    return TFT_BLACK; // Default to black if the format is incorrect
  }
  uint32_t color = strtoul(hex.c_str(), nullptr, 16);
  uint8_t r = (color >> 24) & 0xFF;
  uint8_t g = (color >> 16) & 0xFF;
  uint8_t b = (color >> 8) & 0xFF;
  return RGBToRGB565(r, g, b);
}

void initColorSettings(){
  bg_color_rgb565 = hexToRGB565(bg_color);
  tx_color_rgb565 = hexToRGB565(tx_color);
}

void initUi() {
  attachInterrupt(digitalPinToInterrupt(0), handleInterrupt, FALLING);
  buttonSemaphore = xSemaphoreCreateBinary();
  xTaskCreate(buttonTask, "ButtonTask", 4096, NULL, 1, NULL);
  M5.Display.setRotation(1);
  M5.Display.setTextSize(1);
  M5.Display.fillScreen(bg_color_rgb565);
  M5.Display.setTextColor(tx_color_rgb565);

  display_w = M5.Display.width();
  display_h = M5.Display.height();
  canvas_h = display_h * .8;
  canvas_center_x = display_w / 2;
  canvas_top_h = display_h * .1;
  canvas_bot_h = display_h * .1;

  canvas_top.createSprite(display_w, canvas_top_h);
  canvas_bot.createSprite(display_w, canvas_bot_h);
  canvas_main.createSprite(display_w /*- (display_w * 0.02)*/, canvas_h);
  // bar_right.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  // bar_right2.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  // bar_right3.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  // bar_right4.createSprite((display_w * 0.02) / 2, (canvas_h - 6) / 4 );
  logMessage("UI initialized");
  
}

uint8_t returnBrightness(){return currentBrightness;}

#ifndef LITE_VERSION

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

#endif

void updateUi(bool show_toolbars, bool triggerPwnagothi) {
  if(pwnagothiMode && triggerPwnagothi){
    if(!stealth_mode){
      pwnagothiLoop();
    }
    else{
      pwnagothiStealthLoop();
    }
  }
  #ifndef LITE_VERSION
  keyboard_changed = M5Cardputer.Keyboard.isChange();
  if(keyboard_changed){Sound(10000, 100, sound);}               
  if (toggleMenuBtnPressed()) {
    debounceDelay();
    if(pwnagothiMode){
      return;
    }
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
  #endif

  String mood_face = getCurrentMoodFace();
  String mood_phrase = getCurrentMoodPhrase();

  drawTopCanvas();
  drawBottomCanvas();

  #ifndef LITE_VERSION
  if (menuID == 1) {
    menu_current_pages = 2;
    menu_len = 6;
    #ifdef USE_EXPERIMENTAL_APPS
    drawMenuList(main_menu, 1, 8);
    #else
    drawMenuList(main_menu, 1, 7);
    #endif
  } 
  else if (menuID == 2){
    drawMenuList( wifi_menu , 2, 5);
  }
  #ifdef USE_EXPERIMENTAL_APPS
  else if (menuID == 3){
    drawMenuList( bluetooth_menu , 3, 6);
  }
  else if (menuID == 4){
    drawMenuList( IR_menu , 4, 5);
  }
  #endif
  else if (menuID == 5){
    drawMenuList( pwngotchi_menu , 5, 4);
  }
  else if (menuID == 6){
    drawMenuList( settings_menu , 6, 15);
  }  
  else if (menuID == 7){
    (wpa_sec_api_key.length()>5)?drawMenuList(wpasec_menu, 7, 3):drawMenuList(wpasec_setup_menu, 7, 1);
  }
  else if (menuID == 8){
    File toUpload = SD.open("/pwngrid/cracks.conf");
    if(toUpload && toUpload.size() > 3){ 
      menu temp[7] =  { 
        {"Units met", 16},
        {"Messages inbox", 10},
        {"Quick message", 11},
        {"Frends list", 17},
        {"Send captured networks to pwngrid", 26},
        {"View identity/fingerprint", 13},
        {"Reset pwngrid/fingerprint", 15}
      };
      drawMenuList(temp, 8, 7);
    }
    else (pwngrid_indentity.length()>10)? drawMenuList(pwngrid_menu, 8, 7): drawMenuList(pwngrid_menu, 8, 1);
  }
  else if (menuID == 9){
    if(wiggle_api_key.length() > 5){
      drawMenuList(wardrivingMenuWithWiggle, 9, 4);
    }
    else{
      drawMenuList(wardrivingMenuWithWiggleUnsett, 9, 3);
    }
  }
  else if (menuID == 0)
  {
    drawMood(mood_face, mood_phrase);
  }
  else if(appRunning){}
  #endif
  #ifdef LITE_VERSION
    drawMood(mood_face, mood_phrase);
  #endif 

  M5.Display.startWrite();
  if (show_toolbars) {
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
  }
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
}

void drawTopCanvas() {
  canvas_top.fillSprite(bg_color_rgb565);
  canvas_top.setTextSize(1);
  canvas_top.setTextColor(tx_color_rgb565);
  canvas_top.setColor(tx_color_rgb565);
  canvas_top.setTextDatum(top_left);
  canvas_top.drawString("CH:" + String(WiFi.channel()) + " AP: " + String(WiFi.scanComplete()), 0, 3);
  canvas_top.setTextDatum(top_right);
  unsigned long ms = millis();

  unsigned long seconds = ms / 1000;
  unsigned int minutes = seconds / 60;
  unsigned int hours = minutes / 60;

  seconds = seconds % 60;
  minutes = minutes % 60;

  // Pad with zero if needed
  char buffer[9];
  sprintf(buffer, "%02u:%02u:%02lu", hours, minutes, seconds);
  canvas_top.drawString("UPS " + String(M5.Power.getBatteryLevel()) + "%  UP:" + buffer , display_w, 3);
  canvas_top.drawLine(0, canvas_top_h - 1, display_w, canvas_top_h - 1);
}


void drawBottomCanvas() {
  canvas_bot.fillSprite(bg_color_rgb565);
  canvas_bot.setTextSize(1);
  canvas_bot.setTextColor(tx_color_rgb565);
  canvas_bot.setColor(tx_color_rgb565);
  canvas_bot.setTextDatum(top_left);
  uint16_t captures = sessionCaptures;
  uint16_t allTimeCaptures = pwned_ap;
  String shortWifiName = lastPwnedAP.length() > 6 ? lastPwnedAP.substring(0, 6) + "..." : lastPwnedAP;
  canvas_bot.drawString("PWND: " + String(captures) + "/" + String(allTimeCaptures) + (shortWifiName.length() > 0 ? " (" + shortWifiName + ")" : ""), 3, 5);
  String wifiStatus;
  if(WiFi.status() == WL_NO_SHIELD){
    wifiStatus = "off";
    if(apMode){canvas_bot.drawString("Wifi: AP  " + wifiChoice, 0, 5);}
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
  canvas_bot.setTextDatum(top_right);
  canvas_bot.drawString(String((pwnagothiMode) ? "AUTO" : "MANU") + " " + wifiStatus, display_w, 5);
  canvas_bot.drawLine(0, 0, display_w, 0);
}

void drawMood(String face, String phrase) {
    uint16_t bg = bg_color_rgb565;
    uint16_t fg = tx_color_rgb565;
    canvas_main.fillSprite(bg);
    canvas_main.setTextColor(fg, bg);
    canvas_main.setColor(fg);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(3, 10);
    canvas_main.println(hostname + ">");


    if (moods.count(face + ".jpg")) {
        MoodImage &m = moods[face + ".jpg"];
        int rowBytes = (m.width+7)/8;
        for (int y=0; y<m.height; y++) {
            for (int x=0; x<m.width; x++) {
                bool px = m.bitmap[y*rowBytes + x/8] & (1 << (7-(x%8)));
                canvas_main.drawPixel(x, y+25, px ? fg : bg);
            }
        }
    } else {
        // fallback: display face as text
        canvas_main.setTextSize(4);
        canvas_main.setTextColor(fg, bg);
        canvas_main.drawString(face, 5, 30);
    }

    // Draw phrase
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(fg, bg);
    canvas_main.setCursor(3, canvas_h - 40);
    canvas_main.println("> " + phrase);
    canvas_main.setTextSize(1);
    canvas_main.setCursor(3, canvas_h - 10);
    if(getPwngridTotalPeers() > 0){
      canvas_main.println(getLastPeerFace() + " |||| " + getPwngridLastFriendName() + " (" + String(getPwngridLastSessionPwnedAmount()) + "/" + String(getPwngridLastPwnedAmount()) + ")");
    }
}

struct unit {
  String name;
  String fingerprint;
};

// Function to serialize the `unit` struct to a JsonObject
void serializeUnit(const unit& u, JsonObject& obj) {
  obj["name"] = u.name;
  obj["fingerprint"] = u.fingerprint;
}

void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical) {
  appRunning = true;
  debounceDelay();
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillScreen(bg_color_rgb565);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    if(isCritical){canvas_main.setColor(RED);}
    else {canvas_main.setColor(tx_color_rgb565);}
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(info, canvas_center_x, canvas_h / 2);
    canvas_main.drawString(info2, canvas_center_x, (canvas_h / 2) + 20);
    ;
    if(canBeQuit){
      canvas_main.setTextSize(1);
      canvas_main.drawString("To exit press OK", canvas_center_x, canvas_h * 0.9);
      drawBottomCanvas();
      pushAll();
      M5.update();
      M5Cardputer.update();
      if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){
        Sound(10000, 100, sound);
        return ;
      }

    }
    else{
      drawBottomCanvas();
      pushAll();
      return;
    }
  }
  appRunning = false;
}

#ifndef LITE_VERSION

#include <esp_sntp.h>

static const char *BASE_DIR = "/pwngrid/chats";

bool registerNewMessage(message newMess) {
  // fix timestamp if missing
  if (newMess.ts == 0) {
      newMess.ts = (uint64_t)time(nullptr);
  }

  // build file path
  String path = String(BASE_DIR) + "/" + newMess.fromOrTo;

  // load file or create new JSON
  JsonDocument doc;
  File f = SD.open(path, FILE_READ);
  if (f) {
      DeserializationError err = deserializeJson(doc, f);
      f.close();
      if (err) {
          // file exists but broken, reset to empty array
          doc.clear();
          doc.to<JsonArray>();
      }
  } else {
      // file missing, create array
      doc.to<JsonArray>();
  }

  JsonArray arr = doc.as<JsonArray>();
  JsonObject obj = arr.add<JsonObject>();

  obj["fromOrTo"] = newMess.fromOrTo;
  obj["fingerprint"] = newMess.fingerprint;
  obj["id"] = newMess.id;
  obj["text"] = newMess.text;
  obj["ts"] = newMess.ts;
  obj["outgoing"] = newMess.outgoing;

  // write back
  File w = SD.open(path, FILE_WRITE);
  if (!w) return false;
  serializeJson(doc, w);
  w.close();

  return true;
}

#include <algorithm>

std::vector<message> loadMessageHistory(const String &unitName) {
    std::vector<message> out;

    String path = String(BASE_DIR) + "/" + unitName;
    File f = SD.open(path, FILE_READ);
    if (!f) {
        return out;
    }

    JsonDocument doc;
    if (deserializeJson(doc, f)) {
        f.close();
        return out;
    }
    f.close();

    JsonArray arr = doc.as<JsonArray>();
    out.reserve(arr.size());

    for (JsonObject obj : arr) {
        message m;
        m.fromOrTo = (const char*)obj["fromOrTo"];
        m.fingerprint = (const char*)obj["fingerprint"];
        m.id = obj["id"] | 0;
        m.text = (const char*)obj["text"];
        m.ts = obj["ts"] | 0;
        m.outgoing = obj["outgoing"] | false;
        out.push_back(m);
    }

    // sort by timestamp, oldest first
    std::sort(out.begin(), out.end(),
        [](const message &a, const message &b) {
            return a.ts < b.ts;
        }
    );

    return out;
}

int clampMsgWidth(const String &s) {
    if (s.length() <= 24) return s.length();
    return 24;
}

String shortenMsg(String s) {
    if (s.length() <= 24) return s;
    return s.substring(0, 21) + "...";
}

// messages: vector<message>
// scrollOffset: how many lines up we are scrolled from the newest
void renderMessages(M5Canvas &canvas, const std::vector<message> &messages, int scrollOffset) {
  int lineHeight = 12;
  int maxLines = 4;  // vertical space fits 4 messages
  int startY = 26;

  int total = messages.size();
  if (total == 0) return;

  // SCROLL LIMITS
  int maxScroll = total > maxLines ? (total - maxLines) : 0;
  if (scrollOffset < 0) scrollOffset = 0;
  if (scrollOffset > maxScroll) scrollOffset = maxScroll;

  int startIndex = total - maxLines - scrollOffset;
  if (startIndex < 0) startIndex = 0;

  // DRAW MESSAGES
  for (int i = 0; i < maxLines; i++) {
      int idx = startIndex + i;
      if (idx >= total) break;

      const message &m = messages[idx];
      String txt = shortenMsg(m.text);

      int y = startY + i * lineHeight;

      canvas.setTextSize(1.3);
      canvas.setTextDatum(middle_left);

      if (!m.outgoing) {
          canvas.drawString(">" +txt, 6, y);
      } else {
          int w = canvas.textWidth(txt);
          canvas.drawString( txt+ "<", 240 - w - 14, y);
      }
  }

  // SCROLL BAR -------------------------------------------------

  // bar area: full chat window height
  int barX = 240 - 3;     // right edge
  int barY = 22;          // top
  int barH = maxLines * lineHeight;  // whole scroll area

  if (total > maxLines) {
    float ratio = (float)maxLines / (float)total;
    int thumbHeight = (int)(barH * ratio);
    if (thumbHeight < 6) thumbHeight = 6;

    float posRatio = 1.0f - ((float)scrollOffset / (float)maxScroll);

    int thumbY = barY + (int)((barH - thumbHeight) * posRatio);

    canvas.fillRect(barX, thumbY, 2, thumbHeight, tx_color_rgb565);
  }
}

String findIncomingFingerprint(const std::vector<message> &messages) {
    for (const auto &m : messages) {
        if (!m.outgoing) {
            return m.fingerprint;
        }
    }
    return String(); // nothing found, enjoy your empty string
}

void pwngridMessenger() {
  debounceDelay();
  if(!(WiFi.status() == WL_CONNECTED)){
    drawInfoBox("Info", "Network connection needed", "To open inbox!", false, false);
    delay(3000);
    runApp(43);
    if(WiFi.status() != WL_CONNECTED){
      drawInfoBox("ERROR!", "No network connection", "Operation abort!", true, false);
      menuID = 0;
      return;
    }
  }
  if(!SD.exists("/pwngrid/chats")){
    SD.mkdir("/pwngrid/chats");
  }
  File dir = SD.open("/pwngrid/chats");
  drawInfoBox("Please wait", "Syncing inbox", "with pwngrid...", false, false);
  if(api_client::init(KEYS_FILE) == false){
    drawInfoBox("ERROR!", "Pwngrid init failed!", "Try restarting!", true, false);
    menuID = 0;
    return;
  }
  api_client::pollInbox();
  std::vector<String> chats;
  while(true){
    String nextFileName = dir.getNextFileName();
    if(nextFileName.length()>8){
      String cutName = nextFileName.substring(15);
      chats.push_back(cutName);
    }
    else{
      break;
    }
  }
  chats.push_back("New chat");
  String menuItems[chats.size() + 1];
  for(uint8_t i = 0; i<(chats.size()); i++){
    if(!chats[i]){
      break;
    }
    menuItems[i] = chats[i];
  }
  int8_t result = drawMultiChoice("Open or create chat:", menuItems, chats.size(), 0, 0);
  if(result == chats.size()-1){
    api_client::init(KEYS_FILE);
    debounceDelay();
    File contacts = SD.open(ADDRES_BOOK_FILE, FILE_READ, false);
    if(contacts.size()<5){
      drawInfoBox("Info", "No frends found.", "Go outside and meet some!", true, false);
      menuID = 0;
      return;
    }
    JsonDocument contacts_json;
    DeserializationError err = deserializeJson(contacts_json, contacts);

    if (err) {
        logMessage("Failed to parse contacts: " + String(err.c_str()));
        drawInfoBox("ERROR", "Contacts load failed!", "Check SD card.", true, false);
        menuID = 0;
        return;
    }

    JsonArray contacts_arr = contacts_json.as<JsonArray>();
    logMessage("Array size: " + String(contacts_arr.size()));
    std::vector<unit> contacts_vector;
    for (JsonObject obj : contacts_arr) {
        String name = obj["name"] | "unknown";
        String fingerprint = obj["fingerprint"] | "none";
        logMessage("Name: " + name + ", Fingerprint: " + fingerprint);
        contacts_vector.push_back({name, fingerprint});
    }
    String names[contacts_vector.size()+1];
    
    uint16_t i = 0;
    uint8_t namesSize = 0;
    for(; i < contacts_vector.size(); i++) {
        bool stringTheSame = false;
        for(uint8_t y = 0; y < chats.size(); y++) {
            if(strcmp(chats[y].c_str(), contacts_vector[i].name.c_str()) == 0) {
                stringTheSame = true;
                break;
            }
        }
        if(!stringTheSame) {
            names[namesSize++] = contacts_vector[i].name;
        }
    }
    result = drawMultiChoice("Select chat recepient:", names, namesSize, 0, 0);
    if(result == -1){
      menuID=0;
      return;
    }
    File newChat = SD.open("/pwngrid/chats/" + names[result], FILE_WRITE, true);
    newChat.close();
  }
  else if(result == -1){
    menuID = 0;
    return;
  }
  else{
    debounceDelay();
    String textTyped = "";
    uint8_t temp = 0;
    bool typingMessage = false;
    int16_t scroll = 0;
    uint64_t time = millis();
    while(true){
      M5.update();
      M5Cardputer.update();
      canvas_main.clear();
      canvas_main.setColor(bg_color_rgb565);
      canvas_main.drawRect(5, 75, 230, 20, tx_color_rgb565);
      canvas_main.drawLine(0, 20, 250, 20, tx_color_rgb565);
      canvas_main.setTextDatum(middle_left);
      canvas_main.setTextSize(2);
      canvas_main.drawString(chats[result] + ">", 5, 10);
      canvas_main.setTextSize(1.5);
      canvas_main.drawString(">" + textTyped, 8, 86);
      uint64_t timeNow = millis();
      auto chatHistory = loadMessageHistory(chats[result]);
      renderMessages(canvas_main, chatHistory, scroll);
      canvas_main.setTextSize(1);
      if(((timeNow - 10000) > time) && !typingMessage){
        time = timeNow;
        canvas_main.drawString(" Syncing inbox... Keyboard is disabled!", 2, 102);
        printHeapInfo();
        pushAll();
        api_client::pollInbox();
      }
      else{
        canvas_main.drawString((!typingMessage)? "[d]elete [`]exit [i]nput [;]up [.]down":" Input mode - ENTER or DEL all to exit", 2, 102);
      }
      int maxScroll = (chatHistory.size() > 4) ? (chatHistory.size() - 4) : 0;
      keyboard_changed = M5Cardputer.Keyboard.isChange();
      if(keyboard_changed){Sound(10000, 100, sound);}    
      Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
      for(auto i : status.word){
        if (i == ';' && !typingMessage) scroll++; time = millis();
        if (i == '.' && !typingMessage) scroll--; time = millis();
        if (scroll < 0) scroll = 0;
        if (scroll > maxScroll) scroll = maxScroll;
        if(i=='`'){
          return;
        }
        if(!typingMessage && i == 'd'){
          if(drawQuestionBox("Delete chat?", "Are you sure?", "This can't be undone")){
            dir.close();
            SD.remove("/pwngrid/chats/" + chats[result]);
            drawInfoBox("Sucess", "Chat removed", "", true, false);
            menuID =0;
            return;
          }
        }
        if(typingMessage && temp<24){
          textTyped = textTyped + i;
          temp ++;
        }
        if(i=='i'){
          typingMessage = true;
        }
        debounceDelay();
      }
      if (status.del && temp >=1) {
        textTyped.remove(textTyped.length() - 1);
        temp --;
        debounceDelay();
      }
      else if (status.del && temp ==0){
        typingMessage = false;
      }
      if (status.enter) {
        time = millis();
        message test = {
          chats[result], pwngrid_indentity, 0, textTyped, 0, true
        };
        canvas_main.setTextDatum(middle_center);
        canvas_main.setTextSize(2);
        canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565);
        canvas_main.drawString("Sending message...", canvas_center_x , canvas_h/2);
        pushAll();
        api_client::init(KEYS_FILE);
        File contacts = SD.open(ADDRES_BOOK_FILE, FILE_READ, false);
        if(contacts.size()<5){
          drawInfoBox("ERROR!", "SD card error!.", "Required files not found!", true, false);
          menuID = 0;
          return;
        }
        JsonDocument contacts_json;
        DeserializationError err = deserializeJson(contacts_json, contacts);

        if (err) {
            logMessage("Failed to parse contacts: " + String(err.c_str()));
            drawInfoBox("ERROR", "Contacts load failed!", "Check SD card.", true, false);
            menuID = 0;
            return;
        }

        JsonArray contacts_arr = contacts_json.as<JsonArray>();
        
        String senderFingerprint = "";
        for (JsonObject obj : contacts_arr) {
            String name = obj["name"] | "unknown";
            String fingerprint = obj["fingerprint"] | "none";
            logMessage("Name: " + name + ", Fingerprint: " + fingerprint);
            logMessage("Comparing " + name + " with " + chats[result]);
            if(name == (chats[result] + "\n") || name == chats[result]){
              logMessage("Found sender fingerprint, continuing to send...");
              senderFingerprint = fingerprint;
              break;
            }
        }

        if(senderFingerprint.length()<10)
        {
          senderFingerprint = findIncomingFingerprint(chatHistory);
        }
        

        logMessage("Found fingerprint from chat: " + senderFingerprint);

        if(senderFingerprint.length()<10){
          drawInfoBox("ERROR!", "Sender fingerprint not", "found, send abort!", true, false);
        }
        else{
          if(api_client::sendMessageTo(senderFingerprint, textTyped)){
            registerNewMessage(test);
          }
          else{
            for(uint8_t retries = 0; retries < 3; retries++){
              logMessage("Retrying to send message, attempt " + String(retries+1));
              if(api_client::sendMessageTo(senderFingerprint, textTyped)){
                registerNewMessage(test);
                break;
              }
              delay(1000);
            }
            canvas_main.setTextDatum(middle_center);
            canvas_main.setTextSize(2);
            canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565);
            canvas_main.drawString("Send failed!", canvas_center_x , canvas_h/2);
            pushAll();
            delay(3000);
          }
        }
        typingMessage = false;
        textTyped = "";
        temp = 0;
      }
      pushAll();
    };
  }

} 

inline void trigger(uint8_t trigID){logMessage("Trigger" + String(trigID));}

String isoTimestampToDateTimeString(String isoTimestamp) {
    if (isoTimestamp.length() < 19) {
        return "Invalid Timestamp";
    }

    String date = isoTimestamp.substring(0, 10); // YYYY-MM-DD
    String time = isoTimestamp.substring(11, 19); // HH:MM:SS

    return date + " " + time;
}

void runApp(uint8_t appID){
  logMessage("App started running, ID:"+ String(appID));
  menu_current_opt = 0;
  menu_current_page = 1;
  menuID = 0; 
  if(appID){
    if(appID == 1){
      debounceDelay();
      drawMenuList( wifi_menu , 2, 6);
    }
    #ifdef USE_EXPERIMENTAL_APPS
    if(appID == 2){drawMenuList(bluetooth_menu, 3, 6);}
    if(appID == 3){drawMenuList(IR_menu, 4, 5 );}
    #endif
    if(appID == 4){
      debounceDelay();
      drawMenuList(pwngotchi_menu, 5 , 5);
    }
    if(appID == 5){drawInfoBox("ERROR", "not implemented", "" ,  true, true);}
    if(appID == 6){
      debounceDelay();
      drawMenuList(settings_menu ,6  , 15);
    }
    if(appID == 7){
      debounceDelay();
      drawMenuList(pwngrid_menu, 8, 7);
    }
    if(appID == 8){
      debounceDelay();
      drawMenuList(wardrivingMenuWithWiggle, 9, 6);
    }
    if(appID == 9){}
    if(appID == 10){
      pwngridMessenger();
    }
    if(appID == 11){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To send messages!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Message send abort", true, false);
          menuID = 0;
          return;
        }
      }
      api_client::init(KEYS_FILE);
      File contacts = SD.open(ADDRES_BOOK_FILE, FILE_READ);
      if(!SD.open(ADDRES_BOOK_FILE)){
        drawInfoBox("ERROR", "No frends found.", "Meet and add one.", true, false);
      }
      JsonDocument contacts_json;
      DeserializationError err = deserializeJson(contacts_json, contacts);

      if (err) {
          logMessage("Failed to parse contacts: " + String(err.c_str()));
          return;
      }

      JsonArray contacts_arr = contacts_json.as<JsonArray>();
      logMessage("Array size: " + String(contacts_arr.size()));
      if(contacts_arr.size() == 0){
        drawInfoBox("Info", "No frends found", "Add to text them", true, false);
        menuID = 0;
        return;
      }
      std::vector<unit> contacts_vector;
      for (JsonObject obj : contacts_arr) {
          String name = obj["name"] | "unknown";
          String fingerprint = obj["fingerprint"] | "none";
          logMessage("Name: " + name + ", Fingerprint: " + fingerprint);
          contacts_vector.push_back({name, fingerprint});
      }
      String names[contacts_vector.size()+1];
      for(uint16_t i; i<=contacts_vector.size(); i++){
        names[i] = contacts_vector[i].name;
      }
      int16_t result = drawMultiChoice("Select recepient:", names, contacts_vector.size(), 0, 0);
      if(result >= 0 && result <= contacts_vector.size()){
        String message = userInput("Message:", "", 255);
        drawInfoBox("Sending...", "Sending message, ", "please wait...", false, false);
        if(api_client::sendMessageTo(contacts_vector[result].fingerprint, message)){
          drawInfoBox("Sucess", "Message send", "", true, false);
        }
        else{
          drawInfoBox("Error!", "Error sending message", "Try again or check logs", true, false);
        }
      }
    }
    if(appID == 12){
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To enroll!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Enrol abort", true, false);
          menuID = 0;
          return;
        }
      }
      drawInfoBox("Init", "Initializing keys...", "This may take a while.", false, false);
      SD.mkdir("/pwngrid");
      SD.mkdir("/pwngrid/keys");
      SD.mkdir("/pwngrid/chats");
      File cont = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
      cont.print("[]");
      cont.flush();
      cont.close();

      if(api_client::init(KEYS_FILE)){
        if(!(WiFi.status() == WL_CONNECTED)){
          drawInfoBox("ERROR!", "Connect to wifi", "to proceed", true, false);
          menuID = 0;
          return;
        }
        drawInfoBox("Info", "Enroling with pwngrid...", "This may take a while", false, false);
        if(api_client::enrollWithGrid()){
          drawInfoBox("Info", "Succesfully enrolled.", "All pwngrid functions enabled.", true, false);
        }
        else{
          drawInfoBox("Error", "Something went wrong", "Try again later.", true, false);
        }
        menuID = 0;
        return;
      }
      else{
        drawInfoBox("Error", "Keygen failed", "Try restarting!", true, false);
      }

    }
    if(appID == 13){
      M5Canvas identity_canvas(&M5.Display);
      identity_canvas.createSprite(100, canvas_h -22);
      canvas_main.clear(bg_color_rgb565);
      canvas_main.setTextColor(tx_color_rgb565);
      canvas_main.setColor(tx_color_rgb565);
      canvas_main.qrcode("https://pwnagotchi.ai/pwnfile/#" + pwngrid_indentity, 5, 5);
      canvas_main.setTextSize(2);
      canvas_main.setTextDatum(middle_left);
      canvas_main.drawString("Identity:", 110, 10);
      identity_canvas.setTextSize(1.5);
      identity_canvas.setTextColor(tx_color_rgb565);
      identity_canvas.clear(bg_color_rgb565);
      identity_canvas.setTextDatum(top_left);
      identity_canvas.print(pwngrid_indentity);
      pushAll();
      identity_canvas.pushSprite(110, 35);
      while(true){
        M5.update();
        M5Cardputer.update();
        auto keysState = M5Cardputer.Keyboard.keysState();
        if(keysState.enter){
          menuID = 0;
          return;
        }
        for(auto i : keysState.word){
          if(i=='`'){
            menuID = 0;
            return;
          }
        }
      }
    }
    if(appID == 70){
      debounceDelay();
      sdmanager::runFileManager();
    }
    if(appID == 14){}
    if(appID == 15){
      bool confirmation = drawQuestionBox("Reset?", "This will delete all keys,", "messages, frends, identity");
      if(confirmation){
        canvas_main.fillScreen(bg_color_rgb565);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.clear(bg_color_rgb565);
        canvas_main.setTextSize(2);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString("Resetting pwngrid...", canvas_center_x, canvas_h /7);
        canvas_main.setTextSize(1.2);
        canvas_main.drawString("Old indentity", canvas_center_x, (canvas_h *2 ) /7);
        canvas_main.drawString(pwngrid_indentity, canvas_center_x, (canvas_h*3) /7);
        canvas_main.drawString("New indentity:", canvas_center_x, (canvas_h*4) /7);
        String new_indetity = "NONE";
        canvas_main.drawString(new_indetity, canvas_center_x, (canvas_h*5)/7);
        canvas_main.setTextSize(1);
        canvas_main.drawString("Deletion in progress, please wait...", canvas_center_x, (canvas_h*6)/7);
        pushAll();
        //TODO: Deletion of all pwngrid files
        SD.remove("/pwngrid/keys/id_rsa");
        SD.remove("/pwngrid/keys/id_rsa.pub");
        SD.remove("/pwngrid/token.json");
        SD.remove(ADDRES_BOOK_FILE);
        SD.rmdir("/pwngrid/keys");
        SD.rmdir("/pwngrid/chats");
        SD.rmdir("/pwngrid");

        File chatsDis = SD.open("/pwngrid/chats");
        while(true){
          String nextFileName = chatsDis.getNextFileName();
          if(nextFileName.length()>8){
            SD.remove("/pwngrid/chats/" + nextFileName);
          }
          else{
            break;
          }
        }
        chatsDis.close();

        lastTokenRefresh = 0;

        delay(5000);
        pwngrid_indentity = new_indetity;
        saveSettings();
        menuID = 0;
        return;
      }
    }
    if(appID == 16){
      uint8_t int_peers = getPwngridTotalPeers();
      if(int_peers == 0){
        drawInfoBox("Info", "No nearby pwngrid units", "Try again later", true, false);
        menuID = 0;
        return;
      }
      pwngrid_peer peers_list[int_peers];
      for(uint8_t i = 0; i<int_peers; i++){
        peers_list[i] = getPwngridPeers()[i];
      }
      String mmenu[int_peers + 1];
      for(uint8_t i = 0; i<int_peers; i++){
        mmenu[i] = peers_list[i].face + " | " + peers_list[i].name;
      }
      int8_t choice = drawMultiChoice("Nearby pwngrid units", mmenu, int_peers, 2, 0);
      if(choice == -1){
        menuID = 0;
        return;
      }
      //Peer Details and addressbook addition
      uint8_t current_option;
      debounceDelay();
      while(true)
      {
        drawTopCanvas();
        drawBottomCanvas();
        canvas_main.fillScreen(bg_color_rgb565);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.clear(bg_color_rgb565);
        canvas_main.setTextSize(2);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString(peers_list[choice].face, canvas_center_x, canvas_h / 8);
        canvas_main.setTextSize(1.5);
        canvas_main.drawString(peers_list[choice].name, canvas_center_x, (canvas_h * 2)/8);
        canvas_main.setTextSize(1);
        canvas_main.drawString(peers_list[choice].identity, canvas_center_x, (canvas_h * 3)/8);
        canvas_main.setTextSize(1.5);
        canvas_main.drawString("PWND: " + String(peers_list[choice].pwnd_run) + "/" + String(peers_list[choice].pwnd_tot) + ", RSSI: " + String(peers_list[choice].rssi) , canvas_center_x, (canvas_h*4)/7 );
        String options[] = {"Add to friends", "Send message", "Back"};
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_left);
        canvas_main.drawString(options[0] + "   " + options[1] + "   " + options[2], 10, canvas_h - 30);
        (current_option == 0) ? canvas_main.drawRect(6, canvas_h - 37, 90, 15, tx_color_rgb565): void();
        (current_option == 1) ? canvas_main.drawRect(108, canvas_h - 37, 80, 15, tx_color_rgb565): void();
        (current_option == 2) ? canvas_main.drawRect(200, canvas_h - 37, 27, 15, tx_color_rgb565): void();
        pushAll();
        M5.update();
        M5Cardputer.update();
        auto keys_status = M5Cardputer.Keyboard.keysState();
        auto keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
        for(auto i : keys_status.word){
          if(i == '/'){
            (current_option == 2)? current_option = 0: current_option++;
            debounceDelay();
          }
          else if(i = ','){
            (current_option == 0)? current_option == 2: current_option--;
            debounceDelay();
          }
        }
        if(keys_status.enter){
          if(current_option == 2){
            menuID = 0;
            debounceDelay();
            return;
          }
          if(current_option == 0){
            debounceDelay();
            // Open contacts file for reading and parse JSON into a vector
            File contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_READ);
            unit newPeer = {peers_list[choice].name, peers_list[choice].identity};
                  
            if (contactsFile) {
              JsonDocument doc;  // Use JsonDocument instead of DynamicJsonDocument (since DynamicJsonDocument is deprecated)
              DeserializationError err = deserializeJson(doc, contactsFile);

              if (!err) {
                JsonArray arr = doc.as<JsonArray>();
              
                // Serialize the newPeer struct into a JsonObject
                JsonObject obj = arr.add<JsonObject>();
                serializeUnit(newPeer, obj);  // Custom serialization function

                // Write updated JSON to file
                String out;
                serializeJsonPretty(doc, out);
                contactsFile.close();  // Close the file first
              
                // Reopen the file in write mode to overwrite
                contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
                contactsFile.print(out); 
                contactsFile.flush();
                contactsFile.close();
              } else {
                logMessage("Failed to parse contacts file: " + String(err.c_str()));
              }
            } else {
              // If the file doesn't exist, create it and add the newPeer
              JsonDocument doc;
              JsonArray arr = doc.to<JsonArray>();
            
              // Serialize the newPeer struct into a JsonObject
              JsonObject obj = arr.add<JsonObject>();
              serializeUnit(newPeer, obj);  // Custom serialization function
            
              // Write the new JSON to file
              String out;
              serializeJsonPretty(doc, out);
              contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
              contactsFile.print(out);
              contactsFile.flush();
              contactsFile.close();
            }
            drawInfoBox("Sucess", "Unit added to frend", "list, text to it now!", true, false);
            menuID = 0;
            return;
          }
          if(current_option == 1){
            if(!(WiFi.status() == WL_CONNECTED)){
              drawInfoBox("Info", "Network connection needed", "To send messages!", false, false);
              delay(3000);
              runApp(43);
              if(WiFi.status() != WL_CONNECTED){
                drawInfoBox("ERROR!", "No network connection", "Message send abort", true, false);
                menuID = 0;
                return;
              }
            }
            if(api_client::init(KEYS_FILE) == false){
              drawInfoBox("ERROR!", "Pwngrid init failed!", "Try restarting!", true, false);
              menuID = 0;
              return;
            }
            String message = userInput("Message:", "Type message content:", 100);
            if(!(message.length()>1)){
              menuID = 0;
              return;
            }
            drawInfoBox("Sending...", "Sneding message", "Please wait", false, false);
            if(api_client::sendMessageTo(peers_list[choice].identity, message)){
              drawInfoBox("Send", "Message was send", "succesfuly.", true, false);
            }
            else{
              drawInfoBox("Error", "Message not send.", "Something went wrong!", true, false);
            }
            menuID = 0;
            return;
          }
        }
      }
    }
    if(appID == 17){
      debounceDelay();
      File contacts = SD.open(ADDRES_BOOK_FILE, FILE_READ, true);
      JsonDocument contacts_json;
      DeserializationError err = deserializeJson(contacts_json, contacts);

      if (err) {
          logMessage("Failed to parse contacts: " + String(err.c_str()));
          return;
      }

      JsonArray contacts_arr = contacts_json.as<JsonArray>();
      logMessage("Array size: " + String(contacts_arr.size()));
      uint16_t arrSize = contacts_arr.size();
      std::vector<unit> contacts_vector;
      if(arrSize!=0)
      {   for (JsonObject obj : contacts_arr) {
          String name = obj["name"] | "unknown";
          String fingerprint = obj["fingerprint"] | "none";
          logMessage("Name: " + name + ", Fingerprint: " + fingerprint);
          contacts_vector.push_back({name, fingerprint});
      }}
      else{
        drawInfoBox("Info", "No frends found", "Adding one now", false, false);
        delay(5000);
      }
      String names[contacts_vector.size()+2];
      if(arrSize!=0)
      {for(uint16_t i; i<=contacts_vector.size(); i++){
        names[i] = contacts_vector[i].name;
      }}
      names[contacts_vector.size()] = "Add new";
      int16_t result = (arrSize!=0)? drawMultiChoice("Select contact to manage:", names, contacts_vector.size() + 1, 0, 0): 0;
      if(result<0){
        menuID = 0;
        return;
      }
      else if(result == contacts_vector.size() ){
        String fingerprint;
        String name;
        String subMenu[3] = {"via keyboard", "via PC/Phone", "back"};
        result = drawMultiChoice("Type unit fingerprint:", subMenu, 3, 0, 0);
        if(result==2 || result==-1){
          menuID = 0;
          return;
        }
        else if(result == 0){
          if(!(WiFi.status() == WL_CONNECTED)){
            drawInfoBox("Info", "Network connection needed", "To add unit!", false, false);
            delay(3000);
            runApp(43);
            if(WiFi.status() != WL_CONNECTED){
              drawInfoBox("ERROR!", "No network connection", "Unit add abort!", true, false);
              menuID = 0;
              return;
            }
          }
          fingerprint = userInput("Fingerprint:", "Enter unit fingerprint", 64);
          drawInfoBox("Info", "Parsing unit name", "Please wait", false, false);
          api_client::init(KEYS_FILE);
          name = api_client::getNameFromFingerprint(fingerprint);
          if(fingerprint.length() < 10){
            drawInfoBox("ERROR!", "Unit not found", "Check fingerprint!", true, false);
            menuID = 0;
            return;
          }
        }
        else if(result == 1){
          drawInfoBox("Connect:", "Connect to CardputerSetup", "And go to 192.168.4.1", false, false);
          fingerprint = userInputFromWebServer("Unit fingerprint");
          if(!(WiFi.status() == WL_CONNECTED)){
            drawInfoBox("Info", "Network connection needed", "To add unit!", false, false);
            delay(3000);
            runApp(43);
            if(WiFi.status() != WL_CONNECTED){
              drawInfoBox("ERROR!", "No network connection", "Unit add abort!", true, false);
              menuID = 0;
              return;
            }
          }
          drawInfoBox("Info", "Parsing unit name", "Please wait", false, false);
          if(api_client::init(KEYS_FILE) == false){
            drawInfoBox("ERROR!", "Key init failed", "Try restarting!", true, false);
            menuID = 0;
            return;
          }
          name = api_client::getNameFromFingerprint(fingerprint);
          if(fingerprint.length() < 10 ){
            drawInfoBox("ERROR!", "Unit not found", "Check fingerprint!", true, false);
            menuID = 0;
            return;
          }
        }
        debounceDelay();
        // Open contacts file for reading and parse JSON into a vector
        File contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_READ);
        unit newPeer = {name, fingerprint};
              
        if (contactsFile) {
          JsonDocument doc;  // Use JsonDocument instead of DynamicJsonDocument (since DynamicJsonDocument is deprecated)
          DeserializationError err = deserializeJson(doc, contactsFile);
          if (!err) {
            JsonArray arr = doc.as<JsonArray>();
          
            // Serialize the newPeer struct into a JsonObject
            JsonObject obj = arr.add<JsonObject>();
            serializeUnit(newPeer, obj);  // Custom serialization function
            // Write updated JSON to file
            String out;
            serializeJsonPretty(doc, out);
            contactsFile.close();  // Close the file first
          
            // Reopen the file in write mode to overwrite
            contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
            contactsFile.print(out); 
            contactsFile.flush();
            contactsFile.close();
          } else {
            logMessage("Failed to parse contacts file: " + String(err.c_str()));
          }
        } else {
          // If the file doesn't exist, create it and add the newPeer
          JsonDocument doc;
          JsonArray arr = doc.to<JsonArray>();
        
          // Serialize the newPeer struct into a JsonObject
          JsonObject obj = arr.add<JsonObject>();
          serializeUnit(newPeer, obj);  // Custom serialization function
        
          // Write the new JSON to file
          String out;
          serializeJsonPretty(doc, out);
          contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
          contactsFile.print(out);
          contactsFile.flush();
          contactsFile.close();
        }
        drawInfoBox("Sucess", "Unit added to frend", "list, text to it now!", true, false);
        menuID = 0;
        return;
      }
      uint8_t current_option;
      debounceDelay();
      while(true){  
        drawTopCanvas();
        drawBottomCanvas();
        canvas_main.fillScreen(bg_color_rgb565);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.clear(bg_color_rgb565);
        canvas_main.setTextSize(2);
        canvas_main.setTextDatum(middle_center);
        canvas_main.setTextSize(2);
        canvas_main.drawString(contacts_vector[result].name, canvas_center_x, (canvas_h)/8);
        canvas_main.setTextSize(1);
        canvas_main.drawString(contacts_vector[result].fingerprint, canvas_center_x, (canvas_h * 3)/8);
        canvas_main.setTextSize(1.5);
        String options[] = {"Remove from friends", "Back"};
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_left);
        canvas_main.drawString(options[0] + "      " + options[1], 20, canvas_h - 30);
        (current_option == 0) ? canvas_main.drawRect(15, canvas_h - 37, 125, 15, tx_color_rgb565): void();
        (current_option == 1) ? canvas_main.drawRect(165, canvas_h - 37, 35, 15, tx_color_rgb565): void();
        pushAll();
        M5.update();
        M5Cardputer.update();
        auto keys_status = M5Cardputer.Keyboard.keysState();
        auto keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
        for(auto i : keys_status.word){
          if(i == '/'){
            (current_option == 1)? current_option = 0: current_option++;
            debounceDelay();
          }
          else if(i = ','){
            (current_option == 0)? current_option == 1: current_option--;
            debounceDelay();
          }
        }
        if(keys_status.enter){
          if(current_option == 1){
            menuID = 0;
            return;
          }
          if (current_option == 0) {
            debounceDelay();

            File contactsFile = SD.open(ADDRES_BOOK_FILE, FILE_READ);
            unit peerToDelete = {contacts_vector[result].name, contacts_vector[result].fingerprint};

            if (contactsFile) {
                JsonDocument doc;
                DeserializationError err = deserializeJson(doc, contactsFile);
                contactsFile.close();
            
                if (!err) {
                    JsonArray arr = doc.as<JsonArray>();
                
                    // delete by index like a normal person
                    for (size_t i = 0; i < arr.size(); i++) {
                        JsonObject peer = arr[i];
                        String name = peer["name"] | "";
                        String fp = peer["fingerprint"] | "";
                    
                        if (name == peerToDelete.name && fp == peerToDelete.fingerprint) {
                            arr.remove(i);
                            break; 
                        }
                    }
                  
                    // write back
                    File outFile = SD.open(ADDRES_BOOK_FILE, FILE_WRITE);
                    if (outFile) {
                        serializeJsonPretty(doc, outFile);
                        outFile.close();
                    }
                } else {
                    logMessage("Failed to parse contacts file: " + String(err.c_str()));
                }
            }
          
            drawInfoBox("Sucess", "Unit deleted", "bye bye", true, false);
            menuID = 0;
            return;
        }
        }
      }
    }
    if(appID == 18){
      drawInfoBox("Insert cap!", "Instert lora cap now", "then press enter.", true, false);
      logMessage("Starting wardriver!");
      canvas_main.clear(bg_color_rgb565);
      canvas_main.setTextSize(1.5);
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString("Waiting for time sync...", canvas_center_x, canvas_h/2);
      pushAll();
      startWardriveSession(120000); // 2 minute GPS fix timeout
      canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565);
      canvas_main.fillScreen(bg_color_rgb565);
      canvas_main.setTextColor(tx_color_rgb565);
      canvas_main.clear(bg_color_rgb565);
      canvas_main.setTextSize(1.5);
      canvas_main.setTextDatum(middle_left);
      canvas_main.drawString("Wardriving mode active...", 5, 8);
      canvas_main.setTextSize(1);
      canvas_main.drawString("Hold \"ESC\" to stop", 5, 18);
      pushAll();
      while(true){
        M5.update();
        M5Cardputer.update();
        auto keysState = M5Cardputer.Keyboard.keysState();
        for(auto i : keysState.word){
          if(i=='`')
          {logMessage("Wardriver stopped by user");
          menuID = 0;
          return;}
        }
        speedScan();
        canvas_main.drawString("Scan complete, getting GPS fix...", 5, 27);
        std::vector<wifiSpeedScan> results = getSpeedScanResults();
        wardriveStatus status = wardrive(results, 10000);
        canvas_main.fillRect(5, 23, 230, 8, bg_color_rgb565);
        canvas_main.drawString("Networks found: " + String(status.networksNow) + " Total in run: " + String(status.networksLogged), 5, 27);
        canvas_main.fillRect(5, 90, 230, 20, bg_color_rgb565);
        if(status.gpsFixAcquired){
          canvas_main.fillRect(0, (canvas_h/2)-10, 250, 100, bg_color_rgb565);
          canvas_main.drawString("GPS fix acquired!", 5, 37);
          canvas_main.drawString("Lat: " + String(status.latitude, 6), 5, 47);
          canvas_main.drawString("Lon: " + String(status.longitude, 6), 5, 57);
          canvas_main.drawString("Alt: " + String(status.altitude, 2) + "m", 5, 67);
          canvas_main.drawString(String(isoTimestampToDateTimeString(status.timestampIso)), 5, 77);
        }
        else{
          canvas_main.setTextSize(1.5);
          canvas_main.fillRect(0, (canvas_h/2)-10, 120, 20, bg_color_rgb565);
          canvas_main.drawString("No GPS lock!", 2, (canvas_h/2) + 10);
          canvas_main.setTextSize(1);
          canvas_main.setTextDatum(middle_left);
        }
        canvas_main.drawString("Networks found:", canvas_center_x, 37);
        if(results.size() != 0){
          uint8_t padding = 10;
          for(uint8_t i = 0; i<10; i++){
            canvas_main.fillRect(canvas_center_x, 45 + (i*8) - padding/2, 120, padding, bg_color_rgb565);
            canvas_main.drawString((i<results.size())? results[i].ssid : " ", canvas_center_x, 45 + (i*8));
          }
        }
        else{
          canvas_main.drawString("No networks found!", canvas_center_x, 45);
        }
        pushAll();
        delay(1000);

      }
    }
    if(appID == 19){
      File csvFile;
      // Wardriving CSV viewer with search function
      String selectedPath = "/wardriving/first_seen.csv";
      if(drawQuestionBox("Open custom?", "Open from SD, If not", " \"first seen list\" will be used")){
        selectedPath = sdmanager::selectFile(".csv");
        csvFile = SD.open(selectedPath, FILE_READ);
      }
      else{
        csvFile = SD.open("/wardriving/first_seen.csv", FILE_READ);
      }
      if (!csvFile) {
        drawInfoBox("Error", "File not found", "Wrong selection?", true, false);
        menuID = 0;
        return;
      }
      drawInfoBox("Info", "Loading CSV...", "", false, false);
      
      // Count total lines without storing them all
      uint32_t totalLines = 0;
      csvFile.seek(0);
      char c;
      while (csvFile.available()) {
        c = csvFile.read();
        if (c == '\n') totalLines++;
      }
      if (csvFile.size() > 0 && c != '\n') totalLines++; // Account for last line without newline
      csvFile.close();

      if (totalLines < 3) {
      drawInfoBox("Info", "CSV file is empty or invalid", "", true, false);
      menuID = 0;
      return;
      }
      
      // Function to read a specific line from file without storing all lines
      auto readLineAtIndex = [&](uint32_t lineIndex) -> String {
        String result = "";
        File f = SD.open(selectedPath, FILE_READ);
        if (!f) return result;
        
        uint32_t currentLine = 0;
        char c;
        while (f.available() && currentLine <= lineIndex) {
          c = f.read();
          if (currentLine == lineIndex) {
            if (c == '\n' || c == '\r') {
              if (result.length() > 0) break;
            } else {
              result += c;
            }
          } else if (c == '\n') {
            currentLine++;
          }
        }
        f.close();
        return result;
      };


      // Parse CSV helper function
      auto parseCSVLine = [](const String& csvLine) -> std::vector<String> {
        std::vector<String> fields;
        String field = "";
        bool inQuotes = false;
        for (size_t i = 0; i < csvLine.length(); i++) {
          char c = csvLine[i];
          if (c == '"') {
          inQuotes = !inQuotes;
          } else if (c == ',' && !inQuotes) {
          fields.push_back(field);
          field = "";
          } else {
          field += c;
          }
      }
      fields.push_back(field);
      return fields;
      };

      String searchTerm = "";
      std::vector<int> filteredIndices;
      bool searching = false;
      uint16_t displayIndex = 0;
      uint16_t selectedIndex = 0;
      uint32_t lastSearchTime = 0;
      const uint32_t SEARCH_DELAY_MS = 300;
      
      int displayW = M5.Display.width();
      int displayH = M5.Display.height();
      int tableWidth = displayW - 20;
      int sectionH = 70;

      while (true) {
      M5.update();
      M5Cardputer.update();
      
      if (searching) {
        drawTopCanvas();
        drawBottomCanvas();
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextSize(2);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString("Search CSV", canvas_center_x, canvas_h / 6);
        canvas_main.setTextSize(1.2);
        canvas_main.drawString("SSID/BSSID:", canvas_center_x, canvas_h / 3);
        canvas_main.setTextSize(1.5);
        canvas_main.drawString(searchTerm, canvas_center_x, canvas_h / 2);
        canvas_main.setTextSize(1);
        canvas_main.drawString("[DEL] clear, [ENTER] search, [`] cancel", canvas_center_x, canvas_h * 0.9);
        pushAll();
        
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        uint32_t now = millis();
        
        for (auto k : status.word) {
          if (k == '`') {
            searching = false;
            debounceDelay();
            break;
          }
          searchTerm += k;
          lastSearchTime = now;
          debounceDelay();
        }
        if (status.del && searchTerm.length() > 0) {
          searchTerm.remove(searchTerm.length() - 1);
          lastSearchTime = now;
          debounceDelay();
        }
        if (status.enter) {
          drawInfoBox("Searching...", "Filtering results", "Please wait", false, false);
          filteredIndices.clear();
          String lowerSearch = searchTerm;
          lowerSearch.toLowerCase();
          
          // Optimized: Read file once and parse line by line
          File csvFile = SD.open("/wardrive.csv", FILE_READ);
          if (csvFile) {
            uint32_t currentLine = 0;
            String line = "";
            char c;
            
            while (csvFile.available()) {
              c = csvFile.read();
              
              if (c == '\n' || c == '\r') {
                // Process complete line
                if (currentLine >= 2 && line.length() > 0) {
                  String lowerLine = line;
                  lowerLine.toLowerCase();
                  if (lowerLine.indexOf(lowerSearch) >= 0) {
                    filteredIndices.push_back(currentLine);
                  }
                }
                line = "";
                currentLine++;
                
                // Skip extra newlines/carriage returns
                if (c == '\r' && csvFile.available() && csvFile.peek() == '\n') {
                  csvFile.read();
                }
              } else {
                line += c;
              }
            }
            
            // Don't forget the last line if file doesn't end with newline
            if (line.length() > 0 && currentLine >= 2) {
              String lowerLine = line;
              lowerLine.toLowerCase();
              if (lowerLine.indexOf(lowerSearch) >= 0) {
                filteredIndices.push_back(currentLine);
              }
            }
            
            csvFile.close();
          }
          
          displayIndex = 0;
          selectedIndex = 0;
          searching = false;
          debounceDelay();
        }
      } else {
        drawTopCanvas();
        drawBottomCanvas();
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextSize(1);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.setTextDatum(top_left);
        
        int totalEntries = filteredIndices.empty() ? (totalLines - 2) : filteredIndices.size();
        int currentPage = (displayIndex / 4) + 1;
        int totalPages = (totalEntries + 3) / 4;
        canvas_main.setTextSize(2);
        canvas_main.drawString("Wardriving db viewer", 1, 3);
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString("Page " + String(currentPage) + "/" + String(totalPages) + " | Entries: " + String(totalEntries), canvas_center_x, canvas_h - 18);
        canvas_main.setTextDatum(top_left);
        // Draw table header
        canvas_main.setTextSize(1);
        int headerY = 22;
        int col1X = 5;
        int col2X = 120;
        int scrollbarX = displayW - 8;
        canvas_main.drawLine(col1X, headerY + 12, displayW - 15, headerY + 12, tx_color_rgb565);
        canvas_main.drawString("SSID", col1X, headerY);
        canvas_main.drawString("BSSID", col2X, headerY);
        
        // Draw entries
        int rowHeight = 12;
        int rowY = headerY + 16;
        int visibleRows = 4;
        
        for (int i = 0; i < visibleRows && (displayIndex + i) < totalEntries; i++) {
        int csvIdx = filteredIndices.empty() ? (displayIndex + i + 2) : filteredIndices[displayIndex + i];
        String csvLine = readLineAtIndex(csvIdx);
        auto fields = parseCSVLine(csvLine);
        
        if (fields.size() < 6) continue;
        
        String ssid = fields[1];
        String mac = fields[0];
        
        // Truncate SSID for display
        if (ssid.length() > 18) ssid = ssid.substring(0, 15) + "...";
        // Truncate MAC for display
        if (mac.length() > 17) mac = mac.substring(0, 14) + "...";
        
        // Highlight selected row
        if (selectedIndex == (displayIndex + i)) {
          canvas_main.fillRect(col1X - 3, rowY - 2, displayW - 15, rowHeight, tx_color_rgb565);
          canvas_main.setTextColor(bg_color_rgb565);
          canvas_main.drawString(">", col1X - 5, rowY);
          canvas_main.drawString(ssid, col1X, rowY);
          canvas_main.drawString(mac, col2X, rowY);
          canvas_main.setTextColor(tx_color_rgb565);
        } else {
          canvas_main.drawString(ssid, col1X, rowY);
          canvas_main.drawString(mac, col2X, rowY);
        }
        
        rowY += rowHeight;
        }
        
        // Draw scrollbar
        int scrollbarY = headerY + 14;
        int scrollbarHeight = visibleRows * rowHeight;
        canvas_main.drawLine(scrollbarX, scrollbarY, scrollbarX, scrollbarY + scrollbarHeight, tx_color_rgb565);
        
        if (totalEntries > visibleRows) {
          float scrollRatio = (float)displayIndex / (totalEntries - visibleRows);
          int thumbHeight = max(5, (scrollbarHeight * visibleRows) / totalEntries);
          int thumbY = scrollbarY + (int)((scrollbarHeight - thumbHeight) * scrollRatio);
          canvas_main.fillRect(scrollbarX - 2, thumbY, 4, thumbHeight, tx_color_rgb565);
        }
        
        canvas_main.drawString("[/]next [,]prev [S]search [ENTER]details [`]back", 0, canvas_h - 10);
        pushAll();
        
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        
        for (auto k : status.word) {
        if (k == 's' || k == 'S') {
          searchTerm = "";
          searching = true;
          lastSearchTime = millis();
          debounceDelay();
          break;
        }
        if (k == '`') {
          menuID = 0;
          return;
        }
        }
        
        if (status.word.size() > 0) {
        for (auto k : status.word) {
          if (k == '/') {
          if ((displayIndex + 4) < totalEntries) {
        displayIndex += 4;
        selectedIndex = displayIndex;
          }
          debounceDelay();
          }
          if (k == ',') {
          if (displayIndex > 0) {
        displayIndex = (displayIndex >= 4) ? displayIndex - 4 : 0;
        selectedIndex = displayIndex;
          }
          debounceDelay();
          }
          if (k == '.') {
          if (selectedIndex < (totalEntries - 1)) {
        selectedIndex++;
        if (selectedIndex >= (displayIndex + 4)) displayIndex = selectedIndex - 3;
          }
          debounceDelay();
          }
          if (k == ';') {
          if (selectedIndex > 0) {
        selectedIndex--;
        if (selectedIndex < displayIndex) displayIndex = selectedIndex;
          }
          debounceDelay();
          }
        }
        }
        
        if (status.enter) {
        int csvIdx = filteredIndices.empty() ? (selectedIndex + 2) : filteredIndices[selectedIndex];
        String csvLine = readLineAtIndex(csvIdx);
        auto fields = parseCSVLine(csvLine);
        
        if (fields.size() >= 9) {
          String ssid = fields[1];
          String bssid = fields[0];
          String authMode = (fields.size() > 2) ? fields[2] : "N/A";
          String channel = (fields.size() > 4) ? fields[4] : "N/A";
          String rssi = (fields.size() > 5) ? fields[6] : "N/A";
          String lat = (fields.size() > 6) ? fields[7] : "N/A";
          String lon = (fields.size() > 7) ? fields[8] : "N/A";
          
          debounceDelay();
            drawTopCanvas();
            drawBottomCanvas();
            canvas_main.fillSprite(bg_color_rgb565);
            canvas_main.setTextSize(2);
            canvas_main.setTextColor(tx_color_rgb565);
            canvas_main.setTextDatum(middle_center);
            canvas_main.drawString(ssid, canvas_center_x, 15);
            
            canvas_main.setTextSize(1);
            canvas_main.setTextDatum(top_left);
            canvas_main.drawString("BSSID: " + bssid, 5, 25);
            canvas_main.drawString("Channel: " + channel, 5, 35);
            canvas_main.drawString("RSSI: " + rssi + " dBm", 5, 45);
            
            if(fields.size() > 2) canvas_main.drawString("Auth: " + authMode, 5, 55);
            if(fields.size() > 6) {
            canvas_main.drawString("Lat: " + lat, 5, 65);
            canvas_main.drawString("Lon: " + lon, 5, 75);
            }
            
            canvas_main.setTextSize(1);
            canvas_main.setTextDatum(middle_center);
            canvas_main.drawString("[ENTER] back to list", canvas_center_x, canvas_h - 10);
            
            pushAll();
            
            while(true) {
            M5.update();
            M5Cardputer.update();
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            if(keyboard_changed){Sound(10000, 100, sound);}
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter) break;
            for(auto k : status.word) {
              if(k == '`') break;
            }
            delay(50);
            }
        }
        debounceDelay();
        }
      }
      }}
    if(appID == 20){
      wifion();
      drawInfoBox("Info", "Scanning for wifi...", "Please wait", false, false);
      int numNetworks = WiFi.scanNetworks();
      String wifinets[numNetworks+1];
      if (numNetworks == 0) {
        drawInfoBox("Info", "No wifi nearby", "Abort.", true, false);
        menuID = 0;
        return;
      } else {
        // Przechodzimy przez wszystkie znalezione sieci i zapisujemy ich nazwy w liście
        for (int i = 0; i < numNetworks; i++) {
        String ssid = WiFi.SSID(i);
        
        wifinets[i] = String(ssid);
        logMessage(wifinets[i]);
        }
      }
      uint8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks, 2, 0);
      wifiChoice = WiFi.SSID(wifisel);
      intWifiChoice = wifisel;
      logMessage("Selected wifi: "+ wifiChoice);
      drawInfoBox("Succes", wifiChoice, "Was selected", true, false);
      updateActivity(true);
      menuID = 0;
    }
    if(appID == 21){
      if(wifiChoice.equals("")){
        drawInfoBox("Error", "No wifi selected", "Do it first", true, false);
      }
      else{
        drawWifiInfoScreen(WiFi.SSID(intWifiChoice), WiFi.BSSIDstr(intWifiChoice), String(WiFi.RSSI(intWifiChoice)), String(WiFi.channel(intWifiChoice)));
      }
      updateActivity(true);
      menuID = 0;
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
        debounceDelay();
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
        M5.update();
        M5Cardputer.update();
        debounceDelay();
        uint8_t ssidChoice = drawMultiChoice("Select list", ssidMenu, 4 , 2 , 2);
        if(ssidChoice==0){
          debounceDelay();
          broadcastFakeSSIDs( funny_ssids, 48, sound);
        }
        else if (ssidChoice==1){
          debounceDelay();
          broadcastFakeSSIDs( broken_ssids, 20, sound);
        }
        else if (ssidChoice==2){
          debounceDelay();
          broadcastFakeSSIDs( rickroll_ssids, 8, sound);
          menu_current_opt = 0;
          menu_current_page = 1;
          menuID = 0;
          }
        else if (ssidChoice==3){
          String* BeaconList = makeList("Create spam list", 48, false, 30);
          broadcastFakeSSIDs( BeaconList , sizeof(BeaconList), sound);
        }
        else{
          menuID = 0;
          return;
        }
      }
      else if(tempChoice == 2){
        if(apMode){
          bool answear = drawQuestionBox("AP of?", "AP arleady running!", "Power AP off?");
          if (answear){
            WiFi.mode(WIFI_MODE_NULL);
            apMode = false;
            wifiChoice = "";
            menuID = 0;
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
      updateActivity(true);
      menuID = 0;
    }
    if(appID == 23){
      bool answwear = drawQuestionBox("WARNING!", "This is illegal to use not", "on your network! Continue?");
      if (answwear){
        if(!wifiChoice.equals("")){
          set_target_channel(WiFi.SSID(intWifiChoice).c_str());
          setMac(WiFi.BSSID(intWifiChoice));
          logMessage("User inited deauth");
          initClientSniffing();
          String clients[50];
          int clientLen;
          while(true){
            get_clients_list(clients, clientLen);
            drawInfoBox("Searching...", "Found "+ String(clientLen)+ " clients", "ENTER for next step", false, false);
            updateM5();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              debounceDelay();
              esp_wifi_set_promiscuous(false);
              break;
            }
          }
          // Insert "Everyone" at the beginning by shifting the existing list down.
          // Iterate from clientLen-1 down to 0 so we don't overwrite entries while shifting.
          if (clientLen < 50) {
            // there's room to add one more entry
            for (int i = clientLen - 1; i >= 0; i--) {
              clients[i + 1] = clients[i];
            }
            clients[0] = "Everyone";
            clientLen++; // we added one entry at the front
          } else {
            // no room: drop the last entry, shift everything down and place "Everyone" at 0
            for (int i = 48; i >= 0; i--) {
              clients[i + 1] = clients[i];
            }
            clients[0] = "Everyone";
            // clientLen stays at 50
          }
          int8_t target = drawMultiChoice("Select target.", clients, clientLen , 0, 0);
          if(target==-1){
            menuID = 0;
            clearClients();
            return;
          }
          logMessage("Selected target: " + clients[target]);
          int previousMillis;
          uint16_t interval = 1000;
          int PPS;
          drawInfoBox("Deauth!", "ENTER to end. Target:", String(clients[target]) + " PPS: " + String(PPS), false, false);
          while(true){
            int currentMillis = millis();  
            if (currentMillis - previousMillis >= interval) {
              drawInfoBox("Deauth!", "Deauth active on target:", String(clients[target]) + " PPS: " + String(PPS), false, false);
              previousMillis = currentMillis;
              PPS = 0;
            }
            updateM5();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              break;
            }

            if((clients[target] == "Everyone")?deauth_everyone(1, 10):send_deauth_packets(clients[target], 1, 10)){
              PPS++;
            }
            
          }
          
          clearClients();
        }
        else{
          drawInfoBox("Error!", "No wifi selected!", "Select one first!", true, false);
        }
      }
      updateActivity(true);
      menuID = 0;
    }
    if(appID == 24){
      String mmenu[] = {"Mac sniffing", "EAPOL sniffing"};
      singlePage = false;
      menu_current_pages = 2;
      uint8_t answerrr = drawMultiChoice("Sniffing", mmenu, 2, 1, 0);
      if(answerrr == 0){
        String mmenuu[] = {"Auto switch" ,"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"};
        answerrr = drawMultiChoice("Select chanel", mmenuu, 13, 1, 0);
        if(true){
          uint8_t chanelSwitch = 1;
          static unsigned long lastSwitchTime = millis();
          const unsigned long channelSwitchInterval = 500;  
          esp_wifi_set_channel(answerrr, WIFI_SECOND_CHAN_NONE);
          wifion();  // Ustawienie trybu WiFi na stację
          esp_wifi_set_promiscuous(true);  // Włączenie trybu promiskuitywnego
          esp_wifi_set_promiscuous_rx_cb(client_sniff_promiscuous_rx_cb);
          logMessage("Started mac sniffing!");
          canvas_main.clear();
          uint8_t line;
          while(true){
            M5.update();
            M5Cardputer.update();  
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            if(keyboard_changed){Sound(10000, 100, sound);}
            ;
            drawTopCanvas();
            drawBottomCanvas();
            canvas_main.clear(bg_color_rgb565);
            canvas_main.fillSprite(bg_color_rgb565); //Clears main display
            canvas_main.setTextSize(1);
            canvas_main.setTextColor(tx_color_rgb565);
            canvas_main.setColor(tx_color_rgb565);
            canvas_main.setTextDatum(top_left);
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            canvas_main.println("From:             To:               Ch:");
            line++;
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            canvas_main.println("---------------------------------------");
            line++;
            int macCount;  // Non-const integer to hold the count of MAC entries
            const MacEntry* tableOfMac = get_mac_table(macCount);  // Get the MAC table
            if(macCount){
              for (int i = macCount ; i > 0; i--) {
                // Convert MAC addresses to strings and print them
                canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
                String sourceMac = macToString(tableOfMac[i-1].source);
                String destinationMac = macToString(tableOfMac[i-1].destination);
                String chanelMac = String(tableOfMac[i-1].channel);
                // Example usage with canvas_main
                canvas_main.println(sourceMac + " " + destinationMac + " " + chanelMac);
                line++;
              }
            }
            pushAll();
            line = 0;
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            for(auto i : status.word){
              if(i=='`' && status.fn){
              esp_wifi_set_promiscuous(false);
              WiFi.mode(WIFI_MODE_NULL);
              menuID = 0;
              return;
              }
            }

            if (millis() - lastSwitchTime > channelSwitchInterval && !answerrr) {
              chanelSwitch++;
              if (chanelSwitch > 12) {
                chanelSwitch = 1;  // Loop back to channel 1
              }
              lastSwitchTime = millis();
              esp_wifi_set_channel(chanelSwitch , WIFI_SECOND_CHAN_NONE);
            }

          }
        }
      }
      else if(answerrr==1){
        String mmenuu[] = {"Auto switch" ,"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"};
        answerrr = drawMultiChoice("Select chanel", mmenuu, 13, 1, 0);
        if(SnifferBegin(answerrr)){
          canvas_main.clear();
          pushAll();
          uint8_t line;
          while(true){
            debounceDelay();
            M5.update();
            M5Cardputer.update();  
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            if(keyboard_changed){Sound(10000, 100, sound);}
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            for(auto i : status.word){
              if(i=='`' && status.fn){
                menuID = 0;
                return;
              }
            }
            ;
            drawTopCanvas();
            drawBottomCanvas();
            canvas_main.clear(bg_color_rgb565);
            canvas_main.setTextSize(1);
            canvas_main.setTextColor(tx_color_rgb565);
            //canvas_main.setColor(tx_color_rgb565);
            canvas_main.setTextDatum(top_left);
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            canvas_main.println("EAPOL sniffer ver.1.0 by Devsur.");
            line++;
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            canvas_main.println("From:             To SSID:");
            line++; // ID is what is added to file to identify thic=s copture of others
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            canvas_main.println("---------------------------------------");
            line++;
            canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
            int packetCount = SnifferGetClientCount();
            if(packetCount){
              const PacketInfo* packets = SnifferGetPacketInfoTable();
              for (int i = packetCount  ; i > 0; i--){
                //String strMacSrc = macToString(packets[i-1].srcMac);
                String strMacDest = macToString(packets[i-1].destMac);
                String fileID = String(packets[i-1].fileName);
                canvas_main.setCursor(1, (((PADDING + 1) * line) + 5) + 1);
                canvas_main.println(strMacDest + "   " + fileID);
                line++;
              }
            
            }
            pushAll();
            SnifferLoop();
            line = 0;
          }
        }
        else{
          drawInfoBox("Error!", "Can't init EAPOL sniffer.", "Check SD card!", true, false);
          menuID = 0;
          return;
        }
      }
      updateActivity(true);
    }
    if(appID == 25){
      String new_wiggle_api_key = "";
      String mmenu[] = {"With keyboard", "Via PC/Phone", "Back"};
      uint8_t answerrr = drawMultiChoice("Set new key:", mmenu, 3, 2, 2);
      if(answerrr==0){
        new_wiggle_api_key = userInput("Wiggle.net API key", "Enter new Wiggle API key", 64);
      }
      else if(answerrr==1){
        drawInfoBox("Connect:", "Connect to CardputerSetup", "And go to 192.168.4.1", false, false);
        new_wiggle_api_key = userInputFromWebServer("Wiggle.net API key");
      }
      else{
        menuID = 0;
        return;
      }
      if(new_wiggle_api_key.length() <10){
        drawInfoBox("Error", "Key too short", "Operation abort", true, false);
        menuID = 0;
        return;
      }
      wiggle_api_key = new_wiggle_api_key;
      if(saveSettings()){
        drawInfoBox("Succes", "Wiggle API key", "was changed", true, false);
        menuID = 0;
        return;
      }
      else{
        drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        menuID = 0;
        return;
      }
    }
    if(appID == 26){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To send stats!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Stats send abort", true, false);
          menuID = 0;
          return;
        }
      }
      drawInfoBox("Uploading", "Please wait", "This may take some time...", false, false);
      api_client::init(KEYS_FILE);
      bool result = api_client::uploadCachedAPs();
      if(result){
        drawInfoBox("Succes", "Stats uploaded", "To pwngrid", true, false);
      }
      else{
        drawInfoBox("ERROR!", "Upload failed!", "Check network!", true, false);
      }
      menuID = 0;
      return; 
    }
    if(appID == 27){
      if(drawQuestionBox("Reset token?", "Are you sure?", "This will remove API key!")){
        wiggle_api_key = "";
        if(saveSettings()){
          drawInfoBox("Succes", "Wigle.net API key", "was removed", true, false);
          menuID = 0;
          return;
        }
        else{
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
          menuID = 0;
          return;
        }
      }
      menuID = 0;
    }
    if(appID == 28){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To upload!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Upload abort", true, false);
          menuID = 0;
          return;
        }
      }
      drawInfoBox("Info", "Next, select file", "to upload", true, false);
      String file = sdmanager::selectFile(".csv");
      if(file == ""){
        drawInfoBox("Error", "No file selected", "Operation abort", true, false);
        menuID = 0; 
        return;
      }
      drawInfoBox("Uploading", "Please wait", "This may take some time...", false, false);
      int *statusCode = 0;
      int statusToCode;
      if(uploadToWigle(wiggle_api_key, file.c_str(), statusCode)){
        drawInfoBox("Succes", "File uploaded", "To wigle.net", false, false);
        delay(2000);
        statusToCode = *statusCode;
      }
      else{
        statusToCode = *statusCode;
        drawInfoBox("ERROR!", "Upload failed!", "Status code: " + String(statusToCode), true, false);
        menuID = 0;
        return;
      }
      if(statusToCode == 200){
        drawInfoBox("Succes", "File uploaded", "And registered", true, false);
      }
      else if(statusToCode == 500){
        drawInfoBox("ERROR!", "Server was unable", "to process file", true, false);
      }
      else if(statusToCode == 401){
        drawInfoBox("ERROR!", "Unauthorized", "Check API key", true, false);
      }
      else{
        drawInfoBox("ERROR!", "Upload failed!", "Status code: " + String(statusToCode), true, false);
      }
    }
    if(appID == 29){}
    if(appID == 30){}
    if(appID == 31){}
    if(appID == 32){}
    if(appID == 33){}
    if(appID == 34){}
    if(appID == 35){}
    if(appID == 36){
      if(!pwnagothiMode){
        bool answear = drawQuestionBox("CONFIRMATION", "Operate only if you ", "have premision!");
        if(answear){
          menuID = 0;
          String sub_menu[] = {"Stealth (legacy)", "Normal (beta)"};
          uint8_t modeChoice = drawMultiChoice("Select mode:", sub_menu, 2, 2, 2);
          debounceDelay();
          if(modeChoice==0){
            stealth_mode = true;
          }
          else{
            stealth_mode = false;
          }
          drawInfoBox("INITIALIZING", "Pwnagothi mode initialization", "please wait...", false, false);
          menuID = 0;
          if(pwnagothiBegin()){
            pwnagothiMode = true;
            menuID = 0;
            return;
          }
          else{
            drawInfoBox("ERROR", "Pwnagothi init failed!", "", true, false);
            pwnagothiMode = false;
          }
          menuID = 0;
          return;
        }
      }
      else{
        drawInfoBox("WTF?!", "Pwnagothi mode is on", "Can't you just look at UI!??", true, true);
      }
      menuID = 0;
      return;
    }
    if(appID == 37){
      pwnagothiMode = false;
      WiFi.mode(WIFI_MODE_NULL);
      drawInfoBox("INFO", "Auto mode turned off", "Enabled manual mode", true, false);
      menuID = 0;
    }
    if(appID == 38){
      editWhitelist();
      menuID = 0;
    }
    if(appID == 39){
      drawInfoBox("Info", "Reading SD card...", "Please wait", false, false);
      if(!SD.begin(SD_CS, sdSPI, 1000000)) {
        drawInfoBox("Error", "Cannot open SD card", "Check SD card!", true, true);
        menuID = 0;
        return;
      }
      File root = SD.open("/handshake");
      if (!root || !root.isDirectory()) {
        drawInfoBox("Error", "Cannot open /handshakes", "Check SD card!", true, true);
        menuID = 0;
        return;
      }
      String fileList[50];
      uint8_t fileCount = 0;
      File file = root.openNextFile();
      while (file && fileCount < 50) {
        if (!file.isDirectory()) {
          fileList[fileCount++] = String(file.name());
        }
        file = root.openNextFile();
      }
      if (fileCount == 0) {
        drawInfoBox("Info", "No handshakes found", "", true, false);
        menuID = 0;
        return;
      }
      drawMultiChoiceLonger("Handshakes:", fileList, fileCount, 5, 3);
      updateActivity(true);
      menuID = 0;
    }
    if(appID == 40){
        String name = userInput("New value", "Change Hostname to:", 18);
        if(name != ""){
          hostname = name;
          if(saveSettings()){
            menuID = 0;
            return;
          }
          else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
          menuID = 0;
          return;
        }
        drawInfoBox("Name invalid", "Null inputed,", "operation abort", true, false);
        menuID = 0;
        return;
    }
    if(appID == 41){
      brightnessPicker();
      if(saveSettings()){
        menuID = 0;
        return;
      }
      else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      menuID = 0;
    }
    if(appID == 42){
      String selection[] = {"Off", "On"};
      debounceDelay();
      sound = drawMultiChoice("Sound", selection, 2, 6, 2);
      if(saveSettings()){
        menuID = 0;
        return;
      }
      else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      menuID = 0;
    }
    if(appID == 43){
      wifion();
      drawInfoBox("Scanning...", "Scanning for networks...", "Please wait", false, false);
      int numNetworks = WiFi.scanNetworks();
      String wifinets[50];
      if (numNetworks == 0) {
        drawInfoBox("Info", "No wifi nearby", "Abort.", true, false);
        menuID = 0;
        return;
      }
      else {
        // Przechodzimy przez wszystkie znalezione sieci i zapisujemy ich nazwy w liście
        for (int i = 0; i < numNetworks; i++) {
          String ssid = WiFi.SSID(i);
          logMessage(WiFi.SSID(i) + " =? " + savedApSSID);
          if(WiFi.SSID(i) == (savedApSSID)){
            WiFi.begin(savedApSSID, savedAPPass);
            uint8_t counter;
            while (counter<=10 && !WiFi.isConnected()) {
              delay(1000);
              drawInfoBox("Connecting", "Connecting to " + savedApSSID, "You'll soon be redirected ", false, false);
              counter++;
            }
            counter = 0;
            if(WiFi.isConnected()){
              drawInfoBox("Connected", "Connected succesfully to", String(WiFi.SSID()) , true, false);
              menuID = 0;
              return;
            }
          }
          wifinets[i] = String(ssid);
          logMessage(wifinets[i]);
        }
      }
      wifinets[numNetworks] = "Rescan";
      uint8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks + 1, 6, 3);
      if(wifisel == -1){
        menuID = 0;
        return;
      }
      if(wifisel == numNetworks){
        runApp(43);
        menuID = 0;
        return;
      }
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
        savedApSSID = WiFi.SSID(wifisel);
        savedAPPass = password;
        if(saveSettings()){
          menuID = 0;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else{
        drawInfoBox("Error", "Connection failed", "Maybe wrong password...", true, false);
      }
      menuID = 0;
    }
    if(appID == 44){
      String tempMenu[] = {"From SD", "From WIFI", "From Github"};
      uint8_t choice = drawMultiChoice("Update type", tempMenu, 3, 6, 4);
      if(choice == 0){updateFromSd();}
      else if(choice == 1){
        if(!(WiFi.status() == WL_CONNECTED)){
          runApp(43);
        }
        updateFromHTML();
      }
      else if(choice == 2){
        if(!(WiFi.status() == WL_CONNECTED)){
          runApp(43);
        }
        drawInfoBox("Updating...", "Updating from github...", "This may take a while...", false,false);
        updateFromGithub();
        drawInfoBox("ERROR!", "Update failed!", "Try again or contact dev", true, false);
      }
      menuID = 0;
      }
    if(appID == 45){
      drawInfoBox("M5Gotchi", "v" + String(CURRENT_VERSION) + " by Devsur11  ", "www.github.com/Devsur11 ", true, false);
    }
    if(appID == 46){
      M5.Display.fillScreen(tx_color_rgb565);
      esp_deep_sleep_start(); 
      menuID = 0;
      }
    if(appID == 47){
      String options[] = {"Turn ON", "Turn OFF", "Back"};
      int choice = drawMultiChoice("WiFi Power", options, 3, 2, 0);
      if (choice == 0) {
        wifion();
        drawInfoBox("WiFi", "WiFi turned ON", "", true, false);
      } else if (choice == 1) {
        WiFi.mode(WIFI_MODE_NULL);
        drawInfoBox("WiFi", "WiFi turned OFF", "", true, false);
      } else {
        menuID = 0;
        return;
      }
      menuID = 0;
    }
    if(appID == 48){
      String options[] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("Pwnagothi on boot", options, 3, 6, 0);
      if (choice == 0) {
        pwnagothiModeEnabled = true;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwnagothi will run", "on boot", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        pwnagothiModeEnabled = false;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwnagothi will NOT run", "on boot", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 0;
        return;
      }
      menuID = 0;
    }
    if(appID == 49){
      String options[] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("EAPOL integrity check", options, 3, 6, 0);
      if (choice == 0) {
        skip_eapol_check = false;
        if (saveSettings()) {
          drawInfoBox("Success", "EAPOL check enabled", "", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        skip_eapol_check = true;
        if (saveSettings()) {
          drawInfoBox("Success", "EAPOL check disabled", "", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 0;
        return;
      }
      menuID = 0;
      return;
    }
    if(appID == 50){
      String themeOptions[] = {"White mode", "Dark mode", "Custom", "Back"};
      int themeChoice = drawMultiChoice("Theme", themeOptions, 4, 6, 0);

      if (themeChoice == 0) {
        bg_color = "#FFFFFFFF";
        tx_color = "#000000";
        if (saveSettings()) {
          drawInfoBox("Theme", "White mode applied", "Restarting...", false, false);
          delay(1000);
          ESP.restart();
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (themeChoice == 1) {
        bg_color = "#000000";
        tx_color = "#FFFFFFFF";
        if (saveSettings()) {
          drawInfoBox("Theme", "Dark mode applied", "Restarting...", false, false);
          delay(1000);
          ESP.restart();
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (themeChoice == 2) {
        drawInfoBox("Custom Theme", "Set background color with picker", "Make sure to see text!", false, false);
        delay(5000);
        String customBg = colorPickerUI(false, "#000000ff");
        if (customBg == "exited") return;
        drawInfoBox("Custom Theme", "Set text color with picker", "Make sure to see text!", false, false);
        delay(5000);
        String customTx = colorPickerUI(true, customBg);
        if (customTx == "exited") return;
        bg_color = customBg;
        tx_color = customTx;
        if (saveSettings()) {
          drawInfoBox("Theme", "Custom theme applied", "Restarting...", false, false);
          delay(1000);
          ESP.restart();
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 0;
        return;
      }
      menuID = 0;
    }
    if(appID == 51){
      bool confirm = drawQuestionBox("Factory Reset", "Delete all config data?", "", "Press 'y' to confirm, 'n' to cancel");
      if (!confirm) {
        menuID = 0;
        return;
      }
      drawInfoBox("Factory Reset", "Deleting config data...", "", false, false);
      runApp(15);
      if (SD.exists(NEW_CONFIG_FILE)) {
        SD.remove(NEW_CONFIG_FILE);
        SD.remove("/uploaded.json");
        SD.remove("/cracked.json");
        SD.remove(PERSONALITY_FILE);
        drawInfoBox("Success", "Data deleted", "Restarting...", false, false);
        delay(1000);
        ESP.restart();
      } else {
        drawInfoBox("Error", "Data files not found", "Nothing to delete", true, false);
        menuID = 0;
        return;
      }
    }
    if(appID == 52){
      if(WiFi.status() == WL_CONNECTED){
        if(wpa_sec_api_key.equals("")){
          drawInfoBox("Error", "No API key set", "Set it first!", true, false);
          menuID = 0;
          return;
        }
        else{
          drawInfoBox("Syncing", "Syncing data with WPASec", "Please wait...", false, false);
          processWpaSec(wpa_sec_api_key.c_str());
          drawInfoBox("Done", "Sync finished", "Press enter to continue", true, false);
          menuID = 0;
          appID = 0;
          return;
        }
      }
      else{
        drawInfoBox("Error", "No wifi connection", "Connect to wifi in settings!", true, false);
      }
      menuID = 0;
      return;
    }    
    if(appID == 53){
      if(SD.exists("/cracked.json")){
        File crackedFile = SD.open("/cracked.json", FILE_READ);
        if (!crackedFile) {
          drawInfoBox("Error", "Failed to open cracked.json", "Check SD card!", true, false);
          menuID = 0;
          return;
        }
        crackedFile.close();
        std::vector<CrackedEntry> entries = getCrackedEntries();
        if (entries.empty()) {
          drawInfoBox("Info", "No cracked entries found", "Try syncing", true, false);
          crackedFile.close();
          menuID = 0;
          return;
        }
        String displayList[entries.size()];
        while(true){
          for (size_t i = 0; i < entries.size(); i++) {
            displayList[i] = entries[i].ssid;
          }
          int8_t selection = drawMultiChoice("Cracked list", displayList, entries.size(), 5, 3);
          if(selection == -1){
            crackedFile.close();
            menuID = 0;
            return;
          }
          String detailInfo = "Password: " + entries[selection].password;
          String detailInfo2 = "Bssid: " + entries[selection].bssid;
          drawInfoBox(entries[selection].ssid, detailInfo, detailInfo2, true , false);
          M5.update();
          M5Cardputer.update();
          Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
          if(M5Cardputer.Keyboard.isChange()){Sound(10000, 100, sound);}
        }
      }
      else{
        drawInfoBox("Error", "List is empty", "Try sync first!", true, false);
      }
      menuID = 0;
    }
    if(appID == 54){
      String menuList[] = {"With keyboard", "With pc/phone", "Back"};
      uint8_t choice = drawMultiChoice("WPAsec API key setup", menuList, 3, 6, 3);
      if(choice == 0){
        wpa_sec_api_key = userInput("API key", "Enter your WPAsec API key", 50);
        if(wpa_sec_api_key.equals("")){
          drawInfoBox("Error", "Key can't be empty", "Operation aborted", true, false);
          wpa_sec_api_key = "";
          saveSettings();
          appID = 0;
          menuID = 0;
          return;
        }
        if(saveSettings()){
          drawInfoBox("Success", "API key saved", "", true, false);
          appID = 0;
          menuID = 0;
          return;
        }
        else{
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
          appID = 0;
          menuID = 0;
          return;
        }
      }
      else if(choice == 1){
        drawInfoBox("READY", "Connect to \"CardputerSetup\"", "and go to 192.168.4.1", false, false);
        wpa_sec_api_key =  userInputFromWebServer("Your WPAsec API key");
        if(wpa_sec_api_key.equals("")){
          drawInfoBox("Error", "Key can't be empty", "Operation aborted", true, false);
          wpa_sec_api_key = "";
          saveSettings();
          return;
        }
        else{
          if(saveSettings()){
            drawInfoBox("Success", "API key saved", "", true, false);
            return;
          }
          else{
            drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
            return;
          }
        }
      }
      else {
        appRunning = false;
        appID = 0;
        menuID = 0;
        return;
      }
    }
    if(appID == 55){
      debounceDelay();
      drawMenuList(wpasec_menu, 7, 3);
    }
    if(appID == 56){
      ESP.restart();
    }
    if(appID == 57){
      if(initPersonality()){
        debounceDelay();
        }
      else{
        drawInfoBox("Error", "Can't load personality", "Check SD card!", true, false);
        menuID = 0;
        return;
      }
      while (true) {
        String personality_options[] = {
          "Nap time" + String(" (ms): ") + String(pwnagotchi.nap_time),
          "Delay after wifi scan" + String(" (ms): ") + String(pwnagotchi.delay_after_wifi_scan), 
          "Delay after no networks found" + String(" (ms): ") + String(pwnagotchi.delay_after_no_networks_found), 
          "Delay after attack fail" + String(" (ms): ") + String(pwnagotchi.delay_after_attack_fail),
          "Delay after attack success" + String(" (ms): ") + String(pwnagotchi.delay_after_successful_attack),
          "Deauth packets sent" + String(" : ") + String(pwnagotchi.deauth_packets_sent),
          "Delay after deauth" + String(" (ms): ") + String(pwnagotchi.delay_after_deauth),
          "Delay after picking target" + String(" (ms): ") + String(pwnagotchi.delay_after_picking_target),
          "Delay before switching target" + String(" (ms): ") + String(pwnagotchi.delay_before_switching_target),
          "Delay after client found" + String(" (ms): ") + String(pwnagotchi.delay_after_client_found),
          "Handshake wait time" + String(" (ms): ") + String(pwnagotchi.handshake_wait_time),
          "Deauth packet delay" + String(" (ms): ") + String(pwnagotchi.deauth_packet_delay),
          "Delay after no clients found" + String(" (ms): ") + String(pwnagotchi.delay_after_no_clients_found),
          "Client discovery timeout" + String(" (ms): ") + String(pwnagotchi.client_discovery_timeout),
          "Sound on events" + String(pwnagotchi.sound_on_events ? " (y)" : " (n)"),
          "Deauth on" + String(pwnagotchi.deauth_on ? " (y)" : " (n)"),
          "Add to whitelist on success" + String(pwnagotchi.add_to_whitelist_on_success ? " (y)" : " (n)"),
          "Add to whitelist on fail" + String(pwnagotchi.add_to_whitelist_on_fail ? " (y)" : " (n)"),
          "Activate sniffer on deauth" + String(pwnagotchi.activate_sniffer_on_deauth ? " (y)" : " (n)"),
          "Back"
        };
      
        int8_t choice = drawMultiChoiceLonger("Personality settings", personality_options, 20, 6, 4);
        if(choice == 19 || choice == -1){
          savePersonality();
          menuID = 0;
          return;
        }
        else if(choice >= 14){
          bool valueToSet = getBoolInput(personality_options[choice], "Press t or f, then ENTER", false);
          switch (choice) {
            case 14:
              pwnagotchi.sound_on_events = valueToSet;
              break;
            case 15:
              pwnagotchi.deauth_on = valueToSet;
              break;
            case 16:
              pwnagotchi.add_to_whitelist_on_success = valueToSet;
              break;
            case 17:
              pwnagotchi.add_to_whitelist_on_fail = valueToSet;
              break;
            case 18:
              pwnagotchi.activate_sniffer_on_deauth = valueToSet;
              break;
            case 19:
              savePersonality();
              menuID = 0;
              return;
            default:
              break;
          }
          savePersonality();
        }
        else{
          int16_t valueToSet = getNumberfromUser(personality_options[choice], "Enter new value", 60000);
          if(valueToSet == -1){
            continue;
          }
          switch (choice) {
            case 0:
              pwnagotchi.nap_time = valueToSet;
              break;
            case 1:
              pwnagotchi.delay_after_wifi_scan = valueToSet;
              break;
            case 2:
              pwnagotchi.delay_after_no_networks_found = valueToSet;
              break;
            case 3:
              pwnagotchi.delay_after_attack_fail = valueToSet;
              break;
            case 4:
              pwnagotchi.delay_after_successful_attack = valueToSet;
              break;
            case 5:
              pwnagotchi.deauth_packets_sent = valueToSet;
              break;
            case 6:
              pwnagotchi.delay_after_deauth = valueToSet;
              break;
            case 7:
              pwnagotchi.delay_after_picking_target = valueToSet;
              break;
            case 8:
              pwnagotchi.delay_before_switching_target = valueToSet;
              break;
            case 9:
              pwnagotchi.delay_after_client_found = valueToSet;
              break;
            case 10:
              pwnagotchi.handshake_wait_time = valueToSet;
              break;
            case 11:
              pwnagotchi.deauth_packet_delay = valueToSet;
              break;
            case 12:
              pwnagotchi.delay_after_no_clients_found = valueToSet;
              break;
            case 13:
              pwnagotchi.client_discovery_timeout = valueToSet;
              break;
            default:
              break;
          }
          savePersonality();
        }
      }
      }
    if(appID == 58){
      String menuu[] = {"Yes", "No", "Back"};
      int8_t choice = drawMultiChoice("Log to sd card?", menuu, 3, 6, 0);
      if(choice == 0){
        sd_logging = true;
        if(saveSettings()){
          drawInfoBox("Success", "Logging to SD card enabled", "", true, false);
          menuID = 0;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else if(choice == 1){
        sd_logging = false;
        if(saveSettings()){
          drawInfoBox("Success", "Logging to SD card disabled", "", true, false);
          menuID = 0;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else{
        menuID = 0;
        return;
      }
    }
    if(appID == 59){
      String menuu[] = {"Dim screen", "Toggle auto mode", "Back"};
      int8_t choice = drawMultiChoice("On tap action", menuu, 3, 6, 0);
      if(choice == 0){
        toogle_pwnagothi_with_gpio0 = false;
        saveSettings();
      }
      else if(choice == 1){
        toogle_pwnagothi_with_gpio0 = true;
        saveSettings();
      }
      else{
        menuID = 0;
        return;
      }
      menuID = 0;
      return;
    }
    if(appID == 60){
      String mmenu[3] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("Advertise pwngrid", mmenu, 3, 6, 0);
      if (choice == 0) {
        advertisePwngrid = true;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwngrid advertising enabled", "", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        advertisePwngrid = false;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwngrid advertising disabled", "", true, false);
          menuID = 0;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 0;
        return;
      }
      menuID = 0;
      return;
    }
    return;
  }
}

int16_t getNumberfromUser(String tittle, String desc, uint16_t maxNumber){
  uint16_t number = 0;
  appRunning = true;
  debounceDelay();
  while (true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setCursor(5, 10);
    canvas_main.println(tittle + ":");
    canvas_main.setTextDatum(middle_center);
    canvas_main.setTextSize(1);
    canvas_main.drawString(desc, canvas_center_x, canvas_h * 0.9);
    canvas_main.setTextSize(1.5);
    canvas_main.drawString(String(number), canvas_center_x, canvas_h / 2);
    pushAll();
    M5.update();
    M5Cardputer.update();
    ;
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        return 0;
      }
      if(i>='0' && i<='9'){
        number = number * 10 + (i - '0');
        debounceDelay();
      }
    }
    if (status.del) {
      logMessage("Delete pressed");
      if (number > 0) {
          number = number / 10;
      }
      debounceDelay();
    }
    if (status.enter) {
      if(number > maxNumber){
        drawInfoBox("Error", "Number can't be higher than " + String(maxNumber), "", true, false);
        number = 0;
        debounceDelay();
      }
      else{
        appRunning = false;
        logMessage("Number input returning: " + String(number));
        return number;
      }
    }
  }
}

bool getBoolInput(String tittle, String desc, bool defaultValue){
  bool toReturn = defaultValue;
  appRunning = true;
  debounceDelay();
  while (true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setCursor(5, 10);
    canvas_main.println(tittle + ":");
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(desc, canvas_center_x, canvas_h * 0.9);
    canvas_main.setTextSize(1.5);
    if(toReturn){
      canvas_main.drawString("True", canvas_center_x, canvas_h / 2);
    }
    else{
      canvas_main.drawString("False", canvas_center_x, canvas_h / 2);
    }
    pushAll();
    M5.update();
    M5Cardputer.update();
    ;
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        debounceDelay();
        return defaultValue;
      }
      if(i=='t'){//'y'){ replace with t for relase - my cardputer keyboard has broken t key
        toReturn = true;
      }
      if(i=='f'){
        toReturn = false;
      }
    }
    if (status.enter) {
      appRunning = false;
      logMessage("Bool input returning: " + String(toReturn));
      return toReturn;
    }
  }
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
    return;
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
  debounceDelay();
  //bool loop = 1;
  while (true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1);
    canvas_main.drawString(desc, canvas_center_x, canvas_h * 0.9);
    M5.update();
    M5Cardputer.update();
    ;
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
      debounceDelay();
    }
    if (status.del && temp >=1) {
      textTyped.remove(textTyped.length() - 1);
      temp --;
      debounceDelay();
    }
    if (status.enter) {
      break;
    }
    
    if(temp > maxLenght){
      drawInfoBox("Error", "Can't type more than " + String(maxLenght), " characters" , true, false);
      textTyped.remove(textTyped.length() - 1);
      temp --;
      debounceDelay();
    }
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    canvas_main.setTextColor(tx_color_rgb565);
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
  logMessage("Userinput returning: " + textTyped);
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
  debounceDelay();
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(info, canvas_center_x, canvas_h / 2);
    canvas_main.drawString(info2, canvas_center_x, (canvas_h / 2) + 20);
    canvas_main.setTextSize(1);
    canvas_main.drawString( label, canvas_center_x, canvas_h * 0.9);
    pushAll();
    M5.update();
    M5Cardputer.update();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    ;

    
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        return false;
      }
      else if(i=='y'){
        logMessage("yes");
        return true;
      }
      else if(i=='n'){
        logMessage("No");
        return false;
      }
    }
  }
  appRunning = false;
}

//function returns selected option index or -1 if cancelled
int drawMultiChoice(String tittle, String toDraw[], uint8_t menuSize , uint8_t prevMenuID, uint8_t prevOpt) {
  debounceDelay();
  uint8_t tempOpt = 0;
  menu_current_opt = 0;
  menu_current_page = 1;
  menu_len = menuSize;
  singlePage = false;
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    M5.update();
    M5Cardputer.update();  
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

    canvas_main.clear(bg_color_rgb565);
    canvas_main.fillSprite(bg_color_rgb565); //Clears main display
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, PADDING + 1);
    canvas_main.println(tittle);
    canvas_main.setTextSize(2);
    char display_str[256] = ""; // Increased buffer size
    uint8_t startIdx = (menu_current_page - 1) * 4;
    if (startIdx >= menuSize) startIdx = 0; // Prevent overflow
    
    uint8_t remainingItems = (menuSize > startIdx) ? menuSize - startIdx : 0;
    uint8_t itemsToShow = min(remainingItems, (uint8_t)4); // Show max 4 items per page
    
    for (uint8_t j = 0; j < itemsToShow && (startIdx + j) < menuSize; j++) {
      uint8_t idx = startIdx + j;
      String itemText = toDraw[idx];
      if (itemText.length() > 40) { // Truncate long strings
        itemText = itemText.substring(0, 37) + "...";
      }
      snprintf(display_str, sizeof(display_str), "%s %s", (tempOpt == idx) ? ">" : " ", itemText.c_str());
      int y = PADDING + (j * ROW_SIZE / 2) + 20;
      canvas_main.drawString(display_str, 0, y);
    }
    pushAll();

    
    for(auto i : status.word){
      if(i=='`'){
        Sound(10000, 100, sound);
        menuID = prevMenuID;
        menu_current_opt = prevOpt;
        return -1;
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
      float temp = 1+(menu_current_opt/4);
      menu_current_page = temp;
    }
    if(isOkPressed()){
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return tempOpt;
    }
    
  }
}

int drawMultiChoiceLonger(String tittle, String toDraw[], uint8_t menuSize , uint8_t prevMenuID, uint8_t prevOpt) {
  debounceDelay();
  uint8_t tempOpt = 0;
  menu_current_opt = 0;
  menu_current_page = 1;
  menu_len = menuSize;
  singlePage = false;
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    M5.update();
    M5Cardputer.update();  
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    ;

    canvas_main.clear(bg_color_rgb565);
    canvas_main.fillSprite(bg_color_rgb565); //Clears main display
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, PADDING + 1);
    canvas_main.println(tittle);
    canvas_main.setTextSize(1);
    char display_str[100] = "";
    uint16_t start = (menu_current_page - 1) * 8;
    uint16_t end = start + 8;
    if (end > menu_len) end = menu_len;

    for (uint16_t j = start; j < end; j++) {
        sprintf(display_str, "%s %s", (tempOpt == j) ? ">" : " ",
                toDraw[j].c_str());
        int y = 8 + ((j - start) * 10) + 20;
        canvas_main.drawString(display_str, 0, y);
    }
    pushAll();

    
    for(auto i : status.word){
      if(i=='`'){
        Sound(10000, 100, sound);
        menuID = prevMenuID;
        menu_current_opt = prevOpt;
        return -1;
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
      float temp = 1+(menu_current_opt/8);
      menu_current_page = temp;
    }
    if(isOkPressed()){
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return tempOpt;
    }
    
  }
}

String* makeList(String windowName, uint8_t appid, bool addln, uint8_t maxEntryLen){
  uint8_t writeID = 0;
  String list[] = {"Add element", "Remove element" , "Done", "Preview"};
  String* listToReturn = new String[50];
  if(maxEntryLen > 12){maxEntryLen = 12;}
  debounceDelay();
  while(true){
    ;
    uint8_t choice = drawMultiChoice(windowName, list, 4 , 0, 0);
    if (choice==0){
      String tempText = userInput("Add value:", "", maxEntryLen);
      // if(addln){
      //   listToReturn[writeID] = tempText + "\n";
      //   writeID++;
      // }
      // else{
        listToReturn[writeID] = tempText;
        writeID++;
      //}
      logMessage("Added to list: " + tempText);
    }
    else if (choice==2){
      debounceDelay();
      return listToReturn;
    }
    else if (choice==1){
      s16_t idOfItemToRemove = drawMultiChoice("Remove element", list, writeID, 0, 0);
      if (idOfItemToRemove == -1) {
        continue;
      }
      else{// Shift items up to remove the selected one
        for (uint8_t i = idOfItemToRemove; i < writeID - 1; i++) {
          list[i] = list[i + 1];
        }
        list[writeID - 1] = "";
        writeID--;}
    }
    else if (choice==3){
      debounceDelay();
      while(true){
        if (writeID == 0) {
          drawInfoBox("Info", "List is empty", "Nothing to preview.", true, false);
          break;
        }
        drawTopCanvas();
        drawBottomCanvas();
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}  
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

void drawList(String toDraw[], uint8_t menu_size) {
  menu_len = menu_size;

  M5.update();
  M5Cardputer.update();

  canvas_main.fillSprite(bg_color_rgb565);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextSize(2);
  canvas_main.setTextDatum(top_left);

  int maxW = canvas_main.width() - 10;  // leave space for scrollbar
  int maxH = canvas_main.height();
  int lineH = 18;

  static uint32_t marqueeTick = millis();
  static int marqueeOffset = 0;
  const uint32_t MARQUEE_DELAY_MS = 300; // speed of marquee

  // ============================================================
  // Build wrapped buffer for NON-selected items, but record
  // the selected item index BEFORE wrapping
  // ============================================================
  std::vector<String> wrapped;
  int selectedLineIndex = 0;

  for (uint8_t i = 0; i < menu_len; i++) {
    bool isSel = (menu_current_opt == i);
    String full = toDraw[i];

    if (!isSel) {
      // wrap normally
      wrapped.push_back("  " + full);
    } else {
      // selected item occupies exactly one line in wrapped list,
      // but we add only a placeholder so line calculation works
      selectedLineIndex = wrapped.size();
      wrapped.push_back("SELECTED_LINE"); // placeholder
    }
  }

  int totalLines = wrapped.size();
  int linesPerPage = maxH / lineH;

  // ============================================================
  // figure out scrolling of page
  // ============================================================
  static int targetScroll = 0;
  static int currentScroll = 0;

  if (selectedLineIndex < targetScroll) {
    targetScroll = selectedLineIndex;
  }
  if (selectedLineIndex >= targetScroll + linesPerPage) {
    targetScroll = selectedLineIndex - linesPerPage + 1;
  }
  if (targetScroll < 0) targetScroll = 0;
  if (targetScroll > totalLines - linesPerPage)
    targetScroll = totalLines - linesPerPage;
  if (targetScroll < 0) targetScroll = 0;

  // Smooth immediate - keep currentScroll synced (was previously forcing)
  if (currentScroll < targetScroll) currentScroll = targetScroll;
  else if (currentScroll > targetScroll) currentScroll = targetScroll;

  int yOffset = -(currentScroll * lineH);

  // ============================================================
  // draw lines + real selected item
  // ============================================================
  for (int i = 0; i < totalLines; i++) {
    int y = yOffset + i * lineH;
    if (y < -lineH || y > maxH) continue;

    if (i != selectedLineIndex) {
      // normal wrapped item
      canvas_main.drawString(wrapped[i], 0, y);
      continue;
    }

    // ====================================================
    // selected item special drawing (marquee)
    // ====================================================
    String full = toDraw[menu_current_opt];

    // draw cursor permanently on the left
    canvas_main.drawString(">", 0, y);

    // how much horizontal space remains after cursor
    int textX = canvas_main.textWidth("> ");
    int spaceW = maxW - textX;

    int fullW = canvas_main.textWidth(full);

    if (fullW <= spaceW) {
      // fits: no marquee
      canvas_main.drawString(full, textX, y);
      marqueeOffset = 0;
    } else {
      // compute how many chars fit
      int maxChars = full.length();
      while (maxChars > 0 &&
           canvas_main.textWidth(full.substring(0, maxChars)) > spaceW) {
        maxChars--;
      }
      if (maxChars < 1) maxChars = 1;

      int maxOffset = full.length() - maxChars;
      if (maxOffset < 0) maxOffset = 0;

      // marquee logic: advance only until the last visible slice reaches the end,
      // then stop (do not keep wrapping into empty space)
      uint32_t now = millis();
      if (now - marqueeTick >= MARQUEE_DELAY_MS) {
        marqueeTick = now;
        if (marqueeOffset < maxOffset+1) {
          marqueeOffset++;
        } else {
          marqueeOffset = maxOffset;
          marqueeOffset = 0;
        }
      }

      // clamp start
      int start = marqueeOffset;
      if (start < 0) start = 0;
      if (start > maxOffset) start = maxOffset;

      int end = start + maxChars;
      if (end > full.length()) end = full.length();

      String slice = full.substring(start, end);
      canvas_main.drawString(slice, textX, y);
    }
  }

  // ============================================================
  // Scrollbar
  // ============================================================
  int sbX = canvas_main.width() - 6;
  int sbH = canvas_main.height();
  int scrollMax = max(totalLines - linesPerPage, 1);

  float ratio = (float)currentScroll / scrollMax;
  float barRatio = (float)linesPerPage / totalLines;

  int barH = sbH * barRatio;
  if (barH < 10) barH = 10;
  int barY = ratio * (sbH - barH);

  canvas_main.fillRect(sbX, 0, 6, sbH, bg_color_rgb565);
  canvas_main.fillRect(sbX, barY, 6, barH, tx_color_rgb565);

  // ============================================================
  // input handling
  // ============================================================
  auto &keys = M5Cardputer.Keyboard;

  if (keys.isKeyPressed(KEY_ENTER)) {
    return;
  }
  if (keys.isKeyPressed('.')) {
    menu_current_opt = (menu_current_opt + 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
  }
  if (keys.isKeyPressed(';')) {
    menu_current_opt = (menu_current_opt + menu_len - 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
  }
  if (keys.isKeyPressed('`')) {
    return;
  }
}

void drawMenuList(menu toDraw[], uint8_t menuIDPriv, uint8_t menu_size) {
  menuID = menuIDPriv;
  menu_len = menu_size;

  M5.update();
  M5Cardputer.update();

  canvas_main.fillSprite(bg_color_rgb565);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextSize(2);
  canvas_main.setTextDatum(top_left);

  int maxW = canvas_main.width() - 10;  // leave space for scrollbar
  int maxH = canvas_main.height();
  int lineH = 18;

  static uint32_t marqueeTick = millis();
  static int marqueeOffset = 0;
  const uint32_t MARQUEE_DELAY_MS = 300; // speed of marquee

  // ============================================================
  // Simplified menu rendering: avoid heap allocations by not building
  // a wrapped string vector. Each menu entry is treated as a single
  // logical line to minimize dynamic String usage.
  // ============================================================
  int selectedLineIndex = menu_current_opt;
  int totalLines = menu_len;
  int linesPerPage = maxH / lineH;

  // ============================================================
  // figure out scrolling of page
  // ============================================================
  static int targetScroll = 0;
  static int currentScroll = 0;

  if (selectedLineIndex < targetScroll) {
    targetScroll = selectedLineIndex;
  }
  if (selectedLineIndex >= targetScroll + linesPerPage) {
    targetScroll = selectedLineIndex - linesPerPage + 1;
  }
  if (targetScroll < 0) targetScroll = 0;
  if (targetScroll > totalLines - linesPerPage)
    targetScroll = totalLines - linesPerPage;
  if (targetScroll < 0) targetScroll = 0;

  // Smooth immediate - keep currentScroll synced (was previously forcing)
  if (currentScroll < targetScroll) currentScroll = targetScroll;
  else if (currentScroll > targetScroll) currentScroll = targetScroll;

  int yOffset = -(currentScroll * lineH);

  // ============================================================
  // draw lines + real selected item
  // ============================================================
  for (int i = 0; i < totalLines; i++) {
    int y = yOffset + i * lineH;
    if (y < -lineH || y > maxH) continue;
    if (i != selectedLineIndex) {
      // normal non-selected item: draw prefix + name without allocating
      canvas_main.drawString("  ", 0, y);
      canvas_main.drawString(toDraw[i].name, 18, y);
      continue;
    }

    // ====================================================
    // selected item special drawing (marquee)
    // ====================================================
    String full = toDraw[menu_current_opt].name;

    // draw cursor permanently on the left
    canvas_main.drawString(">", 0, y);

    // how much horizontal space remains after cursor
    int textX = canvas_main.textWidth("> ");
    int spaceW = maxW - textX;

    int fullW = canvas_main.textWidth(full);

    if (fullW <= spaceW) {
      // fits: no marquee
      canvas_main.drawString(full, textX, y);
      marqueeOffset = 0;
    } else {
      // compute how many chars fit
      int maxChars = full.length();
      while (maxChars > 0 &&
           canvas_main.textWidth(full.substring(0, maxChars)) > spaceW) {
        maxChars--;
      }
      if (maxChars < 1) maxChars = 1;

      int maxOffset = full.length() - maxChars;
      if (maxOffset < 0) maxOffset = 0;

      // marquee logic: advance only until the last visible slice reaches the end,
      // then stop (do not keep wrapping into empty space)
      uint32_t now = millis();
      if (now - marqueeTick >= MARQUEE_DELAY_MS) {
        marqueeTick = now;
        if (marqueeOffset < maxOffset+1) {
          marqueeOffset++;
        } else {
          marqueeOffset = maxOffset;
          marqueeOffset = 0;
        }
      }

      // clamp start
      int start = marqueeOffset;
      if (start < 0) start = 0;
      if (start > maxOffset) start = maxOffset;

      int end = start + maxChars;
      if (end > full.length()) end = full.length();

      String slice = full.substring(start, end);
      canvas_main.drawString(slice, textX, y);
    }
  }

  // ============================================================
  // Scrollbar
  // ============================================================
  int sbX = canvas_main.width() - 6;
  int sbH = canvas_main.height();
  int scrollMax = max(totalLines - linesPerPage, 1);

  float ratio = (float)currentScroll / scrollMax;
  float barRatio = (float)linesPerPage / totalLines;

  int barH = sbH * barRatio;
  if (barH < 10) barH = 10;
  int barY = ratio * (sbH - barH);

  canvas_main.fillRect(sbX, 0, 6, sbH, bg_color_rgb565);
  canvas_main.fillRect(sbX, barY, 6, barH, tx_color_rgb565);

  // ============================================================
  // input handling
  // ============================================================
  auto &keys = M5Cardputer.Keyboard;

  if (keys.isKeyPressed(KEY_ENTER)) {
    debounceDelay();
    runApp(toDraw[menu_current_opt].command);
    return;
  }
  if (keys.isKeyPressed('.')) {
    menu_current_opt = (menu_current_opt + 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
    return;
  }
  if (keys.isKeyPressed(';')) {
    menu_current_opt = (menu_current_opt + menu_len - 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
    return;
  }
  if (keys.isKeyPressed('`')) {
    debounceDelay();
    return;
  }
}

void logVictim(String login, String pass){
  loginCaptured = login;
  passCaptured = pass;
  return;
}

void drawWifiInfoScreen(String wifiName, String wifiMac, String wifiRRSI, String wifiChanel){
  debounceDelay();
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(2);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(wifiChoice, display_w/2, 25);
    canvas_main.setTextSize(1.5);
    canvas_main.drawString("Mac: " + wifiMac, display_w/2 , 50);
    canvas_main.drawString(wifiRRSI + " RRSI, Chanel: " + wifiChanel, display_w/2, 70);
    canvas_main.setTextSize(1);
    canvas_main.drawString("<To clone press C, ENTER to exit>", display_w/2, 100);
    pushAll();
    updateM5();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    ;
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

#endif

inline void pushAll(){
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


#ifndef LITE_VERSION

#include <vector>

void editWhitelist(){
  std::vector<String> whitelist = parseWhitelist();
  uint16_t writeID = whitelist.size();
  String list[] = {"Add element", "Remove element" , "Done", "Preview"};
  debounceDelay();
  while(true){
    initVars();
    logMessage("WRITE ID: " + String(writeID));
    std::vector<String> listToReturn = parseWhitelist();
    s8_t choice = drawMultiChoice("Whitelist editor", list, 4 , 0, 0);
    if (choice==0){
      String tempText = userInput("Add value:", "", 20);
      addToWhitelist(tempText);
      writeID++;
    }
    else if (choice==2 || choice == -1){
      drawInfoBox("Restarting...", "Restart is needed, ", "for changes to apply", false, false);
      delay(5000);
      ESP.restart();
    }
    else if (choice==1){
      // Convert vector to array for drawMultiChoice
      String tempArr[listToReturn.size()];
      for (size_t i = 0; i < listToReturn.size(); ++i) tempArr[i] = listToReturn[i];
      s16_t idOfItemToRemove = drawMultiChoice("Remove element", tempArr, writeID, 0, 0);
      if(idOfItemToRemove == -1){
        continue;
      }
      else
      {
        removeItemFromWhitelist(listToReturn[idOfItemToRemove]);
        if(writeID > 0){
          writeID = writeID - 1;
        }
        // Re-parse whitelist to update local array after deletion
        listToReturn = parseWhitelist();
      }
    }
    else if (choice==3){
      debounceDelay();
      while(true){
        // Exception handler: if list is empty, show info and break
        if (writeID == 0) {
          drawInfoBox("Info", "Whitelist is empty", "Nothing to preview.", true, false);
          break;
        }
        drawTopCanvas();
        drawBottomCanvas();
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}  
        for(auto i : status.word){
          if(i=='`'){
            break;
          }
        }
        M5.update();
        M5Cardputer.update();
        if(isOkPressed()){break;}
        // Convert vector to array for drawList
        String tempArr[listToReturn.size()];
        for (size_t i = 0; i < listToReturn.size(); ++i) tempArr[i] = listToReturn[i];
        drawList(tempArr, writeID);
        pushAll();
        drawMenu();
      }
    }
  }
}

String colorPickerUI(bool pickingText, String bg_color_toset) {
  int r = 0, g = 0, b = 0;
  int selected = 0; // 0=R, 1=G, 2=B
  bool done = false;
  String result = "";

  // Adjusted sizes for better fit
  int box_w = 40, box_h = 30;
  int box_y = canvas_h / 2 - box_h / 2 - 10;
  int box_x[3] = {canvas_center_x - box_w - 25, canvas_center_x, canvas_center_x + box_w + 25};

  int preview_w = 70, preview_h = 25;
  int preview_x = canvas_center_x;
  int preview_y = box_y + box_h + 20;

  while (!done) {
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(2);
    canvas_main.setTextDatum(middle_center);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.drawString("Select color", canvas_center_x, canvas_h / 6);

    // Draw color boxes
    for (int i = 0; i < 3; i++) {
      uint16_t border_color = (selected == i) ? tx_color_rgb565 : bg_color_rgb565;
      canvas_main.drawRect(box_x[i] - box_w/2, box_y, box_w, box_h, border_color);
      canvas_main.setTextSize(2);
      canvas_main.setTextColor(tx_color_rgb565);
      int val = (i == 0) ? r : (i == 1) ? g : b;
      canvas_main.drawString(String(val), box_x[i], box_y + box_h/2 - 8 + 10);
      canvas_main.setTextSize(1);
      String label = (i == 0) ? "red" : (i == 1) ? "green" : "blue";
      canvas_main.drawString(label, box_x[i], box_y + box_h + 10);
    }

    // Draw preview/confirm box
    uint16_t preview_color = RGBToRGB565(r, g, b);
    if(pickingText){
      canvas_main.drawRect(preview_x - preview_w/2, preview_y, preview_w, preview_h * 2/3, hexToRGB565(bg_color_toset));
      canvas_main.fillRect(preview_x - preview_w/2, preview_y, preview_w, preview_h * 2/3, hexToRGB565(bg_color_toset));
    }
    else{
      canvas_main.drawRect(preview_x - preview_w/2, preview_y, preview_w, preview_h * 2/3, preview_color);
      canvas_main.fillRect(preview_x - preview_w/2, preview_y, preview_w, preview_h * 2/3, preview_color);
    }
    
    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    if(pickingText) canvas_main.setTextColor(preview_color);
    canvas_main.drawString("Confirm", preview_x, preview_y + preview_h/2 - 6);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.drawString("Up/Down: value Left/Right: color OK set", preview_x, preview_y + preview_h/2 + 12);

    pushAll();

    // Handle input
    M5.update();
    M5Cardputer.update();
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}  

    for (auto k : status.word) {
      if (k == '/') { // right
        selected = (selected + 1) % 3;
      }
      if (k == ',') { // left
        selected = (selected + 2) % 3;
      }
      if (k == ';') { // up
        if (selected == 0 && r < 255) r++;
        if (selected == 1 && g < 255) g++;
        if (selected == 2 && b < 255) b++;
      }
      if (k == '.') { // down
        if (selected == 0 && r > 0) r--;
        if (selected == 1 && g > 0) g--;
        if (selected == 2 && b > 0) b--;
      }
    }
    // Exit if fn+` pressed
    if (status.fn) {
      for (auto k : status.word) {
        if (k == '`') {
          return "exited";
        }
      }
    }
    if (status.enter) {
      char hexStr[9];
      sprintf(hexStr, "#%02X%02X%02XFF", r, g, b);
      result = String(hexStr);
      done = true;
      break;
    }
    delay(80);
  }
  return result;
}

int brightnessPicker(){
  brightness = M5.Display.getBrightness();
  uint8_t rect_x = 10;
  uint8_t rect_y = (canvas_h / 4) + 30; 
  uint8_t rect_w = (canvas_center_x*2) - 20; 
  uint8_t rect_h = 30;
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillScreen(bg_color_rgb565);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString("Brightness:", canvas_center_x, canvas_h / 4);
    canvas_main.drawRect(rect_x, rect_y, rect_w , rect_h);
    float fillProcent = float(M5.Display.getBrightness()) / float(255);
    logMessage(String(fillProcent) + "% brightess detected, current brightness: "+ String(M5.Display.getBrightness()));
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.fillRect(rect_x, rect_y, rect_w*fillProcent, rect_h);
    canvas_main.setColor(bg_color_rgb565);
    pushAll();
    M5.update();
    M5Cardputer.update();
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}  

    for (auto k : status.word) {
      if (k == '/' || k == ';') { // right
        if(brightness == 255){
          brightness--;
        }
        brightness++;
      }
      if (k == ',' || k == '.') { // left
        if(brightness == 1){
          brightness++;
        }
        brightness--;
      }
    }
    if (status.fn) {
      for (auto k : status.word) {
        if (k == '`' ) {
          debounceDelay();
          return brightness;
        }
      }
    }
    if (status.enter) {
      debounceDelay();
      return brightness;
    }
    M5.Display.setBrightness(brightness);
  }
}

#endif

void debounceDelay(){
  while(M5Cardputer.Keyboard.isPressed() != 0){
    M5.update();
    M5Cardputer.update();
    delay(10);
  }
  M5Cardputer.update();
  M5.update();
  delay(40);
  M5Cardputer.update();
  M5.update();
}

#ifdef ENABLE_COREDUMP_LOGGING
#include "esp_core_dump.h"
#include "esp_system.h"

void sendCrashReport(){
  //inform user of state
  drawInfoBox("Error", "A critical error has", "occurred, sending report...", false, false);
  //first try to find saved wifi
  uint8_t wifiCount = WiFi.scanNetworks();
  for(uint8_t i = 0; i < wifiCount; i++){
    String ssid = WiFi.SSID(i);
    if(ssid == savedApSSID){
      WiFi.begin(savedApSSID.c_str(), savedAPPass.c_str());
      uint8_t connectTry = 0;
      while(WiFi.status() != WL_CONNECTED && connectTry < 10){
        delay(1000);
        connectTry++;
      }
      break;
    }
  }
  if(WiFi.status() == WL_CONNECTED){
  }
  else{
    bool answwer = drawQuestionBox("Error", "Saved wifi not found", "Set up new one?", "Press Y for yes, N for no");
    if(answwer){
      runApp(43); //wifi setup app
      if(WiFi.status() == WL_CONNECTED){
        logMessage("Wifi connected, sending report...");
      }
      else{
        drawInfoBox("Error", "Cannot send report", "No wifi connected", true, false);
        bool test1 = drawQuestionBox("Question", "Do you want to delete", "all report logs?", "Y for yes, N for no");
        if(test1){
          esp_core_dump_image_erase();
          drawInfoBox("Logs deleted", "All coredump logs", "have been deleted", true, false);
        }
        return;
      }
    }
    else{
      drawInfoBox("Error", "Cannot send report", "No wifi connected", true, false);
      return;
    }
  }
  connectMQTT();
  sendCoredump();
  drawInfoBox("Report sent", "Thank you for helping", "to improve this software!", true, false);
}
#endif
