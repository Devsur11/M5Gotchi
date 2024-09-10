#include "M5Cardputer.h"
#include "mood.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>

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

String multiplyChar(char toMultiply, uint8_t literations);
void trigger(uint8_t trigID);
void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical);
bool activityRewarded();
void initUi();
void wakeUp();
void drawMood(String face, String phrase,  bool broken = false);
void drawTopCanvas();
void drawRightBar();
void drawBottomCanvas(uint8_t friends_run = 0, uint8_t friends_tot = 0,
                      String last_friend_name = "", signed int rssi = -1000);
void drawMenu();
void updateUi(bool show_toolbars = false);
void runApp(uint8_t appID = 0);
void drawSinglePage(menu toDraw[], uint8_t menuIDPriv, uint8_t uiSize);
void drawMultiplePages(menu toDraw[], uint8_t menuIDPriv, uint8_t menuSize);
void drawMainMenu();
inline void resetSprite();
String userInput(String tittle, String desc, uint8_t maxLenght);
bool drawQuestionBox(String tittle, String info, String info2);
int drawMultiChoice(String toDraw[], uint8_t menuSize );