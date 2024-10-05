#include "M5Cardputer.h"
#include "mood.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>
#include "evilPortal.h"
//#include "wifiBeacon.h"
#include "networkKit.h"

struct menu {
  char name[25];
  int command;
};


String multiplyChar(char toMultiply, uint8_t literations);
void trigger(uint8_t trigID);
void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical);
bool activityRewarded();
void initUi();
void wakeUp();
void drawMood(String face, String phrase);
void drawTopCanvas();
void drawRightBar();
void drawBottomCanvas();
void drawMenu();
void updateUi(bool show_toolbars = false);
void runApp(uint8_t appID = 0);
void drawSinglePage(menu toDraw[], uint8_t menuIDPriv, uint8_t uiSize);
void drawMultiplePages(menu toDraw[], uint8_t menuIDPriv, uint8_t menuSize);
void drawMainMenu();
inline void resetSprite();
String userInput(String tittle, String desc, uint8_t maxLenght);
bool drawQuestionBox(String tittle, String info, String info2, String label = "To confirm press y, to abort press n");
int drawMultiChoice(String tittle, String toDraw[], uint8_t menuSize, uint8_t prevMenuID, uint8_t prevOpt);
uint8_t returnBrightness();
String* makeList(String windowName, uint8_t appid, bool addln, uint8_t maxEntryLen);
void drawList(String toDraw[], uint8_t manu_size);
void logVictim(String login, String pass);
void drawWifiInfoScreen(String wifiName, String wifiMac, String wifiRRSI);
inline void pushAll();
inline void updateM5();