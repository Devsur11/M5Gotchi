#include "M5Cardputer.h"
#include "mood.h"

struct menu {
  char name[25];
  int command;
};

void initUi();
void wakeUp();
void drawMood(String face, String phrase, bool broken = false);
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