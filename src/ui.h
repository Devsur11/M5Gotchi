#pragma once
#include "logger.h"
#include "M5GFX.h"

struct menu {
  const char *name;
  int command;
};

struct unit {
  String name;
  String fingerprint;
};

extern QueueHandle_t unitQueue;
extern uint16_t bg_color_rgb565;
extern uint16_t tx_color_rgb565;

// A tiny in-memory message struct
struct message {
  String fromOrTo;           // Name of peer that we're comunicating with
  String fingerprint;        // fingerprint of peer that is sending message
  uint32_t id;               // server message id (0 for outgoing or local)
  String text;               // decrypted message
  uint64_t ts;               // unix timestamp
  bool outgoing;             // true if sent by us
};

void stopPwngridInboxTask();
void unitWriterTask(void *pv);
void pwngridInboxTask(void *param);
String resolveChatFingerprint(const String &chatName, const std::vector<message> &history);
String multiplyChar(char toMultiply, uint8_t literations);
void trigger(uint8_t trigID);
void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical);
bool activityRewarded();
void initUi();
void redrawUi(bool show_toolbars = false);
void drawMood(String face, String phrase);
void drawTopCanvas();
void drawRightBar();
void drawBottomCanvas();
void drawMenu();
void updateUi(bool show_toolbars = false, bool triggerPwnagothi = true, bool overrideDelay = false);
void runApp(uint8_t appID = 0);
inline void resetSprite();
String userInput(const String &prompt, String desc, int maxLen,  const String &initial = "");
bool drawQuestionBox(String tittle, String info, String info2, String label = "  ");
int drawMultiChoice(String tittle, String toDraw[], uint8_t menuSize, uint8_t prevMenuID, uint8_t prevOpt);
uint8_t returnBrightness();
String* makeList(String windowName, uint8_t appid, bool addln, uint8_t maxEntryLen);
void drawList(String toDraw[], uint8_t manu_size);
void logVictim(String login, String pass);
inline void drawWifiInfoScreen(String wifiName, String wifiMac, String wifiRRSI, String wifiChanel);
void pushAll();
void updateM5();
void editWhitelist();
uint16_t RGBToRGB565(uint8_t r, uint8_t g, uint8_t b);
uint16_t hexToRGB565(String hex);
String colorPickerUI(bool pickingText, String bg_color_toset);
void coordsPickerUI();
void initColorSettings();
void drawMenuList(menu toDraw[], uint8_t menuIDPriv, uint8_t menu_size);
int brightnessPicker();
int16_t getNumberfromUser(String tittle, String desc, uint16_t maxNumber);
bool getBoolInput(String tittle, String desc, bool defaultValue);
int drawMultiChoiceLonger(String tittle, String toDraw[], uint8_t menuSize , uint8_t prevMenuID, uint8_t prevOpt);
void IRAM_ATTR handleInterrupt();
void debounceDelay();
void esp_will_beg_for_its_life();
void pwngridMessenger();
bool registerNewMessage(message newMess);
std::vector<message> loadMessageHistory(const String &unitName);
void renderMessages(M5Canvas &canvas, const std::vector<message> &messages, int scrollOffset);
String findIncomingFingerprint(const std::vector<message> &messages);
void drawHintBox(const String &text, uint8_t hintID);
void drawStats();
void drawSysInfo();
bool addUnitToAddressBook(const unit u);

#ifdef ENABLE_COREDUMP_LOGGING
void sendCrashReport();
#endif