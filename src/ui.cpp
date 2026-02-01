#include "settings.h"
#ifndef BUTTON_ONLY_INPUT
#include "M5Cardputer.h"
#endif
#include "lgfx/v1/misc/enum.hpp"
#include "lgfx/v1/misc/DataWrapper.hpp"
#include "HWCDC.h"
#include "Arduino.h"
#include <ArduinoJson.h>
#include "ui.h"
#include <FS.h>
#include "SD.h"
#include <WiFi.h>
#include "pwnagothi.h"
#include "EapolSniffer.h"
#include "PMKIDGrabber.h"
#include "mood.h"
#include "updater.h"
#include <Update.h>
#include <FS.h>
#include "evilPortal.h"
#include "networkKit.h"
#include "src.h"
#include "logger.h"
#include "moodLoader.h"
#include "wpa_sec.h"
#include "pwngrid.h"
#include "api_client.h"
#include "sdmanager.h"
#include "textsEditor.h"
#include <vector>
#include "wardrive.h"
#include <FS.h>
#include "storageManager.h"
#include "storageAbstraction.h"
#include "usbMassStorage.h"

M5Canvas canvas_top(&M5.Display);
M5Canvas canvas_main(&M5.Display);
M5Canvas canvas_bot(&M5.Display);
M5Canvas bar_right(&M5.Display);
M5Canvas bar_right2(&M5.Display);
M5Canvas bar_right3(&M5.Display);
M5Canvas bar_right4(&M5.Display);

// Mutex that protects all display and canvas operations (loadFont, draw, pushSprite)
SemaphoreHandle_t displayMutex = NULL;


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


// menuID 1
menu main_menu[] = {
    {"Manual Control", 1},        // Manual mode
    {"Auto Mode", 4},             // Auto mode
    {"WPA-SEC", 55},              // WPA-SEC companion
    {"Pwngrid", 7},               // Pwngrid companion
    {"Wardriving", 8},            // Wardriving companion
    {"Files", 70},                // File manager
    {"Statistics", 5},            // Stats
    {"Settings", 6},               // Config
    {"Web file manager", 73},         // Web file manager
    {"Back", 255}
};

// menuID 2
menu wifi_menu[] = {
    {"Networks selector", 20},    // Select Networks
    {"Clone / Details", 21},      // Clone & Details
    {"PMKID Capture", 61},        // PMKID Grabber
    {"Access Point", 22},         // Acces point
    {"Deauthentication", 23},     // Deauth
    {"Packet Sniffing", 24},       // Sniffing
    {"Back", 255}
};

// menuID 7
menu wpasec_menu[] = {
  {"Sync Server", 52},           // Sync with server
  {"Cracked Results", 53},      // Check cracked results
  {"API Key change", 54},       // Change API key
  {"Back", 255}
};

menu wpasec_setup_menu[] = {
  {"Set API Key", 54},            // Setup WPA-SEC API key
  {"Back", 255}
};

// menuID 5
menu pwngotchi_menu[] = {
  {"Enable Auto Mode", 36},      // Switch to auto mode
  {"Auto + Wardriving", 14},     // Auto mode + wardriving
  {"Whitelist", 38},             // Whitelist editor
  {"Handshakes", 39},            // Handshakes file list
  {"Personality", 57},           // Personality editor
  {"Back", 255}
};

// menuID 6
menu settings_menu[] = {
  // Startup / Boot behavior
  {"Auto Mode on Boot", 48},             // M5Gotchi auto mode on boot
  {"Auto-Connect WiFi", 29},             // On startup, connect to wifi
  {"Check Updates on Boot", 33},         // At boot, check for updates
  {"Random MAC on Boot", 34},            // Randomise mac at startup
  {"Check inbox at boot", 9},

  // Network / WiFi
  {"WiFi Connect", 43},                   // Connect to WiFi
  {"Saved Networks", 32},                 // Manage saved networks
  {"GPS Pins", 30},                       // GPS GPIO pins
  {"GPS Baud Rate", 37},                  // GPS Baud Rate
  {"GPS Logging", 31},                    // Log GPS data after handshake
  {"Pwngrid Broadcast", 60},              // Advertise Pwngrid presence

  // Interface / Display
  {"Theme", 50},                          // UI Theme
  {"Brightness", 41},                     // Display brightness
  {"Key Sounds", 42},                     // Keyboard Sound
  {"Text Faces", 90},                     // Edit text faces

  // User / Device
  {"Device Name", 40},                    // Change Hostname/name
  {"GO Button Action", 59},               // GO button press function
  {"Auto-Add Friends", 35},               // Add all met pwnagotchis to friends

  // Logging / Storage
  {"SD Logging", 58},                     // Log to SD
  #ifdef USE_LITTLEFS
  {"LittleFS Manager", 71},               // LittleFS manager
  {"Web file manager", 73},                 // Enable USB drive mode
  #endif
  {"Storage Info", 72},

  // System / Maintenance
  {"System Update", 44},                  // Update system
  {"Factory Reset", 51},                  // Factory reset
  {"System Info", 3},                     // System info
  {"About", 45},                          // About M5Gotchi
  {"Power Off", 46},                      // Power off system
  {"Reboot", 56},                         // Reboot system

  // Optional / advanced
  {"Skip EAPOL Check", 49},                // Skip EAPOL integrity check
  {"Send bug report to dev", 123},
  {"Back", 255}                           // Back to main menu
};


menu gps_pins_menu[] = {
  {"Default Pins", 30},                   // Use default pins
  {"Custom Pins", 31},                     // Set custom pins
  {"Back", 255}
};

// menuID 8
menu pwngrid_menu[] = {
  {"Units Met", 16},                      // Units met
  {"Inbox", 10},                          // Messages inbox
  {"Quick Message", 11},                  // Quick message
  {"Friends", 17},                        // Frends list
  {"Nothing to Send", 0},                 // No new captured networks to send
  {"Identity", 13},                       // View identity/fingerprint
  {"Reset Identity", 15},                 // Reset pwngrid/fingerprint
  {"Back", 255}
};

menu pwngrid_menu_to_send[] = {
  {"Units Met", 16},                      // Units met
  {"Inbox", 10},                          // Messages inbox
  {"Quick Message", 11},                  // Quick message
  {"Friends", 17},                        // Frends list
  {"Send pwn data", 26},                  // No new captured networks to send
  {"Identity", 13},                       // View identity/fingerprint
  {"Reset Identity", 15},                 // Reset pwngrid/fingerprint
  {"Back", 255}
};

menu pwngrid_not_enrolled_menu[] = {
  {"Enroll Device", 12},                    // Enroll with Pwngrid
  {"Back", 255}
};

// devtools menu
menu devtools_menu[] = {
  {"Dev Mode", 100},                       // Toggle dev mode
  {"Set Variable", 101},                   // Set global var
  {"Set Variable (Raw)", 108},             // Set global var (freeform)
  {"Run App by ID", 102},                  // Run app by ID
  {"BG Color Picker", 103},                // Color picker (BG)
  {"Text Color Picker", 104},              // Color picker (TX)
  {"Coords Overlay", 105},                 // Toggle coords overlay
  {"Serial Overlay", 106},                 // Toggle serial overlay
  {"Skip File Checks", 107},               // Skip file checks in dev
  {"Scan Speed Test", 109},                // Speed scan test
  {"Coordinate Picker", 110},              // Coordinate picker
  {"Mood Font Tester", 112},               // Test all text faces with font
  {"Crash Test", 111},                      // Crash test
  {"Back", 255}
};

menu devtools_locked_menu[] = {
  {"Unlock Dev Mode", 100},                // Unlock dev mode
  {"Back", 255}
};

// menuID 9 
menu wardrivingMenuWithWiggle[] = {
  {"Start Wardriving", 18},                // Wardriving mode
  {"View Logs", 19},                       // View logs
  {"Upload to Wiggle", 28},                // Upload to Wiggle.net
  {"Reset Wiggle Config", 27},              // Reset Wiggle.net config
  {"Back", 255}
};

menu wardrivingMenuWithWiggleUnsett[] = {
  {"Start Wardriving", 18},                // Wardriving mode
  {"View Logs", 19},                       // View logs
  {"Set Wiggle API Key", 25},               // Set up Wiggle.net api key
  {"Back", 255}
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
QueueHandle_t unitQueue;
uint8_t prevMID;
volatile bool inboxDirty = false;
volatile bool refresherRunning = false;
TaskHandle_t pwngridInboxTaskHandle = nullptr;
volatile bool killInboxTask = false;
bool crackedList;

void pwngridInboxTask(void *param) {
  while (!killInboxTask) {
    if (WiFi.status() == WL_CONNECTED) {
      api_client::pollInbox();
      inboxDirty = true;
    }
    vTaskDelay(pdMS_TO_TICKS(5000));
  }

  // clean exit
  pwngridInboxTaskHandle = nullptr;
  vTaskDelete(nullptr);
}


void stopPwngridInboxTask() {
  if (pwngridInboxTaskHandle != nullptr) {
    killInboxTask = true;

    // give it a moment to exit cleanly
    vTaskDelay(pdMS_TO_TICKS(50));

    // if it’s still alive, execute it
    if (pwngridInboxTaskHandle != nullptr) {
      vTaskDelete(pwngridInboxTaskHandle);
      pwngridInboxTaskHandle = nullptr;
    }
  }
}

void unitWriterTask(void *pv) {
  unit_msg_t msg;

  for (;;) {
    if (xQueueReceive(unitQueue, &msg, portMAX_DELAY)) {
      unit u;
      u.name = msg.name;
      u.fingerprint = msg.fingerprint;

      addUnitToAddressBook(u);
    }
  }
}

void esp_will_beg_for_its_life() {
  int *ptr = nullptr;
  *ptr = 42; // hehehe
}

bool pwnagotchiModeFromButton = false;
bool buttonDirty = false;

void buttonTask(void *param) {
  bool dimmed = false;
  for (;;) {
    if (xSemaphoreTake(buttonSemaphore, portMAX_DELAY) == pdTRUE && !buttonDirty) {
      if(!toogle_pwnagothi_with_gpio0)
      {dimmed = !dimmed;
      if (dimmed) {
        M5.Display.setBrightness(0);  // example dim value
      } else {
        M5.Display.setBrightness(brightness);
      }}
      else{
        buttonDirty = true;
        if(!pwnagotchiModeFromButton){
          pwnagotchiModeFromButton = true;
          logMessage("Pwnagotchi mode activated");
        }
        else{
          //lets draw a little message here too
          if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
          M5.Display.fillRect(0, (display_h/2) - 20 , 250, 20, bg_color_rgb565);
          M5.Display.setTextDatum(middle_center);
          M5.Display.setTextColor(tx_color_rgb565);
          M5.Display.setTextSize(2);
          M5.Display.drawString("Deactivating...", canvas_center_x , (display_h/2) - 10);
          M5.Display.pushState();
          if (displayMutex) xSemaphoreGive(displayMutex);
          pwnagotchiModeFromButton = false;
          logMessage("Pwnagotchi mode deactivated");
        }
      }
    }
  }
}

volatile unsigned long lastInterruptTime = 0;

void IRAM_ATTR handleInterrupt() {
  unsigned long now = millis();
  if (now - lastInterruptTime > 1000) {  // 1s debounce
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
  unitQueue = xQueueCreate(8, sizeof(unit_msg_t));
  xTaskCreatePinnedToCore(
    unitWriterTask,
    "unitWriter",
    4096,
    NULL,
    2,
    NULL,
    0
  );
  buttonSemaphore = xSemaphoreCreateBinary();
  // Create display mutex
  displayMutex = xSemaphoreCreateMutex();
  if (displayMutex == NULL) {
    logMessage("Failed to create display mutex");
  }
  attachInterrupt(digitalPinToInterrupt(0), handleInterrupt, FALLING);
  xTaskCreate(buttonTask, "ButtonTask", 4096, NULL, 1, NULL);
  crackedList = FSYS.exists("/pwngrid/cracks.conf");
  M5.Display.setRotation(1);
  M5.Display.setTextSize(1);
  M5.Display.fillScreen(bg_color_rgb565);
  M5.Display.setTextColor(tx_color_rgb565);

  display_w = M5.Display.width();
  display_h = M5.Display.height();
  logMessage("Display width: " + String(display_w) + ", height: " + String(display_h));
  canvas_h = display_h * .8;
  canvas_center_x = display_w / 2;
  canvas_top_h = display_h * .1;
  canvas_bot_h = display_h * .1;

  canvas_top.createSprite(display_w, canvas_top_h);
  canvas_bot.createSprite(display_w, canvas_bot_h);
  canvas_main.createSprite(display_w, canvas_h);
  logMessage("UI initialized");
  // enable logger overlay if configured
  loggerSetOverlayEnabled(serial_overlay);
}

uint8_t returnBrightness(){return currentBrightness;}

#ifdef BUTTON_ONLY_INPUT
#include "inputManager.h"

bool toggleMenuBtnPressed() {
  return inputManager::isButtonBLongPressed(); // Long press Button B for menu
}

bool isOkPressed() {
  return inputManager::isButtonAPressed(); // Button A is OK/Select
}

bool isNextPressed() {
  return inputManager::isButtonBPressed(); // Button B is Next/Down navigation
}

bool isPrevPressed() {
  return false; // Single button for navigation, no prev
}
#else

bool toggleMenuBtnPressed() {
  return (M5Cardputer.Keyboard.isKeyPressed('`'));
}

bool isOkPressed() {
  return (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER));
}

bool isNextPressed() {
  return M5Cardputer.Keyboard.isKeyPressed('.');
}
bool isPrevPressed() {
  return M5Cardputer.Keyboard.isKeyPressed(';');
}

#endif

bool needsUiRedraw = true;
static unsigned long lastRedrawTime = 0;
bool crackedFileExist;
File toUpload;

void updateUi(bool show_toolbars, bool triggerPwnagothi, bool overrideDelay) {
  //handle button changing pwnagotchi state:
  if(triggerPwnagothi && buttonDirty){
    if(pwnagotchiModeFromButton && !pwnagothiMode){
      runApp(36); //enable auto mode
      menuID = 0;
      prevMID = 1;  //just to redraw the prompt
      needsUiRedraw = true;
      if(pwnagothiMode){
        pwnagotchiModeFromButton = true;
      }
      else{
        pwnagotchiModeFromButton = false;
      }
    }
    else{
      pwnagotchiModeFromButton = false;
      pwnagothiMode = false;
      needsUiRedraw = true;
      setMoodToStatus();
      prevMID = 1;  //just to redraw the prompt
    }
    buttonDirty = false;
  }

#ifndef BUTTON_ONLY_INPUT
  keyboard_changed = M5Cardputer.Keyboard.isChange();
  M5Cardputer.update();
  if(keyboard_changed){Sound(10000, 100, sound);}
#endif       
  if (toggleMenuBtnPressed()) {
    debounceDelay();
    if(pwnagothiMode){
      return;
    }
    if (menuID==1) {
      menu_current_opt = 0;
      menu_current_page = 1;
      menuID = 0;
      needsUiRedraw = true;
    } else {
      menuID = 1;
      menu_current_opt = 0;
      menu_current_page = 1;
    }
  }
  if(overrideDelay){
    redrawUi(show_toolbars);
  }
  if(show_toolbars)
  {  drawTopCanvas();
    drawBottomCanvas();
  }
  
  if (menuID == 1) {
    drawMenuList(main_menu, 1, 10);
    prevMID = 1;
  } 
  else if (menuID == 2){
    drawMenuList( wifi_menu , 2, 7);
    prevMID = 2;
  }
  else if (menuID == 5){
    drawMenuList( pwngotchi_menu , 5, 6);
    prevMID = 5;
  }
  else if (menuID == 6){
    //lets modify each setting based on current value
    // lets modify each setting based on current value
    char val_1[50];   // Auto Mode on Boot
    char val_2[55];   // Auto-Connect WiFi
    char val_3[55];   // Check Updates on Boot
    char val_4[55];   // Random MAC on Boot
    char val_4_5[55]; // check_inbox_at_startup
    char val_5[45];   // WiFi Connect
    char val_6[70];   // GPS Pins
    char val_6_5[70]; // GPS Baud Rate
    char val_7[70];   // GPS Logging
    char val_8[42];   // Key Sounds
    char val_9[50];   // Pwngrid Broadcast
    char val_10[75];  // Auto-Add Friends
    char val_11[50];  // SD Logging
    char val_12[45];  // Skip EAPOL Check
    char val_13[50];  // Sync Pwnd on Boot

    snprintf(val_1, sizeof(val_1),
            "Auto Mode on Boot: %s",
            pwnagothiModeEnabled ? "ON" : "OFF");

    snprintf(val_2, sizeof(val_2),
            "Auto-Connect WiFi: %s",
            connectWiFiOnStartup ? "ON" : "OFF");

    snprintf(val_3, sizeof(val_3),
            "Check Updates on Boot: %s",
            checkUpdatesAtNetworkStart ? "ON" : "OFF");

    snprintf(val_4, sizeof(val_4),
            "Random MAC on Boot: %s",
            randomise_mac_at_boot ? "ON" : "OFF");

    snprintf(val_4_5, sizeof(val_4_5),
             "Check inbox at boot %s",
             check_inbox_at_startup? "ON" : "OFF");

    snprintf(val_5, sizeof(val_5),
            "WiFi %s",
            (WiFi.status() == WL_CONNECTED) ? "disconnect" : "connect");

    snprintf(val_6, sizeof(val_6),
            "GPS Pins: %s",
            !useCustomGPSPins ? "Default" : "Custom");

    snprintf(val_6_5, sizeof(val_6_5),
            "GPS Baud: %lu",
            gpsBaudRate);

    snprintf(val_7, sizeof(val_7),
            "GPS Logging: %s",
            getLocationAfterPwn ? "ON" : "OFF");

    snprintf(val_8, sizeof(val_8),
            "Key Sounds: %s",
            sound ? "ON" : "OFF");

    snprintf(val_9, sizeof(val_9),
            "Pwngrid Broadcast: %s",
            advertisePwngrid ? "ON" : "OFF");

    snprintf(val_10, sizeof(val_10),
            "Auto-Add Friends: %s",
            add_new_units_to_friends ? "ON" : "OFF");

    snprintf(val_11, sizeof(val_11),
            "SD Logging: %s",
            sd_logging ? "ON" : "OFF");

    snprintf(val_12, sizeof(val_12),
            "Skip EAPOL Check: %s",
            skip_eapol_check ? "ON" : "OFF");

    snprintf(val_13, sizeof(val_13),
            "Sync pwned on Boot: %s",
            sync_pwned_on_boot ? "ON" : "OFF");

    menu new_settings_menu[] = {
        // Startup / Boot behavior
        { val_1, 48 },   // Auto Mode on Boot
        { val_2, 29 },   // Auto-Connect WiFi
        { val_3, 33 },   // Check Updates on Boot
        { val_4, 34 },   // Random MAC on Boot
        { val_4_5, 9 },  //check_inbox_at_startup

        // Network / WiFi
        { val_5, 43 },   // WiFi Connect
        { "Saved Networks", 32 },  // Manage saved networks
        { val_6, 30 },   // GPS Pins
        { val_6_5, 37 }, // GPS Baud Rate
        { val_7, 31 },   // GPS Logging
        { val_9, 60 },   // Pwngrid Broadcast
        { val_13, 122 }, // Sync pwned on boot

        // Interface / Display
        { "Theme", 50 },       // UI Theme
        { "Brightness", 41 },  // Display brightness
        { "Sounds" , 42 },         // Key Sounds
        { "Text Faces", 90 },  // Edit text faces

        // User / Device
        { "Device Name", 40 }, // Change Hostname/name
        { "GO Button Action", 59 }, // GO button press function
        { val_10, 35 },        // Auto-Add Friends

        // Logging / Storage
        { val_11, 58 },        // SD Logging
        #ifdef USE_LITTLEFS
        {"LittleFS Manager", 71},               // LittleFS manager
        {"Web file manager", 73},                 // Enable USB drive mode
        #endif
        {"Storage Info", 72},

        // System / Maintenance
        { "System Update", 44 },
        { "Factory Reset", 51 },
        { "System Info", 3 },
        { "About", 45 },
        { "Power Off", 46 },
        { "Reboot", 56 },

        // Optional / Advanced
        { val_12, 49 },         // Skip EAPOL Check
        { "Send bug report to devs", 123 }, // Send bug report
        { "Back", 255 }
    };
    #ifdef USE_LITTLEFS
    drawMenuList( new_settings_menu , 6, 31);
    #else
    drawMenuList( new_settings_menu , 6, 29);
    #endif
    prevMID = 6;
  }  
  else if (menuID == 7){
    (wpa_sec_api_key.length()>5)?drawMenuList(wpasec_menu, 7, 4):drawMenuList(wpasec_setup_menu, 7, 2);
    prevMID = 7;
  }
  else if (menuID == 8){
    if(!(prevMID == 8)){toUpload = FSYS.open("/pwngrid/cracks.conf");}
    if((toUpload && toUpload.size() > 5) && (pwngrid_indentity.length()>10)){ 
      drawMenuList(pwngrid_menu_to_send, 8, 8);
    }
    else (pwngrid_indentity.length()>10)? drawMenuList(pwngrid_menu, 8, 8): drawMenuList(pwngrid_not_enrolled_menu, 8, 2);
    prevMID = 8;
  }
  else if (menuID == 9){
    if(wiggle_api_key.length() > 5){
      drawMenuList(wardrivingMenuWithWiggle, 9, 5);
    }
    else{
      drawMenuList(wardrivingMenuWithWiggleUnsett, 9, 4);
    }
    prevMID = 9;
  }
  else if (menuID == 99) {
    if(dev_mode){
      drawMenuList(devtools_menu, 99, 13);
    }
    else{
      drawMenuList(devtools_locked_menu, 99, 2);
    }
    prevMID = 99;
  }
  else if (menuID == 0)
  {
    //redraw only in 5 seconds intervals
    unsigned long currentTime = millis();
    if ((currentTime - lastRedrawTime >= 10000 )|| needsUiRedraw || pwnagothiMode) {
      if(prevMID){
        drawInfoBox("", "Refreshing data...", "", false, false);
        prevMID=0;
      }
      redrawUi(show_toolbars);
      lastRedrawTime = currentTime;
      needsUiRedraw = false;
    }
  }
  

  M5.Display.startWrite();
  if (show_toolbars) {
    canvas_top.pushSprite(0, 0);
    canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
  }
  else{
    M5.Display.fillRect(0, 0, display_w, canvas_top_h, bg_color_rgb565);
    M5.Display.fillRect(0, display_h - canvas_bot_h-4, display_w, canvas_bot_h + 10, bg_color_rgb565);
  }
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
  if(pwnagothiMode && triggerPwnagothi){
    if(!stealth_mode){
      pwnagothiLoop();
    }
    else{
      pwnagothiStealthLoop();
    }
  }
}

void setToMainMenu(){
  menuID = 0;
  menu_current_opt = 0;
  menu_current_page = 1;
}

void redrawUi(bool show_toolbars) {
  // draw developer overlays on canvas_main before pushing to display
  // NOTE: removed recursive call to updateUi to avoid stack overflow (updateUi -> redrawUi -> updateUi ...)
  if (coords_overlay) {
    // approximate coordinates of selected menu item
    if (menuID != 0) {
      int lineH = 18;
      int x = 18; // where entries are drawn
      int y = menu_current_opt * lineH + 2;
      // draw crosshair and text
      canvas_main.setTextSize(1);
      canvas_main.setTextColor(tx_color_rgb565);
      canvas_main.drawLine(x - 4, y, x + 20, y, tx_color_rgb565);
      canvas_main.drawLine(x, y - 4, x, y + 12, tx_color_rgb565);
      canvas_main.drawString("X:" + String(x) + " Y:" + String(y), x + 24, y);
    }
  }

  
  if(serial_overlay){
    loggerTask();
    delay(100);
  } 
  String mood_face = getCurrentMoodFace();
  String mood_phrase = getCurrentMoodPhrase();
  drawMood(mood_face, mood_phrase);
}

void drawTopCanvas() {
  if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
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
  // Developer mode indicator
  extern bool dev_mode;
  extern bool serial_overlay;
  extern bool coords_overlay;
  if (dev_mode) {
    canvas_top.setTextDatum(top_left);
    canvas_top.setTextSize(1);
    canvas_top.setTextColor(tx_color_rgb565);
    canvas_top.drawString("DEV", 3, 3);
  }
  if (serial_overlay) {
    canvas_top.setTextDatum(top_left);
    canvas_top.drawString("LOGS", 40, 3);
  }
  if (coords_overlay) {
    canvas_top.setTextDatum(top_left);
    canvas_top.drawString("XY", 80, 3);
  }
  canvas_top.drawLine(0, canvas_top_h - 1, display_w, canvas_top_h - 1);
  if (displayMutex) xSemaphoreGive(displayMutex);
}


void drawBottomCanvas() {
  if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
  canvas_bot.fillSprite(bg_color_rgb565);
  canvas_bot.setTextSize(1);
  canvas_bot.setTextColor(tx_color_rgb565);
  canvas_bot.setColor(tx_color_rgb565);
  canvas_bot.setTextDatum(top_left);
  uint16_t captures = sessionCaptures;
  uint16_t allTimeCaptures = pwned_ap;
  String shortWifiName = lastPwnedAP.length() > 12 ? lastPwnedAP.substring(0, 12) + "..." : lastPwnedAP;
  canvas_bot.drawString("PWND: " + String(captures) + "/" + String(allTimeCaptures) + (shortWifiName.length() > 0 ? " (" + shortWifiName + ")" : ""), 3, 5);
  String wifiStatus;
  if(WiFi.status() == WL_NO_SHIELD){
    wifiStatus = "O";
    if(apMode){canvas_bot.drawString("Wifi: AP  " + wifiChoice, 0, 5);}  
  }
  else if(WiFi.status() == WL_CONNECTED){
    wifiStatus = "C";
  }
  else if(WiFi.status() ==  WL_IDLE_STATUS){
    wifiStatus = "I";
  }
  else if(WiFi.status() == WL_CONNECT_FAILED){
    wifiStatus = "E";
  }
  else if(WiFi.status() ==  WL_CONNECTION_LOST){
    wifiStatus = "L";
  }
  else if(WiFi.status() ==  WL_DISCONNECTED){
    wifiStatus = "D";
  }
  else{
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    WiFi.mode(WIFI_MODE_NULL);
    xSemaphoreGive(wifiMutex);
    wifion();
  }
  canvas_bot.setTextDatum(top_right);
  canvas_bot.drawString(String((pwnagothiMode) ? "AUTO" : "MANU") + " " + wifiStatus, display_w, 5);
  canvas_bot.drawLine(0, 0, display_w, 0);
  if (displayMutex) xSemaphoreGive(displayMutex);
}

void drawMood(String face, String phrase) {
    if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
    uint16_t bg = bg_color_rgb565;
    uint16_t fg = tx_color_rgb565;
    
    // 1. Setup Canvas Defaults
    canvas_main.fillSprite(bg);
    canvas_main.setTextColor(fg, bg);
    canvas_main.setColor(fg);
    canvas_main.setTextSize(1); // Reset size to 1.0 initially
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(3, 5);

    // --- XP Calculation Logic (Unchanged) ---
    constexpr float XP_SCALE = 5.0f;
    constexpr float XP_EXPONENT = 0.75f;
    uint16_t level = (uint16_t)floor(pow(pwned_ap / XP_SCALE, XP_EXPONENT));
    float prev_level_xp = XP_SCALE * pow(level, 1.0f / XP_EXPONENT);
    float next_level_xp = XP_SCALE * pow(level + 1, 1.0f / XP_EXPONENT);
    float to_next_level = next_level_xp - pwned_ap;

    // --- Draw Header ---
    // Use default font (glcd) for header to ensure stability
    canvas_main.setFont(&fonts::Font0); // Explicitly set default font
    canvas_main.setTextSize(1.5);
    
    String lvlText = hostname + ">  Lvl " + String(level);
    int textW = canvas_main.textWidth(lvlText);
    canvas_main.println(lvlText);

    // --- Progress Bar (Unchanged) ---
    int barWidth = 240 - textW - 10;
    float progress = pwned_ap - prev_level_xp;
    float level_span = next_level_xp - prev_level_xp;
    progress = constrain(progress, 0, level_span);
    int filledWidth = (int)((progress / level_span) * barWidth);

    int barX = textW + 10;
    canvas_main.drawRect(barX, 5, barWidth, 10, tx_color_rgb565);
    canvas_main.fillRect(barX, 5, filledWidth, 10, tx_color_rgb565);

    // --- Level Up Sound (Unchanged) ---
    if(prev_level != level){
      prev_level = level;
      Sound(784, 80, pwnagotchi.sound_on_events);   
      delay(80);
      Sound(988, 80, pwnagotchi.sound_on_events);   
      delay(80);
      Sound(1319, 80, pwnagotchi.sound_on_events);  
      delay(80);
      Sound(1568, 200, pwnagotchi.sound_on_events); 
      delay(200);
      saveSettings();
      phrase = "Level up! I am now level " + String(level) + "!";
    }

    // --- Draw Face ---
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
        // Safe VLW Loading for Face
        // 1. Reset TextSize before loading VLW to prevent metric calculation errors
        canvas_main.setTextSize(1.0); 
        canvas_main.loadFont(FSYS, "/fonts/big.vlw");
        delay(50);
        
        // 2. Draw
        // Note: With VLW, scaling via setTextSize usually isn't needed if the font 
        // file is generated at the correct size. If you MUST scale, do it here.
        canvas_main.setTextSize(0.35); 
        canvas_main.drawString(face, 5, 23);
        
        // 3. Unload and Reset immediately
        canvas_main.unloadFont(); 
        canvas_main.setFont(&fonts::Font0); // Force fallback to internal font
        canvas_main.setTextSize(1.0); // Reset size
        delay(50);
    }

    // --- Draw Phrase ---
    // We are now guaranteed to be on the default font with Size 1.0
    canvas_main.setTextSize(1.2);
    canvas_main.setTextColor(fg, bg);
    canvas_main.setCursor(3, canvas_h - 47);
    canvas_main.println("> " + phrase);
    
    // --- Draw Peers Info ---
    if(getPwngridTotalPeers() > 0){
        // Safe VLW Loading for Peers
        canvas_main.setTextSize(1.0); // Reset size BEFORE loading
        canvas_main.loadFont(FSYS, "/fonts/small.vlw");
        
        canvas_main.setTextSize(0.35); 
        
        canvas_main.setCursor(3, canvas_h - 19);
        canvas_main.println(getLastPeerFace() + " " + getPwngridLastFriendName() + " (" + String(getPwngridLastSessionPwnedAmount()) + "/" + String(getPwngridLastPwnedAmount()) + ")");
        
        canvas_main.unloadFont();
        canvas_main.setFont(&fonts::Font0); // Safety reset
        canvas_main.setTextSize(1.0);
    }
    if (displayMutex) xSemaphoreGive(displayMutex);
}


// Function to serialize the `unit` struct to a JsonObject
void serializeUnit(const unit& u, JsonObject& obj) {
  obj["name"] = u.name;
  obj["fingerprint"] = u.fingerprint;
}

void drawInfoBox(String tittle, String info, String info2, bool canBeQuit, bool isCritical) {
  appRunning = true;
  debounceDelay();
  while(true){
    // Draw frame (locked)
    if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
    canvas_main.fillScreen(bg_color_rgb565);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    for(uint8_t size = 0; size<3;size++){
      if(canvas_main.textWidth(tittle) > 245){
        canvas_main.setTextSize(3-size);
      }
      else{
        break;
      }
    }
    uint32_t tittleLenght = canvas_main.textLength(tittle, canvas_main.textWidth(tittle) );
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, (canvas_h / 4) + tittleLenght + 8);
    canvas_main.println(info + "\n" +  info2);
    if(canBeQuit){
      canvas_main.setTextDatum(middle_center);
      canvas_main.setTextSize(2);
      int buttonWidth = canvas_main.textWidth("OK") + 20;
      int buttonHeight = 10;
      canvas_main.drawRect(canvas_center_x - (buttonWidth / 2), (canvas_h * 0.9) - 5, buttonWidth, buttonHeight, tx_color_rgb565);
      canvas_main.setTextSize(1);
      canvas_main.drawString("OK", canvas_center_x, canvas_h * 0.9);
    }
    else{
      //lets draw "Please wait..." at the bottom
      canvas_main.setTextDatum(middle_center);
      canvas_main.setTextSize(1.5);
      canvas_main.setTextColor(tx_color_rgb565);
      canvas_main.drawString("Please wait...", canvas_center_x, canvas_h * 0.9); 
    }
    if (displayMutex) xSemaphoreGive(displayMutex);

    // Push (separate lock inside pushAll)
    pushAll();
    M5.update();

#ifdef BUTTON_ONLY_INPUT
    inputManager::update();
#endif

    if(canBeQuit){
      if(isOkPressed()){
        Sound(10000, 100, sound);
        return ;
      }
    } else {
      return;
    }
  }
  appRunning = false;
}

void drawHintBox(const String &text, uint8_t hintID) {

  if (hintID >= 64) return; // guard against invalid bit indices
  if (bitRead(hintsDisplayed, hintID)) {
    return;
  }
  prevMID = 99; // force redraw of main menu on exit
  appRunning = true;
  debounceDelay();

  uint8_t current_option = 1; // 0 = OK, 1 = Don't show again
  bool selecting = true;

  while (selecting) {
    // Draw frame under mutex
    if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
    canvas_main.fillScreen(bg_color_rgb565);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, 5);
    canvas_main.println(text);

    // Draw buttons
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(middle_center);

    int btn1_x = canvas_center_x - 60;
    int btn2_x = canvas_center_x + 40;
    int btn_y = canvas_h * 0.9;

    // OK button
    if (current_option == 0) {
      canvas_main.drawRect(btn1_x - 20, btn_y - 7, 40, 14, tx_color_rgb565);
      canvas_main.setTextColor(tx_color_rgb565);
    } else {
      canvas_main.setTextColor(tx_color_rgb565);
    }
    canvas_main.drawString("OK", btn1_x, btn_y);

    // Don't show again button
    if (current_option == 1) {
      canvas_main.drawRect(btn2_x - 60, btn_y - 7, 120, 14, tx_color_rgb565);
      canvas_main.setTextColor(tx_color_rgb565);
    } else {
      canvas_main.setTextColor(tx_color_rgb565);
    }
    canvas_main.drawString("Don't show again", btn2_x, btn_y);

    if (displayMutex) xSemaphoreGive(displayMutex);
    pushAll();
    M5.update();

#ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    // Button B to navigate between options
    if (isNextPressed()) {
      current_option = (current_option + 1) % 2;
      debounceDelay();
    }
    // Button A to select
    if (isOkPressed()) {
      if (current_option == 0) {
        Sound(10000, 100, sound);
        selecting = false;
      } else if (current_option == 1) {
        bitSet(hintsDisplayed, hintID);
        saveSettings();
        Sound(10000, 100, sound);
        selecting = false;
      }
    }
#else
    M5.update();
    // Use lightweight checks to avoid copying large structs onto the stack
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if (keyboard_changed) {
      Sound(10000, 100, sound);
    }

    // Check arrow keys directly where possible
    if (M5Cardputer.Keyboard.isKeyPressed(',')) {
      current_option = 0;
      debounceDelay();
    } else if (M5Cardputer.Keyboard.isKeyPressed('/')) {
      current_option = 1;
      debounceDelay();
    } else {
      // Fallback: inspect keysState's small fields only when necessary
      auto ks = M5Cardputer.Keyboard.keysState();
      for (auto c : ks.word) {
        if (c == ',') { // left arrow
          current_option = 0;
          debounceDelay();
        } else if (c == '/') { // right arrow
          current_option = 1;
          debounceDelay();
        }
      }

      if (ks.enter) {
        if (current_option == 0) {
          Sound(10000, 100, sound);
          selecting = false;
        } else if (current_option == 1) {
          bitSet(hintsDisplayed, hintID);
          saveSettings();
          Sound(10000, 100, sound);
          selecting = false;
        }
      }
    }
#endif

    // yield a little to reduce CPU pressure and avoid tight-loop stack issues
    delay(10);
  }

  appRunning = false;
}



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
  File f = FSYS.open(path, FILE_READ);
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
  File w = FSYS.open(path, FILE_WRITE);
  if (!w) return false;
  serializeJson(doc, w);
  w.close();

  return true;
}

#include <algorithm>
std::vector<message> loadMessageHistory(const String &unitName) {
    std::vector<message> out;

    // Use reserve to prevent vector re-allocations
    out.reserve(20); 

    // Construct path safely
    String path = "/pwngrid/chats/" + unitName; // Hardcoded path is safer than String(BASE_DIR) + ...
    
    if (!FSYS.exists(path)) return out;

    File f = FSYS.open(path, FILE_READ);
    if (!f) return out;

    // SAFETY: Don't try to load massive files into RAM
    if (f.size() > 15000) { 
       // Optionally: Read only last X bytes or handle error
       f.close();
       return out; 
    }

    // Use Filter to save RAM? (Only load fields we need)
    // JsonDocument filter; filter["fromOrTo"] = true; ...
    
    JsonDocument doc;
    DeserializationError error = deserializeJson(doc, f);
    
    // Always close file immediately after parsing
    f.close(); 

    if (error) {
        return out;
    }

    JsonArray arr = doc.as<JsonArray>();
    for (JsonObject obj : arr) {
        message m;
        // Check for null to prevent String crashes
        m.fromOrTo = obj["fromOrTo"] | "unknown"; 
        m.fingerprint = obj["fingerprint"] | "";
        m.id = obj["id"] | 0;
        m.text = obj["text"] | "";
        m.ts = obj["ts"] | 0;
        m.outgoing = obj["outgoing"] | false;
        out.push_back(m);
    }

    // Sort
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

String resolveChatFingerprint(const String &chatName, const std::vector<message> &history){
  // 1. Try history (fast path)
  String fp = findIncomingFingerprint(history);
  if (fp.length() > 10) return fp;

  // 2. Fall back to contacts.json (slow path, but only once)
  File contacts = FSYS.open(ADDRES_BOOK_FILE, FILE_READ, false);
  if (!contacts) return String();

  JsonDocument doc;
  if (deserializeJson(doc, contacts)) return String();

  for (JsonObject obj : doc.as<JsonArray>()) {
    String name = obj["name"] | "";
    if (name == chatName || name == chatName + "\n") {
      return String(obj["fingerprint"] | "");
    }
  }

  return String();
}

void pwngridMessenger() {
  killInboxTask = false;
  debounceDelay();

  // 1. Network Check
  if (WiFi.status() != WL_CONNECTED) {
    drawInfoBox("Info", "Network connection needed", "To open inbox!", false, false);
    delay(3000);
    // Warning: Ensure runApp does not recursively call pwngridMessenger
    runApp(43); 
    if (WiFi.status() != WL_CONNECTED) {
      drawInfoBox("ERROR!", "No network connection", "Operation abort!", true, false);
      menuID = 8;
      return;
    }
  }

  // 2. Setup Directory
  if (!FSYS.exists("/pwngrid/chats")) FSYS.mkdir("/pwngrid/chats");

  drawInfoBox("Please wait", "Syncing inbox", "with pwngrid...", false, false);

  if (!api_client::init(KEYS_FILE)) {
    drawInfoBox("ERROR!", "Pwngrid init failed!", "Try restarting!", true, false);
    menuID = 8;
    return;
  }

  api_client::pollInbox();

  // 3. Load Chat List (Safe Method)
  std::vector<String> chats;
  {
      File dir = FSYS.open("/pwngrid/chats");
      if (dir) {
          dir.rewindDirectory();
          while (true) {
            String name = dir.getNextFileName();
            if (!name.length()) break;
            
            // FIX: Prevent crash if getNextFileName returns only the filename
            if (name.startsWith("/pwngrid/chats/")) {
                chats.push_back(name.substring(15));
            } else {
                // Ignore hidden files like .DS_Store
                if (!name.startsWith(".")) chats.push_back(name);
            }
          }
          dir.close(); // FIX: Explicit close
      }
  }
  chats.push_back("New chat");

  // FIX: Use Vector data instead of Stack Array (VLA)
  // Assuming drawMultiChoice accepts String* or String[]
  int8_t result = drawMultiChoice("Open or create chat:", chats.data(), chats.size(), 0, 0);
  
  if (result < 0) {
    stopPwngridInboxTask();
    menuID = 8;
    return;
  }

  // 4. Handle New Chat Creation
  if (result == (int)chats.size() - 1) {
    File contacts = FSYS.open(ADDRES_BOOK_FILE, FILE_READ, false);
    
    // FIX: Check validity and size, close if invalid
    if (!contacts || contacts.size() < 5) {
      if(contacts) contacts.close();
      drawInfoBox("Info", "No friends found.", "Touch grass.", true, false);
      stopPwngridInboxTask();
      menuID = 8;
      return;
    }

    JsonDocument contacts_json;
    DeserializationError err = deserializeJson(contacts_json, contacts);
    contacts.close(); // FIX: Explicit close immediately after use

    if (err) {
      drawInfoBox("ERROR", "Contacts load failed!", "SD is mad.", true, false);
      stopPwngridInboxTask();
      menuID = 8;
      return;
    }

    std::vector<String> names;
    for (JsonObject obj : contacts_json.as<JsonArray>()) {
      String name = obj["name"] | "unknown";
      bool exists = false;
      for (const auto &c : chats) if (c == name) exists = true;
      if (!exists) names.push_back(name);
    }

    if (names.empty()) {
      drawInfoBox("Info", "No new chats.", "", true, false);
      stopPwngridInboxTask();
      menuID = 8;
      return;
    }

    // FIX: Use Vector data
    result = drawMultiChoice("Select chat recipient:", names.data(), names.size(), 0, 0);
    
    if (result < 0) {
      stopPwngridInboxTask();
      menuID = 8;
      return;
    }

    // Create file safely
    File newChat = FSYS.open("/pwngrid/chats/" + names[result], FILE_WRITE, true);
    if(newChat) newChat.close();
    
    chats.push_back(names[result]);
    result = chats.size() - 1;
  }

  // ---------------- CHAT UI ----------------

  std::vector<message> chatHistory = loadMessageHistory(chats[result]);
  bool inboxDirty = false;

  String textTyped;
  textTyped.reserve(32);

  bool typingMessage = false;
  int16_t scroll = 0;

  uint64_t lastInboxSync = millis();
  String chatFingerprint = resolveChatFingerprint(chats[result], chatHistory);

  if (chatFingerprint.length() < 10) {
    drawInfoBox("ERROR!", "Recipient fingerprint", "not found!", true, false);
    stopPwngridInboxTask();
    menuID = 8;
    return;
  }

  while (true) {
    M5.update();
    M5.update();

    uint64_t now = millis();

    // Auto Refresh Logic
    if (!typingMessage && (now - lastInboxSync > 10000)) {
      canvas_main.setTextDatum(middle_center); canvas_main.setTextSize(2); 
      canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565); 
      canvas_main.drawString("Refreshing...", canvas_center_x , canvas_h/2); 
      pushAll();
      
      api_client::pollInbox();
      lastInboxSync = now;
      inboxDirty = true;
    }

    if (inboxDirty) {
      chatHistory = loadMessageHistory(chats[result]);
      inboxDirty = false;
    }

    // FIX: Safer math for scroll limits (unsigned size - 4 can underflow)
    int maxScroll = (int)chatHistory.size() - 4;
    if (maxScroll < 0) maxScroll = 0;
    
    if (scroll < 0) scroll = 0;
    if (scroll > maxScroll) scroll = maxScroll;

    canvas_main.clear();
    canvas_main.setColor(bg_color_rgb565);
    canvas_main.drawRect(5, 75, 230, 20, tx_color_rgb565);
    canvas_main.drawLine(0, 20, 250, 20, tx_color_rgb565);

    canvas_main.setTextDatum(middle_left);
    canvas_main.setTextSize(2);
    canvas_main.drawString(chats[result] + ">", 5, 10);

    renderMessages(canvas_main, chatHistory, scroll);

    canvas_main.setTextSize(1.5);
    canvas_main.drawString(">" + textTyped, 8, 86);

    canvas_main.setTextSize(1);
    #ifdef BUTTON_ONLY_INPUT
    canvas_main.drawString(
      typingMessage ? "A:send long A: edit B:exit" :
      "A:input A long: Del B:scroll B long:exit",
      2, 102
    );
    #else
    canvas_main.drawString(
      typingMessage ? "Input mode - ENTER send / DEL exit" :
      "[d] delete  [`] exit  [i] input  [;][.] scroll",
      2, 102
    );
    #endif

    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    if (!typingMessage) {
      // prioritize long-press B as special action
      if (inputManager::isButtonALongPressed()) {
        // Delete chat
        if(drawQuestionBox("Delete chat?", "Are you sure?", "")){
          FSYS.remove("/pwngrid/chats/" + chats[result]);
          drawInfoBox("Info", "Chat deleted.", "", true, false);
          menuID = 8;
          debounceDelay();
          stopPwngridInboxTask();
          return;
        }
        debounceDelay();
      }

      if (inputManager::isButtonBLongPressed()) {
        // Exit chat
        stopPwngridInboxTask();
        menuID = 8;
        return;
      }

      if (inputManager::isButtonBPressed()) {
        // Scroll
        scroll++;
        delay(50);
        if (scroll > maxScroll) scroll = 0;
        lastInboxSync = now;
      }

      if (inputManager::isButtonAPressed()) {
        // Toggle to input mode
        textTyped = userInput("Type message:", "", 24);
        typingMessage = true;
        debounceDelay();
        lastInboxSync = now;
      }
    } else {
      // Input Mode
      if (inputManager::isButtonBPressed()) {
        // Exit input mode on long press
        typingMessage = false;
        debounceDelay();
      }
      if (inputManager::isButtonAPressed()) {
        // Send message
        if (textTyped.length()) {
          message msg = { chats[result], pwngrid_indentity, 0, textTyped, 0, true };
          
          canvas_main.setTextDatum(middle_center); canvas_main.setTextSize(2); 
          canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565); 
          canvas_main.drawString("Sending...", canvas_center_x , canvas_h/2); 
          pushAll();

          bool msgSent = false;
          
          // Retry logic for sending
          for(uint8_t i = 0; i < 2; i++){
            if(api_client::sendMessageTo(chatFingerprint, textTyped)){
              msgSent = true;
              break;
            }
            delay(200);
          }

          if (msgSent) {
            registerNewMessage(msg);
            inboxDirty = true;
          } else {
            canvas_main.setTextDatum(middle_center); canvas_main.setTextSize(2); 
            canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565); 
            canvas_main.drawString("Send failed!", canvas_center_x , canvas_h/2); 
            pushAll();
            delay(2000); // Shorter delay than 3000
          }
          
          textTyped = "";
          typingMessage = false;
        }
      }
      if(inputManager::isButtonALongPressed()){
        // Edit typed text
        textTyped = userInput("Edit message:", textTyped, 24);
        debounceDelay();
      }
    }
    #else
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

    for (auto c : status.word) {
      if (!typingMessage) {
          if (c == ';') { scroll++; delay(50); lastInboxSync = now; }
          if (c == '.') { scroll--; delay(50); lastInboxSync = now; }
          if (c == '`') { stopPwngridInboxTask(); menuID = 8; return; }
          
          if (c == 'd') {
            if(drawQuestionBox("Delete chat?", "Are you sure?", "")){
              FSYS.remove("/pwngrid/chats/" + chats[result]);
              drawInfoBox("Info", "Chat deleted.", "", true, false);
              menuID = 8;
              debounceDelay();
              stopPwngridInboxTask();
              return;
            }
            debounceDelay();
          }
          
          if (c == 'i') { typingMessage = true; debounceDelay(); lastInboxSync = now; }
      } else {
          // Input Mode
          if (textTyped.length() < 24) { textTyped += c; debounceDelay(); lastInboxSync = now; }
      }
    }

    if (status.del) {
      if (textTyped.length()) { textTyped.remove(textTyped.length() - 1); debounceDelay(); }
      else typingMessage = false;
    }

    if (status.enter && typingMessage && textTyped.length()) {
      message msg = { chats[result], pwngrid_indentity, 0, textTyped, 0, true };
      
      canvas_main.setTextDatum(middle_center); canvas_main.setTextSize(2); 
      canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565); 
      canvas_main.drawString("Sending...", canvas_center_x , canvas_h/2); 
      pushAll();

      bool msgSent = false;
      
      // Retry logic for sending
      for(uint8_t i = 0; i < 2; i++){
        if(api_client::sendMessageTo(chatFingerprint, textTyped)){
          msgSent = true;
          break;
        }
        delay(200);
      }

      if (msgSent) {
        registerNewMessage(msg);
        inboxDirty = true;
      } else {
        canvas_main.setTextDatum(middle_center); canvas_main.setTextSize(2); 
        canvas_main.fillRect(0, (canvas_h/2)-10, 250, 20, bg_color_rgb565); 
        canvas_main.drawString("Send failed!", canvas_center_x , canvas_h/2); 
        pushAll();
        delay(2000); // Shorter delay than 3000
      }
      
      textTyped = "";
      typingMessage = false;
    }
    #endif

    pushAll();
  }
}

String isoTimestampToDateTimeString(String isoTimestamp) {
    if (isoTimestamp.length() < 19) {
        return "Invalid Timestamp";
    }

    String date = isoTimestamp.substring(0, 10); // YYYY-MM-DD
    String time = isoTimestamp.substring(11, 19); // HH:MM:SS

    return date + " " + time;
}

bool addUnitToAddressBook(const unit u) {
    File file = FSYS.open(ADDRES_BOOK_FILE, FILE_READ);
    if (!file) {
        logMessage("Failed to open address book for reading.");
        return false;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, file);
    file.close();
    if (err) {
        logMessage("Failed to parse address book: " + String(err.c_str()));
        return false;
    }

    JsonArray arr = doc.as<JsonArray>();

    // Check for duplicates
    for (JsonObject obj : arr) {
        String existingFingerprint = obj["fingerprint"] | "";
        if (existingFingerprint == u.fingerprint) {
            logMessage("Unit with fingerprint already exists in address book.");
            return true; // Duplicate found
        }
    }

    // Add new unit
    JsonObject newObj = arr.createNestedObject();
    serializeUnit(u, newObj);

    // Write back to file
    file = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
    if (!file) {
        logMessage("Failed to open address book for writing.");
        return false;
    }

    serializeJson(doc, file);
    file.close();

    logMessage("Added unit to address book: " + u.name);
    return true;
}

void runApp(uint8_t appID){
  logMessage("App started running, ID:"+ String(appID));
  menu_current_opt = 0;
  menu_current_page = 1;
  if(appID){
    if(appID == 255){
      if(menuID != 1){
        menuID = 1;
      }
      else{
        menuID = 0;
      }
    }
    if(appID == 1){
      drawHintBox("For all features of manual mode to work, wifi will always disconnect before entering menu.", 4);
      if(WiFi.status() == WL_CONNECTED){
        drawInfoBox("Info", "Disconnecting from WiFi", "Please wait...", false, false);
        WiFi.disconnect();
      }
      debounceDelay();
      drawMenuList( wifi_menu , 2, 6);
    }
    if(appID == 2){}
    if(appID == 3){
      drawSysInfo();
      menuID = 6;
    }
    if(appID == 4){
      drawHintBox("Make sure to add all your networks to whitelist, before enabling auto mode!", 5);
      debounceDelay();
      drawMenuList(pwngotchi_menu, 5 , 6);
    }
    if(appID == 90){
      debounceDelay();
      runTextsEditor();
      menuID = 6;
    }
    if(appID == 5){
      drawHintBox("HS - handshakes\n P - peers (other pwnagotchis) met \n D - deauth amount\n T - time\n E - epochs (pwn loops)", 6);
      drawStats(); 
      menuID = 1;
    }
    if(appID == 6){
      debounceDelay();
      drawMenuList(settings_menu,6,26);
    }
    if(appID == 7){
      if(hostname == "M5Gotchi"){
        drawInfoBox("Info", "Please set a unique name", "In settings -> Device name", true, false);
        menuID = 6;
        return;
      }
      (pwngrid_indentity.length()<10)?drawHintBox("To see all the features of pwngrid, please enrol first!", 7):void();
      debounceDelay();
      drawMenuList(pwngrid_menu, 8, 7);
    }
    if(appID == 8){
      drawHintBox("Wardriving mode allows you to collect WiFi networks location for later use, or to share it with WIGLE.net", 8);
      debounceDelay();
      drawMenuList(wardrivingMenuWithWiggle, 9, 6);
    }
    if(appID == 9){
      drawHintBox("This function needs wifi on boot to be enabled and have a stable wifi connection to work!", 19);
      String menu[] = {"On", "Off", "Back"};
      uint8_t answer = drawMultiChoice("Check inbox at boot", menu, 3, 6, 0);
      if(answer == 0){
        check_inbox_at_startup = true;
        saveSettings();
        drawInfoBox("Info", "Check inbox at boot", "Enabled", true, false);
      }
      else if(answer == 1){
        check_inbox_at_startup = false;
        saveSettings();
        drawInfoBox("Info", "Check inbox at boot", "Disabled", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 10){
      drawHintBox("Due to compexity of pwngrid messenger, in some scenarios you may encounter stuttering or slowdowns.", 9);
      pwngridMessenger();
      menuID = 8;
    }
    if(appID == 11){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To send messages!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Message send abort", true, false);
          menuID = 8;
          return;
        }
      }
      api_client::init(KEYS_FILE);
      File contacts = FSYS.open(ADDRES_BOOK_FILE, FILE_READ);
      if(!FSYS.open(ADDRES_BOOK_FILE)){
        drawInfoBox("ERROR", "No frends found.", "Meet and add one.", true, false);
      }
      JsonDocument contacts_json;
      DeserializationError err = deserializeJson(contacts_json, contacts);

      if (err) {
          logMessage("Failed to parse contacts: " + String(err.c_str()));
          menuID = 8;
          return;
      }

      JsonArray contacts_arr = contacts_json.as<JsonArray>();
      logMessage("Array size: " + String(contacts_arr.size()));
      if(contacts_arr.size() == 0){
        drawInfoBox("Info", "No frends found", "Add to text them", true, false);
        menuID = 8;
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
      for(uint16_t i = 0; i<=contacts_vector.size(); i++){
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
      menuID = 8;
    }
    if(appID == 12){
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To enroll!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Enrol abort", true, false);
          menuID = 8;
          return;
        }
      }
      drawHintBox("Depending on network and device speed, enrollment may take several minutes or even fail.", 10);
      drawInfoBox("Init", "Initializing keys...", "This may take a while.", false, false);
      FSYS.mkdir("/pwngrid");
      FSYS.mkdir("/pwngrid/keys");
      FSYS.mkdir("/pwngrid/chats");
      File cont = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
      cont.print("[]");
      cont.flush();
      cont.close();

      if(api_client::init(KEYS_FILE)){
        if(!(WiFi.status() == WL_CONNECTED)){
          drawInfoBox("ERROR!", "Connect to wifi", "to proceed", true, false);
          menuID = 8;
          return;
        }
        drawInfoBox("Info", "Enroling with pwngrid...", "This may take a while", false, false);
        if(api_client::enrollWithGrid()){
          drawInfoBox("Info", "Succesfully enrolled.", "All pwngrid functions enabled.", true, false);
        }
        else{
          drawInfoBox("Error", "Something went wrong", "Try again later.", true, false);
        }
        menuID = 8;
        return;
      }
      else{
        drawInfoBox("Error", "Keygen failed", "Try restarting!", true, false);
        drawHintBox("Please restart your device before trying to enroll again. It may take up to 3 tries to successfully enroll.", 11);
      }
      menuID = 8;
      return;
    }
    if(appID == 13){
      M5.Display.setBrightness(100);
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
        M5.update();
#ifdef BUTTON_ONLY_INPUT
        inputManager::update();
        if (isOkPressed() || toggleMenuBtnPressed()){
          M5.Display.setBrightness(brightness);
          menuID = 8;
          return;
        }
#else
        auto keysState = M5Cardputer.Keyboard.keysState();
        if(keysState.enter){
          M5.Display.setBrightness(brightness);
          menuID = 8;
          return;
        }
        for(auto i : keysState.word){
          if(i=='`'){
            menuID = 8;
            M5.Display.setBrightness(brightness);
            return;
          }
        }
#endif
      }
      menuID = 8;
    }
    if(appID == 70){
      debounceDelay();
      sdmanager::runFileManager();
      menuID = 1;
    }
    if (appID == 71) {
      debounceDelay();
      // Simple LittleFS info screen + basic actions
      drawLittleFSManager();
      menuID = 6; // return to settings
    }
    if (appID == 72) {
      debounceDelay();
      // Storage info screen
      drawStorageInfo();
      menuID = 6; // return to settings
    }
    if (appID == 73) {
      //check for wifi and connect to it if not connected
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To start server!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Operation abort!", true, false);
          menuID = 6;
          return;
        }
      }
      debounceDelay();
      bool enable_usb = drawQuestionBox("Web file manager", "Start server?", "WiFi needs to be connected.");
      if (enable_usb) {
        if (USBMassStorage::begin(18, 20)) {
          #ifdef BUTTON_ONLY_INPUT
          drawInfoBox("Server Enabled", "Goto " + WiFi.localIP().toString() + ":8080", "to access files. Hold B to exit.", false, false);
          delay(3000);
          logMessage(WiFi.localIP().toString() + " entered USB mass storage mode");
          while(!inputManager::isButtonBLongPressed()){
            M5.update();
            inputManager::update();
          }
          #else
          drawInfoBox("Server Enabled", "Goto " + WiFi.localIP().toString() + ":8080", "to access files. Press ENTER to exit.", false, false);
          delay(3000);
          logMessage(WiFi.localIP().toString() + " entered USB mass storage mode");
          while(!M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)){
            M5.update();
            M5Cardputer.update();
          }
          #endif
          USBMassStorage::end();
          drawInfoBox("Server disabled", "", "", true, false);
        } else {
          drawInfoBox("Error", "Failed to enable. ", "", true, false);
        }
      }
      menuID = 6;
    }
    if(appID == 14){
      if(!pwnagothiMode){
        bool answear = drawQuestionBox("CONFIRMATION", "Operate only if you ", "have premision!");
        if(answear){
          menuID = 5;
          drawHintBox("Stealth mode mimics wifi router, kicking only 1 client at once.\n In the other hand, normal mode kicks all connected clients and that grately impoves capture.", 15);
          String sub_menu[] = {"Stealth (legacy)", "Normal"};
          int8_t modeChoice = drawMultiChoice("Select mode:", sub_menu, 2, 2, 2);
          debounceDelay();
          if(modeChoice == -1){
            menuID = 5;
            return;
          }
          if(modeChoice==0){
            stealth_mode = true;
          }
          else{
            stealth_mode = false;
          }
          drawInfoBox("INITIALIZING", "Pwnagothi mode initialization", "please wait...", false, false);
          menuID = 5;
          if(pwnagothiBegin()){
            auto_mode_and_wardrive = true;
            pwnagothiMode = true;
            menuID = 0;
            return;
          }
          else{
            drawInfoBox("ERROR", "Pwnagothi init failed!", "", true, false);
            pwnagothiMode = false;
          }
          menuID = 5;
          return;
        }
      }
      else{
        drawInfoBox("WTF?!", "Pwnagothi mode is on", "Can't you just look at UI!??", true, true);
      }
      menuID = 5;
      return;
    }
    if(appID == 15){
      bool confirmation = drawQuestionBox("Reset pwngrid?", "This will delete all keys, messages, frends, identity chats!", "");
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
        FSYS.remove("/pwngrid/keys/id_rsa");
        FSYS.remove("/pwngrid/keys/id_rsa.pub");
        FSYS.remove("/pwngrid/token.json");
        FSYS.remove(ADDRES_BOOK_FILE);
        FSYS.rmdir("/pwngrid/keys");
        FSYS.rmdir("/pwngrid/chats");
        FSYS.remove("/pwngrid/cracks.conf");
        File chatsDis = FSYS.open("/pwngrid/chats");
        while(true){
          String nextFileName = chatsDis.getNextFileName();
          if(nextFileName.length()>8){
            FSYS.remove(nextFileName);
          }
          else{
            break;
          }
        }
        chatsDis.close();
        FSYS.rmdir("/pwngrid");
        lastTokenRefresh = 0;

        delay(5000);
        pwngrid_indentity = new_indetity;
        saveSettings();
        menuID = 8;
        return;
      }
      menuID = 8;
      return;
    }
    if(appID == 16){
      auto peers_vec = getPwngridSnapshot();
      uint8_t int_peers = (uint8_t)peers_vec.size();
      if(int_peers == 0){
        drawInfoBox("Info", "No nearby pwngrid units", "Try again later", true, false);
        menuID = 8;
        return;
      }
      // local copy
      std::vector<pwngrid_peer> peers_list = peers_vec;
      String mmenu[int_peers + 1];
      for(uint8_t i = 0; i<int_peers; i++){
        mmenu[i] = peers_list[i].name;
      }
      int8_t choice = drawMultiChoice("Nearby pwngrid units", mmenu, int_peers, 2, 0);
      if(choice == -1){
        menuID = 8;
        return;
      }
      //Peer Details and addressbook addition
      uint8_t current_option;
      debounceDelay();
      drawTopCanvas();
      drawBottomCanvas();
      canvas_main.fillScreen(bg_color_rgb565);
      canvas_main.setTextColor(tx_color_rgb565);
      canvas_main.clear(bg_color_rgb565);
      canvas_main.setTextSize(0.4);
      canvas_main.setTextDatum(middle_center);
      canvas_main.loadFont(FSYS, "/fonts/small.vlw");
      canvas_main.drawString(peers_list[choice].face, canvas_center_x, canvas_h / 8);
      canvas_main.unloadFont();
      canvas_main.setTextSize(1.5);
      canvas_main.drawString(peers_list[choice].name, canvas_center_x, (canvas_h * 2)/8);
      canvas_main.setTextSize(1);
      canvas_main.drawString(peers_list[choice].identity, canvas_center_x, (canvas_h * 3)/8);
      canvas_main.setTextSize(1.5);
      canvas_main.drawString("PWND: " + String(peers_list[choice].pwnd_run) + "/" + String(peers_list[choice].pwnd_tot) + ", RSSI: " + String(peers_list[choice].rssi) , canvas_center_x, (canvas_h*4)/7 );
      while(true)
      {
        String options[] = {"Add to friends", "Send message", "Back"};
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_left);
        canvas_main.drawString(options[0] + "   " + options[1] + "   " + options[2], 10, canvas_h - 30);
        canvas_main.drawRect(6, canvas_h - 37, 90, 15, (current_option == 0)? tx_color_rgb565: bg_color_rgb565);
        canvas_main.drawRect(108, canvas_h - 37, 80, 15, (current_option == 1)? tx_color_rgb565: bg_color_rgb565);
        canvas_main.drawRect(200, canvas_h - 37, 27, 15, (current_option == 2)? tx_color_rgb565: bg_color_rgb565);
        pushAll();
        M5.update();
#ifndef BUTTON_ONLY_INPUT
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
#else
        inputManager::update();
        if (inputManager::isButtonBPressed()) {
          (current_option == 2)? current_option = 0: current_option++;
          debounceDelay();
        }
        if (isOkPressed()) {
#endif
          if(current_option == 2){
            menuID = 8;
            debounceDelay();
            return;
          }
          if(current_option == 0){
            debounceDelay();
            // Open contacts file for reading and parse JSON into a vector
            File contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_READ);
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
                contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
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
              contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
              contactsFile.print(out);
              contactsFile.flush();
              contactsFile.close();
            }
            drawInfoBox("Sucess", "Unit added to frend", "list, text to it now!", true, false);
            menuID = 8;
            return;
          }
          if(current_option == 1){
            if(!(WiFi.status() == WL_CONNECTED)){
              drawInfoBox("Info", "Network connection needed", "To send messages!", false, false);
              delay(3000);
              runApp(43);
              if(WiFi.status() != WL_CONNECTED){
                drawInfoBox("ERROR!", "No network connection", "Message send abort", true, false);
                menuID = 8;
                return;
              }
            }
            if(api_client::init(KEYS_FILE) == false){
              drawInfoBox("ERROR!", "Pwngrid init failed!", "Try restarting!", true, false);
              menuID = 8;
              return;
            }
            String message = userInput("Message:", "Type message content:", 100);
            if(!(message.length()>1)){
              menuID = 8;
              return;
            }
            drawInfoBox("Sending...", "Sneding message", "Please wait", false, false);
            if(api_client::sendMessageTo(peers_list[choice].identity, message)){
              drawInfoBox("Send", "Message was send", "succesfuly.", true, false);
            }
            else{
              drawInfoBox("Error", "Message not send.", "Something went wrong!", true, false);
            }
            menuID = 8;
            return;
          }
        }
      }
      menuID = 8;
      return;
    }
    if(appID == 17){
      debounceDelay();

      File contacts = FSYS.open(ADDRES_BOOK_FILE, FILE_READ, true);
      if (!contacts) {
          logMessage("Failed to open contacts file");
          menuID = 8;
          return;
      }

      // one single fixed allocation instead of heap soup
      StaticJsonDocument<16384> contacts_json;
      DeserializationError err = deserializeJson(contacts_json, contacts);
      contacts.close();

      if (err) {
          logMessage("Failed to parse contacts: " + String(err.c_str()));
          menuID = 8;
          return;
      }

      JsonArray contacts_arr = contacts_json.as<JsonArray>();
      uint16_t arrSize = contacts_arr.size();
      logMessage("Array size: " + String(arrSize));

      // build vector once
      std::vector<unit> contacts_vector;
      contacts_vector.reserve(arrSize);

      for (JsonObject obj : contacts_arr) {
          String name = obj["name"] | "unknown";
          String fingerprint = obj["fingerprint"] | "none";
          logMessage("Name: " + name + ", Fingerprint: " + fingerprint);
          contacts_vector.push_back({name, fingerprint});
      }

      // if (contacts_vector.empty()) {
      //     drawInfoBox("Info", "No frends found", "Adding one now", false, false);
      //     delay(5000);
      // }

      // build names safely on heap
      std::vector<String> names;
      names.reserve(contacts_vector.size() + 1);

      for (size_t i = 0; i < contacts_vector.size(); i++) {
          names.push_back(contacts_vector[i].name);
      }
      names.push_back("Add new");

      // draw menu
      int16_t result = drawMultiChoice(
          "Select contact to manage:",
          names.data(),
          names.size(),
          0,
          0
      );

      if (result < 0) {
          menuID = 8;
          return;
      }
      else if(result == contacts_vector.size() ){
        logMessage("Heap before new frend setup:");
        printHeapInfo();
        String fingerprint;
        String name;
        String subMenu[3] = {"via keyboard", "via PC/Phone", "back"};
        result = drawMultiChoice("Type unit fingerprint:", subMenu, 3, 0, 0);
        if(result==2 || result==-1){
          menuID = 8;
          return;
        }
        else if(result == 0){
          if(!(WiFi.status() == WL_CONNECTED)){
            drawInfoBox("Info", "Network connection needed", "To add unit!", false, false);
            delay(3000);
            runApp(43);
            if(WiFi.status() != WL_CONNECTED){
              drawInfoBox("ERROR!", "No network connection", "Unit add abort!", true, false);
              menuID = 8;
              return;
            }
          }
          logMessage("Heap before unit fp setup:");
          printHeapInfo();
          fingerprint = userInput("Fingerprint:", "Enter unit fingerprint", 64);
          drawInfoBox("Info", "Parsing unit name", "Please wait", false, false);
          // api_client::init(KEYS_FILE);
          logMessage("Heap before new http get:");
          printHeapInfo();
          name = api_client::getNameFromFingerprint(fingerprint);
          if(name.length() < 1){
            drawInfoBox("ERROR!", "Unit not found", "Check fingerprint!", true, false);
            menuID = 8;
            return;
          }
        }
        else if(result == 1){
          drawInfoBox("Connect:", "Connect to CardputerSetup and type fingerprint.", "", false, false);
          logMessage("Heap before unit fp setup:");
          printHeapInfo();
          fingerprint = userInputFromWebServer("Unit fingerprint");
          logMessage("Heap after unit fp setup:");
          printHeapInfo();
          if(!(WiFi.status() == WL_CONNECTED)){
            drawInfoBox("Info", "Network connection needed", "To add unit!", false, false);
            delay(3000);
            runApp(43);
            if(WiFi.status() != WL_CONNECTED){
              drawInfoBox("ERROR!", "No network connection", "Unit add abort!", true, false);
              menuID = 8;
              return;
            }
          }
          drawInfoBox("Info", "Parsing unit name", "Please wait", false, false);
          // if(api_client::init(KEYS_FILE) == false){
          //   drawInfoBox("ERROR!", "Key init failed", "Try restarting!", true, false);
          //   menuID = 8;
          //   return;
          // }
          logMessage("Heap before new http get:");
          printHeapInfo();
          name = api_client::getNameFromFingerprint(fingerprint);
          if(name.length() < 1 ){
            drawInfoBox("ERROR!", "Unit not found", "Check fingerprint!", true, false);
            menuID = 8;
            return;
          }
        }
        debounceDelay();
        // Open contacts file for reading and parse JSON into a vector
        File contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_READ);
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
            contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
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
          contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
          contactsFile.print(out);
          contactsFile.flush();
          contactsFile.close();
        }
        drawInfoBox("Sucess", "Unit added to frend", "list, text to it now!", true, false);
        menuID = 8;
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
#ifndef BUTTON_ONLY_INPUT
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
#else
        inputManager::update();
        if (inputManager::isButtonBPressed()) {
          (current_option == 1)? current_option = 0: current_option++;
          debounceDelay();
        }
        if(inputManager::isButtonAPressed()){
#endif
          if(current_option == 1){
            menuID = 8;
            return;
          }
          if (current_option == 0) {
            debounceDelay();

            File contactsFile = FSYS.open(ADDRES_BOOK_FILE, FILE_READ);
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
                    File outFile = FSYS.open(ADDRES_BOOK_FILE, FILE_WRITE);
                    if (outFile) {
                        serializeJsonPretty(doc, outFile);
                        outFile.close();
                    }
                } else {
                    logMessage("Failed to parse contacts file: " + String(err.c_str()));
                }
            }
          
            drawInfoBox("Sucess", "Unit deleted", "bye bye", true, false);
            menuID = 8;
            return;
        }
        }
      }
      menuID = 8;
      return;
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
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        auto keysState = M5Cardputer.Keyboard.keysState();
        for(auto i : keysState.word){
          if(i=='`'){
            logMessage("Wardriver stopped by user");
            canvas_main.clear(bg_color_rgb565);
            canvas_main.setTextSize(1.5);
            canvas_main.setTextDatum(middle_center);
            canvas_main.drawString("Exited!", canvas_center_x, canvas_h/2);
            pushAll();
            menuID = 9;
            return;
          }
        }
#else
        inputManager::update();
        if(inputManager::isButtonBLongPressed()){
          logMessage("Wardriver stopped by user");
          canvas_main.clear(bg_color_rgb565);
          canvas_main.setTextSize(1.5);
          canvas_main.setTextDatum(middle_center);
          canvas_main.drawString("Exited!", canvas_center_x, canvas_h/2);
          pushAll();
          menuID = 9;
          return;
        }
#endif
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
      menuID = 9;
      return;
    }
    // IMPROVED VERSION - Replace lines 2774-3208 in src/ui.cpp

    if(appID == 19){
      drawHintBox("This app is VERY slow due to complexity of whole csv parsing. Please be patient or use only for searching", 14);
      File csvFile;
      // Wardriving CSV viewer with search function
      String selectedPath = "/wardriving/first_seen.csv";
      String menu[] = {"Select file", "Use default (GPS data from pwned networks if enabled)"};
      int8_t fileChoice = drawMultiChoice("CSV File Option:", menu, 2, 2, 0);
      debounceDelay();
      if(fileChoice == -1){
        menuID = 9;
        return;
      }
      if(fileChoice == 0){
        selectedPath = sdmanager::selectFile(".csv");
        csvFile = FSYS.open(selectedPath, FILE_READ);
      }
      else {
        csvFile = FSYS.open("/wardriving/first_seen.csv", FILE_READ);
      }
      if (!csvFile) {
        drawInfoBox("Error", "File not found", "Wrong selection?", true, false);
        menuID = 9;
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
        menuID = 9;
        return;
      }
      
      // Function to read a specific line from file without storing all lines
      auto readLineAtIndex = [&](uint32_t lineIndex) -> String {
        String result = "";
        File f = FSYS.open(selectedPath, FILE_READ);
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

      // Helper to get context-aware button instructions
      auto getButtonHints = [](bool isSearchMode) -> String {
        #ifdef BUTTON_ONLY_INPUT
          if (isSearchMode) {
            return "A:char B-:del A-:search B--:cancel";
          } else {
            return "A:down B:search A--:detail B--:back";
          }
        #else
          if (isSearchMode) {
            return "[DEL] clear, [ENTER] search, [`] cancel";
          } else {
            return "[/]next [,]prev [S]search [ENTER]details [`]back";
          }
        #endif
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
        #ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        #endif
        
        if (searching) {
          #ifdef BUTTON_ONLY_INPUT
          searchTerm = userInput("Search CSV", "Enter SSID or BSSID to search:", 32);
          #endif
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
          canvas_main.setTextDatum(middle_center);
          canvas_main.drawString(getButtonHints(true), canvas_center_x, canvas_h * 0.9);
          pushAll();
          
    #ifndef BUTTON_ONLY_INPUT
          M5Cardputer.update();
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
    #else
          
          inputManager::update();
          uint32_t now = millis();
          
          // Long press B to cancel search
          if (inputManager::isButtonBLongPressed()) {
            searching = false;
            debounceDelay();
          }
          // Short press B to delete last character
          else if (inputManager::isButtonBPressed() && searchTerm.length() > 0) {
            searchTerm.remove(searchTerm.length() - 1);
            lastSearchTime = now;
            debounceDelay();
          }
          // Long press A to execute search
          else if (true) {
    #endif
            drawInfoBox("Searching...", "Filtering results", "Please wait", false, false);
            filteredIndices.clear();
            String lowerSearch = searchTerm;
            lowerSearch.toLowerCase();
            
            // Optimized: Read file once and parse line by line
            File csvFile = FSYS.open("/wardrive.csv", FILE_READ);
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
    #ifndef BUTTON_ONLY_INPUT
          }
    #else
          }
          // Short press A to add character (keyboard mode would handle this)
    #endif
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
          
          canvas_main.setTextSize(1);
          canvas_main.setTextDatum(middle_center);
          canvas_main.drawString(getButtonHints(false), canvas_center_x, canvas_h - 10);
          pushAll();
          
    #ifndef BUTTON_ONLY_INPUT
          M5Cardputer.update();
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
              menuID = 9;
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
    #else
          inputManager::update();
          
          // Long press B to go back to menu
          if (inputManager::isButtonBLongPressed()) {
            menuID = 9;
            return;
          }
          
          // Short press B to go to next page
          if (inputManager::isButtonBPressed()) {
            searchTerm = "";
            searching = true;
            lastSearchTime = millis();
            debounceDelay();
          }
          
          // Short press A to navigate down one entry
          if (inputManager::isButtonAPressed()) {
            if (selectedIndex < (totalEntries - 1)) {
    #endif
              selectedIndex++;
              if (selectedIndex >= (displayIndex + 4)) displayIndex = selectedIndex - 3;
              }
              debounceDelay();
    #ifndef BUTTON_ONLY_INPUT
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
    #else
          }
          
          // Long press A to view details of selected entry
          if (inputManager::isButtonALongPressed()) {
    #endif
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
              #ifdef BUTTON_ONLY_INPUT
                canvas_main.drawString("[A] back", canvas_center_x, canvas_h - 10);
              #else
                canvas_main.drawString("[ENTER] back to list", canvas_center_x, canvas_h - 10);
              #endif
              
              pushAll();
              
              while(true) {
                M5.update();
                M5.update();
    #ifndef BUTTON_ONLY_INPUT
                M5Cardputer.update();
                keyboard_changed = M5Cardputer.Keyboard.isChange();
                if(keyboard_changed){Sound(10000, 100, sound);}
                Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
                if(status.enter) break;
                for(auto k : status.word) {
                  if(k == '`') break;
                }
    #else
                inputManager::update();
                if(inputManager::isButtonAPressed() || inputManager::isButtonBLongPressed()) break;
    #endif
                delay(50);
              }
            }
            debounceDelay();
          }
        }
      }
      menuID = 9;
      return;
    }
    if(appID == 20){
      wifion();
      drawInfoBox("Info", "Scanning for wifi...", "Please wait", false, false);
      int numNetworks = WiFi.scanNetworks();
      String wifinets[numNetworks+1];
      if (numNetworks == 0) {
        drawInfoBox("Info", "No wifi nearby", "Abort.", true, false);
        menuID = 2;
        return;
      } else {
        // Przechodzimy przez wszystkie znalezione sieci i zapisujemy ich nazwy w liście
        for (int i = 0; i < numNetworks; i++) {
        String ssid = WiFi.SSID(i);
        
        wifinets[i] = String(ssid);
        logMessage(wifinets[i]);
        }
      }
      int8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks, 2, 0);
      if(wifisel == -1){
        menuID = 2;
        return;
      }
      wifiChoice = WiFi.SSID(wifisel);
      intWifiChoice = wifisel;
      logMessage("Selected wifi: "+ wifiChoice);
      drawInfoBox("Succes", wifiChoice, "Was selected", true, false);
      debounceDelay();
      menuID = 2;
      return;
    }
    if(appID == 21){
      if(wifiChoice.equals("")){
        drawInfoBox("Error", "No wifi selected", "Do it first", true, false);
      }
      else{
        drawWifiInfoScreen(WiFi.SSID(intWifiChoice), WiFi.BSSIDstr(intWifiChoice), String(WiFi.RSSI(intWifiChoice)), String(WiFi.channel(intWifiChoice)));
      }
      
      menuID = 2;
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
          M5.update();
#ifndef BUTTON_ONLY_INPUT
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
            xSemaphoreTake(wifiMutex, portMAX_DELAY);
            WiFi.eraseAP();
            xSemaphoreGive(wifiMutex);
            wifion();
            apMode = false;
            wifiChoice = "";
            break;
          }
#else
          inputManager::update();
          if(!loginCaptured.equals("") && !passCaptured.equals("")){
            drawInfoBox("New victim!", loginCaptured, passCaptured, false, false);
          }
          else{
            drawInfoBox("Evil portal", "Evli portal active...", "Enter to exit", false, false);
          }
          if (inputManager::isButtonAPressed()) {
            xSemaphoreTake(wifiMutex, portMAX_DELAY);
            WiFi.eraseAP();
            xSemaphoreGive(wifiMutex);
            wifion();
            apMode = false;
            wifiChoice = "";
            break;
          }
#endif
        }
      }
      if(tempChoice == 1){
        String ssidMenu[] = {"Funny SSID", "Broken SSID", "Rick Roll", "Make your own :)"};
        M5.update();
        M5.update();
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
          menuID = 2;
          }
        else if (ssidChoice==3){
          String* BeaconList = makeList("Create spam list", 48, false, 30);
          broadcastFakeSSIDs( BeaconList , sizeof(BeaconList), sound);
        }
        else{
          menuID = 2;
          return;
        }
      }
      else if(tempChoice == 2){
        if(apMode){
          bool answear = drawQuestionBox("AP of?", "AP arleady running!", "Power AP off?");
          if (answear){
            xSemaphoreTake(wifiMutex, portMAX_DELAY);
            WiFi.eraseAP();
            WiFi.mode(WIFI_MODE_NULL);
            xSemaphoreGive(wifiMutex);
            wifion();
            apMode = false;
            wifiChoice = "";
            menuID = 2;
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
          wifion();
          apMode = false;
          wifiChoice = "";
          }
      }
      menuID = 2;
      return;
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
            #ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            drawInfoBox("Searching...", "Found "+ String(clientLen)+ " clients", "SELECT for next step", false, false);
            #else
            drawInfoBox("Searching...", "Found "+ String(clientLen)+ " clients", "ENTER for next step", false, false);
            #endif
            updateM5();
#ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              debounceDelay();
              xSemaphoreTake(wifiMutex, portMAX_DELAY);
              esp_wifi_set_promiscuous(false);
              xSemaphoreGive(wifiMutex);
              break;
            }
#else
            inputManager::update();
            if(inputManager::isButtonAPressed()){
              debounceDelay();
              xSemaphoreTake(wifiMutex, portMAX_DELAY);
              esp_wifi_set_promiscuous(false);
              xSemaphoreGive(wifiMutex);
              break;
            }
#endif
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
            menuID = 2;
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
#ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            if(status.enter){
              break;
            }

            if((clients[target] == "Everyone")?deauth_everyone(1, 10):send_deauth_packets(clients[target], 1, 10)){
              PPS++;
            }
#else
            inputManager::update();
            if(inputManager::isButtonAPressed()){
              break;
            }

            if((clients[target] == "Everyone")?deauth_everyone(1, 10):send_deauth_packets(clients[target], 1, 10)){
              PPS++;
            }
#endif
            
          }
          
          clearClients();
        }
        else{
          drawInfoBox("Error!", "No wifi selected!", "Select one first!", true, false);
        }
      }
      
      menuID = 2;
      return;
    }
    if(appID == 61){
      if(!dev_mode){
        drawInfoBox("ERROR", "Experimental app!", "Enable dev mode to use", true, false);
        menuID = 2;
        return;
      }
      // PMKID Grabber app - uses wifiChoice if available
      if(wifiChoice.equals("")){
        drawInfoBox("Error", "No wifi selected", "Use 'Select Networks' first", true, false);
        menuID = 2;
        return;
      }

      drawInfoBox("Info", "Scanning for "+ wifiChoice, "Please wait", false, false);
      int numNetworks = WiFi.scanNetworks();
      if (numNetworks <= 0) {
        drawInfoBox("Info", "No networks found", "Rescan in different location", true, false);
        menuID = 2; 
        return;
      }

      // Collect matches for chosen SSID
      std::vector<int> matches;
      for (int i = 0; i < numNetworks; i++) {
        if (WiFi.SSID(i) == wifiChoice) matches.push_back(i);
      }
      if (matches.size() == 0) {
        drawInfoBox("Info", "Selected SSID not found", "Rescan and select it first", true, false);
        menuID = 2; return;
      }

      int pickedIndex = matches[0];
      if (matches.size() > 1) {
        // Let user pick BSSID/channel among duplicates
        String list[matches.size()+1];
        for (size_t k = 0; k < matches.size(); k++) {
          int idx = matches[k];
          list[k] = WiFi.BSSIDstr(idx) + " ch:" + String(WiFi.channel(idx));
        }
        list[matches.size()] = "Cancel";
        int sel = drawMultiChoice("Pick BSSID:", list, matches.size()+1, 6, 0);
        if (sel == -1 || sel == (int)matches.size()) { menuID = 2; return; }
        pickedIndex = matches[sel];
      }

      const uint8_t* bssidPtr = WiFi.BSSID(pickedIndex);
      int ch = WiFi.channel(pickedIndex);
      if (!bssidPtr) {
        drawInfoBox("Error", "Can't get BSSID", "Aborting", true, false);
        menuID = 2; return;
      }

      if (drawQuestionBox("Proceed?", "Grab PMKID from:", wifiChoice)) {
        drawInfoBox("PMKID", "Starting grabber...", "Please wait", false, false);
        attackSetup();
        bool ok;
        while(true){
          attackLoop();
          bool ok = runPMKIDAttack(bssidPtr, ch);
          if(ok) break;
        }
         // 30s timeout
        
        if (ok) {
          drawInfoBox("Success", "PMKID captured", "", true, false);
        } else {
          drawInfoBox("Info", "No PMKID captured", "Try again later", true, false);
        }
      }
      menuID = 2;
      return;
    }
    if(appID == 24){
      String mmenu[] = {"Mac sniffing", "EAPOL sniffing"};
      singlePage = false;
      menu_current_pages = 2;
      uint8_t answerrr = drawMultiChoice("Sniffing", mmenu, 2, 1, 0);
      if(answerrr == 0){
        String mmenuu[] = {"Auto switch" ,"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13"};
        answerrr = drawMultiChoice("Select chanel", mmenuu, 14, 1, 0);
        if(true){
          uint8_t chanelSwitch = 1;
          static unsigned long lastSwitchTime = millis();
          const unsigned long channelSwitchInterval = 500;  
          xSemaphoreTake(wifiMutex, portMAX_DELAY);
          esp_wifi_set_channel(answerrr, WIFI_SECOND_CHAN_NONE);
          wifion();  // Ustawienie trybu WiFi na stację
          esp_wifi_set_promiscuous(true);  // Włączenie trybu promiskuitywnego
          esp_wifi_set_promiscuous_rx_cb(client_sniff_promiscuous_rx_cb);
          xSemaphoreGive(wifiMutex);
          logMessage("Started mac sniffing!");
          canvas_main.clear();
          uint8_t line;
          while(true){
            M5.update();
            M5.update();
#ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            if(keyboard_changed){Sound(10000, 100, sound);}
#else
            inputManager::update();
#endif
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
#ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            for(auto i : status.word){
              if(i=='`'){
              xSemaphoreTake(wifiMutex, portMAX_DELAY);
              esp_wifi_set_promiscuous(false);
              clearClients();
              logMessage("User stopped mac sniffing");
              wifion();
              xSemaphoreGive(wifiMutex);
              menuID = 2;
              return;
              }
            }
#else
            inputManager::update();
            if(inputManager::isButtonBLongPressed()){
              xSemaphoreTake(wifiMutex, portMAX_DELAY);
              esp_wifi_set_promiscuous(false);
              clearClients();
              logMessage("User stopped mac sniffing");
              wifion();
              xSemaphoreGive(wifiMutex);
              menuID = 2;
              return;
            }
#endif

            if (millis() - lastSwitchTime > channelSwitchInterval && !answerrr) {
              chanelSwitch++;
              if (chanelSwitch > 12) {
                chanelSwitch = 1;  // Loop back to channel 1
              }
              lastSwitchTime = millis();
              xSemaphoreTake(wifiMutex, portMAX_DELAY);
              esp_wifi_set_channel(chanelSwitch , WIFI_SECOND_CHAN_NONE);
              xSemaphoreGive(wifiMutex);
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
#ifndef BUTTON_ONLY_INPUT
            M5Cardputer.update();
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            if(keyboard_changed){Sound(10000, 100, sound);}
            keyboard_changed = M5Cardputer.Keyboard.isChange();
            Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
            for(auto i : status.word){
              if(i=='`'){
                menuID = 2;
                wifion();
                SnifferEnd();
                return;
              }
            }
#else
            inputManager::update();
            if(inputManager::isButtonBLongPressed()){
              menuID = 2;
              wifion();
              SnifferEnd();
              return;
            }
#endif
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
          menuID = 2;
          return;
        }
      }
      menuID = 2;
      return;
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
        menuID = 9;
        return;
      }
      if(new_wiggle_api_key.length() <10){
        drawInfoBox("Error", "Key too short", "Operation abort", true, false);
        menuID = 9;
        return;
      }
      wiggle_api_key = new_wiggle_api_key;
      if(saveSettings()){
        drawInfoBox("Succes", "Wiggle API key", "was changed", true, false);
        menuID = 9;
        return;
      }
      else{
        drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        menuID =9;
        return;
      }
      menuID = 9;
      return;
    }
    if(appID == 26){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To send stats!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Stats send abort", true, false);
          menuID = 8;
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
          menuID = 9;
          return;
        }
        else{
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
          menuID = 9;
          return;
        }
      }
      menuID = 9;
      return;
    }
    if(appID == 28){
      drawInfoBox("Info", "Please wait", "", false, false);
      if(!(WiFi.status() == WL_CONNECTED)){
        drawInfoBox("Info", "Network connection needed", "To upload!", false, false);
        delay(3000);
        runApp(43);
        if(WiFi.status() != WL_CONNECTED){
          drawInfoBox("ERROR!", "No network connection", "Upload abort", true, false);
          menuID = 9;
          return;
        }
      }
      drawInfoBox("Info", "Next, select file", "to upload", true, false);
      String file = sdmanager::selectFile(".csv");
      if(file == ""){
        drawInfoBox("Error", "No file selected", "Operation abort", true, false);
        menuID = 9; 
        return;
      }
      drawInfoBox("Uploading", "Please wait", "This may take some time...", false, false);
      int statusCode = 0;
      int statusToCode;
      if(uploadToWigle(wiggle_api_key, file.c_str(), &statusCode)){
        drawInfoBox("Succes", "File uploaded", "To wigle.net", false, false);
        delay(2000);
        statusToCode = statusCode;
      }
      else{
        statusToCode = statusCode;
        drawInfoBox("ERROR!", "Upload failed!", "Status code: " + String(statusToCode), true, false);
        menuID = 9;
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
      menuID = 9;
      return;
    }
    if(appID == 29){
      // Toggle connect to WiFi on startup
      String opts[] = {"Off","On"};
      uint8_t initial = connectWiFiOnStartup ? 1 : 0;
      uint8_t choice = drawMultiChoice("Connect WiFi on boot?", opts, 2, 6, initial);
      connectWiFiOnStartup = (choice == 1);
      if(saveSettings()){
        drawInfoBox("Saved", "Connect on startup updated", "", true, false);
      } else {
        drawInfoBox("ERROR", "Failed to save setting", "Check SD card", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 30){
      // GPS GPIO pins
      drawHintBox("Deafult pinout only works with LORA cap on cardputer adv. For grove connector you'll need to configure custom ones", 16);
      String options[] = {"Use default pins", "Set custom pins"};
      int initial = useCustomGPSPins ? 1 : 0;
      int res = drawMultiChoice("GPS pins", options, 2, 6, initial);
      if(res == 0){
        useCustomGPSPins = false;
        if(saveSettings()) drawInfoBox("Saved", "Using default GPS pins", "", true, false);
      } else if(res == 1){
        // set custom pins - prefill with current pins
        String txs = userInput("GPS TX Pin", "Enter TX pin number", 3);
        String rxs = userInput("GPS RX Pin", "Enter RX pin number", 3);
        if(txs.length() && rxs.length()){
          gpsTx = txs.toInt();
          gpsRx = rxs.toInt();
          useCustomGPSPins = true;
          if(saveSettings()) drawInfoBox("Saved", "Custom GPS pins set", "", true, false);
        }
      }
      menuID = 6;
      return;
    }
    if(appID == 31){
      // Log GPS data after handshake
      String menu[] = {"Off","On"};
      uint8_t initial = getLocationAfterPwn ? 1 : 0;
      uint8_t choice = drawMultiChoice("Log GPS data after handshake", menu, 2, 6, initial);
      getLocationAfterPwn = (choice == 1);
      if(saveSettings()){
        drawInfoBox("Saved", "Setting updated", "", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 37){
      // GPS Baud Rate
      String menu[] = {"9600", "19200", "38400", "57600", "115200"};
      uint32_t baudRates[] = {9600, 19200, 38400, 57600, 115200};
      int initial = 4; // Default to 115200
      for(int i = 0; i < 5; i++){
        if(baudRates[i] == gpsBaudRate){
          initial = i;
          break;
        }
      }
      int choice = drawMultiChoice("GPS Baud Rate", menu, 5, 6, initial);
      gpsBaudRate = baudRates[choice];
      if(saveSettings()){
        drawInfoBox("Saved", "GPS Baud Rate: " + String(gpsBaudRate), "", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 32){
      // Manage saved networks
      // build menu of saved networks
      size_t n = savedNetworks.size();
      std::vector<String> vlist;
      for(size_t i=0;i<n;i++){
        vlist.push_back(savedNetworks[i].ssid + (savedNetworks[i].connectOnStart?" (Auto)":""));
      }
      vlist.push_back("Add new network");
      vlist.push_back("Back");
      String *arr = new String[vlist.size()];
      for(size_t i=0;i<vlist.size(); ++i) arr[i] = vlist[i];
      int8_t choice = drawMultiChoice("Saved networks", arr, vlist.size(), 0, 0);
      delete[] arr;
      if(choice == -1 || choice == n+1){ menuID =6; return; }
      else if(choice == n){
        // Add new network
        drawInfoBox("Scanning...","Scanning for networks","Please wait", false, false);
        int numNetworks = WiFi.scanNetworks();
        if(numNetworks == 0){ drawInfoBox("Info","No networks found","", true, false); menuID=6; return; }
        std::vector<String> wifinets;
        for (int i = 0; i < numNetworks; i++) wifinets.push_back(WiFi.SSID(i));
        String *warr = new String[wifinets.size()];
        for (size_t i = 0; i < wifinets.size(); ++i) warr[i] = wifinets[i];
        int idx = drawMultiChoice("Select network:", warr, wifinets.size(), 6, 3);
        delete[] warr;
        if(idx == -1){ menuID = 6; return; }
        String pass = userInput("Password", "Enter wifi password", 30);
        if(addSavedNetwork(wifinets[idx], pass, false)) drawInfoBox("Saved", "Network added", "", true, false);
        else drawInfoBox("ERROR", "Failed to save network", "", true, false);
        menuID = 6; return;
      } else {
        // selected existing network - options: connect, remove, toggle auto
        size_t idx = choice;
        String opts[] = {"Connect","Toggle Auto","Remove","Back"};
        int sel = drawMultiChoice("Action", opts, 4, 0, 0);
        if(sel == 0){
          // Connect
          String pass = savedNetworks[idx].pass;
          if(pass.length() == 0){
            pass = userInput("Password", "Enter wifi password", 30);
          }
          WiFi.begin(savedNetworks[idx].ssid.c_str(), pass.c_str());
          unsigned long start = millis();
          while(millis() - start < 10000 && WiFi.status() != WL_CONNECTED) delay(500);
          if(WiFi.status() == WL_CONNECTED){ drawInfoBox("Connected","Connected to " + savedNetworks[idx].ssid, "", true, false); }
          else drawInfoBox("Error","Connection failed","", true, false);
        }
        else if(sel == 1){
          bool newVal = !savedNetworks[idx].connectOnStart;
          setSavedNetworkConnectOnStart(idx, newVal);
          drawInfoBox("Saved","Auto connect toggled", "", true, false);
        }
        else if(sel == 2){
          removeSavedNetwork(idx);
          drawInfoBox("Removed","Network removed", "", true, false);
        }
      }
      menuID = 6; return;
    }
    if(appID == 99){
      debounceDelay();
      drawMenuList(devtools_menu, 99, 9);
      return;
    }
    if(appID == 100){
      //pin protection
      String dev_mode_pin = "2147";
      if(userInput("Dev Mode PIN", "Enter PIN to toggle dev mode", 10) != dev_mode_pin){
        drawInfoBox("Error", "Wrong PIN", "First learn how to code!!!", true, false);
        return;
      }

      dev_mode = !dev_mode;
      drawInfoBox("Dev Mode", dev_mode?"Enabled":"Disabled", "", true, false);
      saveSettings();
      menuID = 99;
      return;
    }
    if(appID == 101){
      // Set global var: pick from list for safety
      String varList[] = {"hostname","bg_color","tx_color","sound","brightness","pwnagothiMode","sd_logging","skip_eapol_check","advertisePwngrid","pwned_ap","dev_mode","toogle_pwnagothi_with_gpio0","lite_mode_wpa_sec_sync_on_startup","sync_pwned_on_boot","skip_file_manager_checks_in_dev"};
      String picked = "";
      int choice = drawMultiChoice("Set variable", varList, 15, 99, 0);
      if(choice == -1) return;
      if (choice >= 0 && choice < 14) {
        picked = varList[choice];
        String val = userInput("Set var", "New value for " + picked + ":", 128);
        if(val.length()){
          // known variables mapping
          if(picked == "hostname") hostname = val;
          else if(picked == "bg_color") { bg_color = val; initColorSettings(); }
          else if(picked == "tx_color") { tx_color = val; initColorSettings(); }
          else if(picked == "sound") sound = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "brightness") brightness = val.toInt();
          else if(picked == "pwnagothiMode") pwnagothiMode = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "sd_logging") sd_logging = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "skip_eapol_check") skip_eapol_check = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "advertisePwngrid") advertisePwngrid = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "pwned_ap") pwned_ap = (uint16_t)val.toInt();
          else if(picked == "dev_mode") dev_mode = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "toogle_pwnagothi_with_gpio0") toogle_pwnagothi_with_gpio0 = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "lite_mode_wpa_sec_sync_on_startup") lite_mode_wpa_sec_sync_on_startup = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "sync_pwned_on_boot") sync_pwned_on_boot = (val == "1" || val.equalsIgnoreCase("true"));
          else if(picked == "skip_file_manager_checks_in_dev") skip_file_manager_checks_in_dev = (val == "1" || val.equalsIgnoreCase("true"));
          else {
            drawInfoBox("Unknown variable", picked, "Not supported by setter.", true, true);
            return;
          }
          saveSettings();
          drawInfoBox("OK", "Set " + picked, val, true, false);
        }
      }
      return;
    }
    if(appID == 102){
      int id = getNumberfromUser("Run app","ID to run", 255);
      if(id > 0) runApp((uint8_t)id);
      return;
    }
    if(appID == 103){
      // color picker for background
      String newColor = colorPickerUI(false, bg_color);
      if(newColor.length()) { bg_color = newColor; initColorSettings(); saveSettings(); }
      return;
    }
    if(appID == 104){
      // color picker for text
      String newColor = colorPickerUI(true, tx_color);
      if(newColor.length()) { tx_color = newColor; initColorSettings(); saveSettings(); }
      return;
    }
    if(appID == 105){
      coords_overlay = !coords_overlay;
      drawInfoBox("Coords Overlay", coords_overlay?"Enabled":"Disabled", "", true, false);
      saveSettings();
      return;
    }
    if(appID == 106){
      serial_overlay = !serial_overlay;
      loggerSetOverlayEnabled(serial_overlay);
      drawInfoBox("Serial Overlay", serial_overlay?"Enabled":"Disabled", "", true, false);
      saveSettings();
      return;
    }
    if(appID == 107){
      skip_file_manager_checks_in_dev = !skip_file_manager_checks_in_dev;
      drawInfoBox("Skip File Checks", skip_file_manager_checks_in_dev?"Enabled":"Disabled", "", true, false);
      saveSettings();
      return;
    }
    if(appID == 109){
      if(!dev_mode){ drawInfoBox("Dev only", "Enable dev mode to run.", "", true, false); return; }
      drawInfoBox("Speed scan", "Running speed test", "Please wait...", false, false);
      speedScanTestAndPrintResults();
      drawInfoBox("Done", "Speed scan finished", "", true, false);
      return;
    }
    if(appID == 110){
      if(!dev_mode){ drawInfoBox("Dev only", "Enable dev mode to run.", "", true, false); return; }
      coordsPickerUI();
      return;
    }
    if(appID == 111){
      if(!dev_mode){ drawInfoBox("Dev only", "Enable dev mode to run.", "", true, false); return; }
      drawInfoBox("Crash test", "This will crash the device", "Press Enter to continue", false, false);
      delay(1000);
      speedScanTestAndPrintResults();
      esp_will_beg_for_its_life();
      return;
    }
    if(appID == 112){
      // Mood Font Tester: enumerate faces from /moods/faces.txt and display them using the custom mood font/size
      File f = FSYS.open("/moods/faces.txt", FILE_READ);
      if(!f){
        drawInfoBox("Error", "faces.txt not found", "Ensure /moods/faces.txt exists", true, false);
        return;
      }
      std::vector<String> faces;
      while(f.available()){
        String line = f.readStringUntil('\n');
        line.trim();
        if(line.length() == 0) continue;
        if(line.startsWith("#")) continue;
        if(line.startsWith("[") && line.endsWith("]")) continue;
        faces.push_back(line);
      }
      f.close();
      if(faces.empty()){
        drawInfoBox("Info", "No faces found in /moods/faces.txt", "Add faces and retry", true, false);
        return;
      }
      int idx = 0;
      debounceDelay();
      while(true){
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.setColor(tx_color_rgb565);
        canvas_main.setTextDatum(middle_center);
        // load custom font used in drawMood for faces
        if(FSYS.exists("/fonts/big.vlw")){
          canvas_main.loadFont(SD, "/fonts/big.vlw");
        }
        canvas_main.setTextSize(0.35);
        canvas_main.drawString(faces[idx], canvas_center_x, canvas_h/2);
        if(FSYS.exists("/fonts/big.vlw")) canvas_main.unloadFont();
        // show index
        canvas_main.setTextDatum(top_left);
        canvas_main.setTextSize(1);
        canvas_main.drawString(String(idx+1) + "/" + String(faces.size()), 2, 2);
        pushAll();
        M5.update();
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        Keyboard_Class::KeysState ks = M5Cardputer.Keyboard.keysState();
        if(ks.fn){
          for(auto c : ks.word){ if(c == '`'){ debounceDelay(); return; } }
        }
        for(auto c : ks.word){
          if(c == '.') { idx = (idx + 1) % faces.size(); drawInfoBox("", "Loading...", "", false, false); }
          else if(c == ';') { idx = (idx + faces.size() - 1) % faces.size(); drawInfoBox("", "Loading...", "", false, false);}
          else if(c == KEY_ENTER) { menuID = 99; debounceDelay(); return; }
        }
#else
        inputManager::update();
        if(inputManager::isButtonBPressed()) {
          idx = (idx + 1) % faces.size();
          drawInfoBox("", "Loading...", "", false, false);
        }
        if(inputManager::isButtonAPressed()) {
          menuID = 99;
          debounceDelay();
          return;
        }
        if(inputManager::isButtonBLongPressed()) {
          debounceDelay();
          return;
        }
#endif
        delay(80);
      }
    }
    if(appID == 108){
      // Freeform setter: type var name and value
      String varName = userInput("Set var (free)", "Var name (case-sensitive):", 64);
      if(varName.length()){
        String val = userInput("Set var (free)", "New value for " + varName + ":", 128);
        if(val.length()){
          // try best-effort mapping for common types
          if(varName == "hostname") hostname = val;
          else if(varName == "bg_color") { bg_color = val; initColorSettings(); }
          else if(varName == "tx_color") { tx_color = val; initColorSettings(); }
          else if(varName == "sound") sound = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "brightness") brightness = val.toInt();
          else if(varName == "pwnagothiMode") pwnagothiMode = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "sd_logging") sd_logging = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "skip_eapol_check") skip_eapol_check = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "advertisePwngrid") advertisePwngrid = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "pwned_ap") pwned_ap = (uint16_t)val.toInt();
          else if(varName == "dev_mode") dev_mode = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "toogle_pwnagothi_with_gpio0") toogle_pwnagothi_with_gpio0 = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "lite_mode_wpa_sec_sync_on_startup") lite_mode_wpa_sec_sync_on_startup = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "sync_pwned_on_boot") sync_pwned_on_boot = (val == "1" || val.equalsIgnoreCase("true"));
          else if(varName == "skip_file_manager_checks_in_dev") skip_file_manager_checks_in_dev = (val == "1" || val.equalsIgnoreCase("true"));
          else {
            drawInfoBox("Unknown variable", varName, "Not supported by fallback.", true, true);
            return;
          }
          saveSettings();
          drawInfoBox("OK", "Set " + varName, val, true, false);
        }
      }
      return;
    }
    if(appID == 33){
      String opts[] = {"Off","On"};
      uint8_t initial = checkUpdatesAtNetworkStart ? 1 : 0;
      uint8_t choice = drawMultiChoice("Check updates on network start?", opts, 2, 6, initial);
      checkUpdatesAtNetworkStart = (choice == 1);
      if(saveSettings()) drawInfoBox("Saved","Setting updated", "", true, false);
      menuID = 6; return;
    }
    if(appID == 34){
      //randomise mac option menu
      String menu[] = {"On", "Off", "Back"};
      uint8_t answer = drawMultiChoice("Randomise MAC", menu, 3, 6, 0);
      if(answer == 0){
        randomise_mac_at_boot = true;
        saveSettings();
        drawInfoBox("Info", "Randomise MAC", "Enabled", true, false);
      }
      else if(answer == 1){
        randomise_mac_at_boot = false;
        saveSettings();
        drawInfoBox("Info", "Randomise MAC", "Disabled", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 35){
      // setting "add_new_units_to_friends"
      String options[] = {"Off", "On", "Back"};
      uint8_t answer = drawMultiChoice("Add new units to friends", options, 3, 6, 0);
      if(answer == 0){
        add_new_units_to_friends = false;
        saveSettings();
        drawInfoBox("Info", "Add new units to friends", "Disabled", true, false);
      }
      else if(answer == 1){
        add_new_units_to_friends = true;
        saveSettings();
        drawInfoBox("Info", "Add new units to friends", "Enabled", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 36){
      {
        bool answear = drawQuestionBox("CONFIRMATION", "Operate only if you ", "have premision!");
        if(answear){
          menuID = 5;
          drawHintBox("Stealth mode mimics wifi router, kicking only 1 client at once.\nIn the other hand, normal mode kicks all connected clients and that grately impoves capture.", 15);
          String sub_menu[] = {"Stealth (legacy)", "Normal"};
          int8_t modeChoice = drawMultiChoice("Select mode:", sub_menu, 2, 2, 2);
          debounceDelay();
          if(modeChoice == -1){
            menuID = 5;
            return;
          }
          if(modeChoice==0){
            stealth_mode = true;
          }
          else{
            stealth_mode = false;
          }
          drawInfoBox("INITIALIZING", "Pwnagothi mode initialization", "please wait...", false, false);
          menuID = 5;
          if(pwnagothiBegin()){
            pwnagothiMode = true;
            menuID = 0;
            return;
          }
          else{
            drawInfoBox("ERROR", "Pwnagothi init failed!", "", true, false);
            pwnagothiMode = false;
          }
          menuID = 5;
          return;
        }
      }
      menuID = 5;
      return;
    }
    if(appID == 37){}
    if(appID == 38){
      editWhitelist();
      menuID = 5;
      return;
    }
    if(appID == 39){
      drawInfoBox("Info", "Reading SD card...", "Please wait", false, false);
      File root = FSYS.open("/handshake");
      if (!root || !root.isDirectory()) {
        drawInfoBox("Error", "Cannot open \"/handshake\" folder.", "Check SD card!", true, true);
        menuID = 5;
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
        menuID = 5;
        return;
      }
      drawMultiChoiceLonger("Handshakes:", fileList, fileCount, 5, 3);
      
      menuID = 5;
      return;
    }
    if(appID == 40){
      String name = userInput("New value", "Change Hostname to:", 18);
      if(name != ""){
        hostname = name;
        if(saveSettings()){
          menuID = 6;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
        menuID = 6;
        return;
      }
      drawInfoBox("Name invalid", "Null inputed,", "operation abort", true, false);
      menuID = 6;
      return;
    }
    if(appID == 41){
      brightnessPicker();
      if(saveSettings()){
        menuID = 6;
        return;
      }
      else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      menuID = 6;
      return;
    }
    if(appID == 42){
      while(true){
        String opt0 = String("Keyboard sounds: ") + (sound ? "ON" : "OFF");
        String opt1 = String("Event sounds: ") + (pwnagotchi.sound_on_events ? "ON" : "OFF");
        String menu[] = { opt0, opt1, "Back" };
        debounceDelay();
        int8_t choice = drawMultiChoice("Sound settings", menu, 3, 6, 2);
        if(choice == -1 || choice == 2) break;
        if(choice == 0){
          sound = !sound;
          if(saveSettings()) drawInfoBox("Saved", "Keyboard sounds updated", "", true, false);
          else drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
        else if(choice == 1){
          pwnagotchi.sound_on_events = !pwnagotchi.sound_on_events;
          if(savePersonality()) drawInfoBox("Saved", "Event sounds updated", "", true, false);
          else drawInfoBox("ERROR", "Save personality failed!", "Check SD Card", true, false);
        }
      }
      menuID = 6;
      return;
    }
    if(appID == 122){
      // Toggle sync pwned on boot
      String menu[] = {"On", "Off", "Back"};
      debounceDelay();
      uint8_t choice = drawMultiChoice("Sync pwned on boot?", menu, 3, 6, sync_pwned_on_boot ? 0 : 1);
      if(choice == 0){ sync_pwned_on_boot = true; if(saveSettings()) drawInfoBox("Saved","Will sync pwned on boot", "", true, false); else drawInfoBox("ERROR","Save failed","", true, false);} 
      else if(choice == 1){ sync_pwned_on_boot = false; if(saveSettings()) drawInfoBox("Saved","Will not sync pwned on boot", "", true, false); else drawInfoBox("ERROR","Save failed","", true, false);} 
      menuID = 6; return;
    }
    if(appID == 43){
      if((WiFi.status() == WL_CONNECTED)){
        WiFi.disconnect();
        wifion();
        drawInfoBox("Info", "WiFi disconnected", "", true, false);
        menuID = 6;
        return;
      }
      wifion();
      drawInfoBox("Scanning...", "Scanning for networks...", "Please wait", false, false);
      int numNetworks = WiFi.scanNetworks();
      String wifinets[50];
      if (numNetworks == 0) {
        drawInfoBox("Info", "No wifi nearby", "Abort.", true, false);
        menuID = 6;
        return;
      }
      else {
        // Przechodzimy przez wszystkie znalezione sieci i zapisujemy ich nazwy w liście
        for (int i = 0; i < numNetworks; i++) {
          String ssid = WiFi.SSID(i);
          logMessage(WiFi.SSID(i) + " =? " + savedApSSID);
          // attempt any saved network that matches this SSID
          for(size_t si = 0; si < savedNetworks.size(); ++si){
            if(WiFi.SSID(i) == (savedNetworks[si].ssid)){
              WiFi.begin(savedNetworks[si].ssid.c_str(), savedNetworks[si].pass.c_str());
              uint8_t counter = 0;
              while (counter<=10 && !WiFi.isConnected()) {
                delay(1000);
                drawInfoBox("Connecting", "Connecting to " + savedNetworks[si].ssid, "You'll soon be redirected ", false, false);
                counter++;
              }
              counter = 0;
              if(WiFi.isConnected()){
                drawInfoBox("Connected", "Connected succesfully to", String(WiFi.SSID()) , true, false);
                menuID = 6;
                return;
              }
            }
          }
          wifinets[i] = String(ssid);
          logMessage(wifinets[i]);
        }
      }
      wifinets[numNetworks] = "Rescan";
      int8_t wifisel = drawMultiChoice("Select WIFI network:", wifinets, numNetworks + 1, 6, 3);
      if(wifisel == -1){
        menuID = 6;
        return;
      }
      if(wifisel == numNetworks){
        runApp(43);
        menuID = 6;
        return;
      }
      String password = userInput("Password", "Enter wifi password" , 30);
      if(password.length() < 3){
        menuID = 6;
        return;
      }
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
        // Ensure network is saved (and flag it as connect-on-start by default)
        addSavedNetwork(savedApSSID, savedAPPass, true);
        if(saveSettings()){
          menuID = 6;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else{
        drawInfoBox("Error", "Connection failed", "Maybe wrong password...", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 44){
      if(limitFeatures){
        drawInfoBox("ERROR", "Update disabled. Please use M5Burner version or update via your launcher.", "", true, false);
        menuID = 6;
        return;
      }
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
        drawInfoBox("ERROR!", "Update failed!", "Try again later", true, false);
      }
      menuID = 6;
      return;
    }
    if(appID == 45){
      drawHintBox("Enjoy the project? Consider donating at https://ko-fi.com/Devsur", 18);
      drawInfoBox("M5Gotchi", "v" + String(CURRENT_VERSION) + " by Devsur11  ", "www.github.com/Devsur11/M5Gotchi ", true, false);
      menuID = 6;
      return;
    }
    if(appID == 46){
      M5.Display.fillScreen(tx_color_rgb565);
      esp_deep_sleep_start(); 
      menuID = 6;
      return;
    }
    if(appID == 47){}
    if(appID == 48){
      String options[] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("Pwnagothi on boot", options, 3, 6, 0);
      if (choice == 0) {
        pwnagothiModeEnabled = true;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwnagothi will run", "on boot", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        pwnagothiModeEnabled = false;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwnagothi will NOT run", "on boot", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 49){
      String options[] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("EAPOL integrity check", options, 3, 6, 0);
      if (choice == 0) {
        skip_eapol_check = false;
        if (saveSettings()) {
          drawInfoBox("Success", "EAPOL check enabled", "", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        skip_eapol_check = true;
        if (saveSettings()) {
          drawInfoBox("Success", "EAPOL check disabled", "", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID =6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 50){
      themeMenu();
    }
    if(appID == 51){
      bool confirm = drawQuestionBox("Factory Reset", "Delete all config data?", "", "Press 'y' to confirm, 'n' to cancel");
      if (!confirm) {
        menuID = 6;
        return;
      }
      drawInfoBox("Factory Reset", "Deleting config data...", "", false, false);
      runApp(15);
      if (true) {
        FSYS.remove(NEW_CONFIG_FILE);
        FSYS.remove("/uploaded.json");
        FSYS.remove("/cracked.json");
        FSYS.remove(PERSONALITY_FILE);
        FSYS.remove("/moods/faces.txt");
        FSYS.remove("/moods/texts.txt");
        FSYS.rmdir("/moods");
        FSYS.rmdir("/temp");
        //recursevely delete "fonts" "wardrive" "handshake" folders
        FSYS.remove("/fonts/big.vlw");
        FSYS.remove("/fonts/small.vlw");
        FSYS.rmdir("/fonts");
        File wardriveDir = FSYS.open("/wardrive");
        if (wardriveDir && wardriveDir.isDirectory()) {
          File wardriveFile = wardriveDir.openNextFile();
          while (wardriveFile) {
            FSYS.remove(String(wardriveFile.name()).c_str());
            wardriveFile = wardriveDir.openNextFile();
          }
          wardriveDir.close();
          FSYS.rmdir("/wardrive");
        }
        File handshakeDir = FSYS.open("/handshake");
        if (handshakeDir && handshakeDir.isDirectory()) {
          File handshakeFile = handshakeDir.openNextFile();
          while (handshakeFile) {
            logMessage("Deleting handshake file: /handshake/" + String(handshakeFile.name()));
            if (!handshakeFile.isDirectory()) {
              FSYS.remove(String(handshakeFile.path()));
            }
            handshakeFile = handshakeDir.openNextFile();
          }
          handshakeDir.close();
          FSYS.rmdir("/handshake");
        }


        drawInfoBox("Success", "Data deleted", "Restarting...", false, false);
        delay(1000);
        ESP.restart();
      } else {
        drawInfoBox("Error", "Data files not found", "Nothing to delete", true, false);
        menuID = 6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 52){
      if(WiFi.status() == WL_CONNECTED){
        if(wpa_sec_api_key.equals("")){
          drawInfoBox("Error", "No API key set", "Set it first!", true, false);
          menuID = 7;
          return;
        }
        else{
          drawInfoBox("Syncing", "Syncing data with WPASec", "Please wait...", false, false);
          processWpaSec(wpa_sec_api_key.c_str());
          drawInfoBox("Done", "Sync finished", "Press enter to continue", true, false);
          menuID = 7;
          return;
        }
      }
      else{
        drawInfoBox("Error", "No wifi connection", "Connect to wifi in settings!", true, false);
      }
      menuID = 7;
      return;
    }    
    if(appID == 53){
      if(FSYS.exists("/cracked.json")){
        File crackedFile = FSYS.open("/cracked.json", FILE_READ);
        if (!crackedFile) {
          drawInfoBox("Error", "Failed to open cracked.json", "Check SD card!", true, false);
          menuID = 7;
          return;
        }
        crackedFile.close();
        std::vector<CrackedEntry> entries = getCrackedEntries();
        if (entries.empty()) {
          drawInfoBox("Info", "No cracked entries found", "Try syncing", true, false);
          crackedFile.close();
          menuID = 7;
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
            menuID = 7;
            return;
          }
          String detailInfo = "Password: " + entries[selection].password;
          String detailInfo2 = "Bssid: " + entries[selection].bssid;
          drawInfoBox(entries[selection].ssid, detailInfo, detailInfo2, true , false);
          M5.update();
#ifndef BUTTON_ONLY_INPUT
          M5Cardputer.update();
          Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
          if(M5Cardputer.Keyboard.isChange()){Sound(10000, 100, sound);}
#else
          inputManager::update();
#endif
        }
      }
      else{
        drawInfoBox("Error", "List is empty", "Try sync first!", true, false);
      }
      menuID = 7;
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
          menuID = 7;
          return;
        }
        if(saveSettings()){
          drawInfoBox("Success", "API key saved", "", true, false);
          menuID = 7;
          return;
        }
        else{
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
          menuID = 7;
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
          menuID = 7;
          return;
        }
        else{
          if(saveSettings()){
            drawInfoBox("Success", "API key saved", "", true, false);
            menuID = 7;
            return;
          }
          else{
            drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
            menuID = 7;
            return;
          }
        }
      }
      else {
        menuID = 7;
        return;
      }
      menuID = 7;
      return;
    }
    if(appID == 55){
      (wpa_sec_api_key.length()<10)?drawHintBox("To see all the available WPAsec commands, you'll need to input your API key.\n Get it from https://wpa-sec.stanev.org/?get-key", 12):void();
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
        menuID = 5;
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
          "GPS fix interval" + String(" (ms): ") + String(pwnagotchi.gps_fix_timeout),
          "Sound on events" + String(pwnagotchi.sound_on_events ? " (y)" : " (n)"),
          "Deauth on" + String(pwnagotchi.deauth_on ? " (y)" : " (n)"),
          "Add to whitelist on success" + String(pwnagotchi.add_to_whitelist_on_success ? " (y)" : " (n)"),
          "Add to whitelist on fail" + String(pwnagotchi.add_to_whitelist_on_fail ? " (y)" : " (n)"),
          "Activate sniffer on deauth" + String(pwnagotchi.activate_sniffer_on_deauth ? " (y)" : " (n)"),
          "Back"
        };
      
        int8_t choice = drawMultiChoiceLonger("Personality settings", personality_options, 21, 6, 4);
        if(choice == 20 || choice == -1){
          savePersonality();
          menuID = 5;
          return;
        }
        else if(choice >= 15){
          bool valueToSet = getBoolInput(personality_options[choice], "Press t or f, then ENTER", false);
          logMessage("Value to set: " + String(valueToSet ? "true" : "false") + "to " + personality_options[choice]);
          switch (choice) {
            case 15:
              pwnagotchi.sound_on_events = valueToSet;
              break;
            case 16:
              pwnagotchi.deauth_on = valueToSet;
              break;
            case 17:
              pwnagotchi.add_to_whitelist_on_success = valueToSet;
              break;
            case 18:
              pwnagotchi.add_to_whitelist_on_fail = valueToSet;
              break;
            case 19:
              pwnagotchi.activate_sniffer_on_deauth = valueToSet;
              break;
            default:
              break;
          }
          savePersonality();
        }
        else{
          int16_t valueToSet = getNumberfromUser(personality_options[choice], "Enter new value", 60000);
          logMessage("Value to set: " + String(valueToSet) + " to " + personality_options[choice]);
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
            case 14:
              pwnagotchi.gps_fix_timeout = valueToSet;
              break;
            default:
              break;
          }
          savePersonality();
          menuID = 5;
        }
      }
      menuID = 5;
      return;
      }
    if(appID == 58){
      String menuu[] = {"Yes", "No", "Back"};
      int8_t choice = drawMultiChoice("Log to sd card?", menuu, 3, 6, 0);
      if(choice == 0){
        sd_logging = true;
        if(saveSettings()){
          drawInfoBox("Success", "Logging to SD card enabled", "", true, false);
          menuID = 6;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else if(choice == 1){
        sd_logging = false;
        if(saveSettings()){
          drawInfoBox("Success", "Logging to SD card disabled", "", true, false);
          menuID = 6;
          return;
        }
        else{drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);}
      }
      else{
        menuID = 6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 59){
      #ifdef M5STICKS3_ENV
        drawInfoBox("Error", "GPIO0 toggle not supported on M5StickS3", "", true, false);
        menuID = 6;
        return;
      #endif
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
        menuID = 6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 60){
      String mmenu[3] = {"Enable", "Disable", "Back"};
      int choice = drawMultiChoice("Advertise pwngrid", mmenu, 3, 6, 0);
      if (choice == 0) {
        advertisePwngrid = true;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwngrid advertising enabled", "", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else if (choice == 1) {
        advertisePwngrid = false;
        if (saveSettings()) {
          drawInfoBox("Success", "Pwngrid advertising disabled", "", true, false);
          menuID = 6;
          return;
        } else {
          drawInfoBox("ERROR", "Save setting failed!", "Check SD Card", true, false);
        }
      } else {
        menuID = 6;
        return;
      }
      menuID = 6;
      return;
    }
    if(appID == 123){
      #ifdef ENABLE_COREDUMP_LOGGING
        sendCrashReport();
      #else
        drawInfoBox("Error", "Core dump logging is disabled", "Recompile with ENABLE_COREDUMP_LOGGING", true, false);
      #endif
    }
    return;
  }
}
int16_t getNumberfromUser(String tittle, String desc, uint16_t maxNumber){
  uint16_t number = 0;
  appRunning = true;
  debounceDelay();
  
  #ifdef BUTTON_ONLY_INPUT
  // Button-only number input: use a simple digit selector
  uint8_t selected_digit = 0;
  bool selecting = true;
  
  while (selecting) {
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setCursor(5, 10);
    canvas_main.println(tittle + ":");
    canvas_main.setTextDatum(middle_center);
    canvas_main.setTextSize(1);
    
    // Display current number
    canvas_main.setTextSize(2);
    canvas_main.drawString(String(number), canvas_center_x, canvas_h / 3);
    
    // Draw digit selector (0-9)
    canvas_main.setTextSize(1.5);
    int digit_y = canvas_h / 2 + 10;
    
    for (int i = 0; i < 10; i++) {
      int x_pos = canvas_center_x - 40 + (i % 5) * 20;
      int y_pos = digit_y + (i / 5) * 20;
      
      if (i == selected_digit) {
        canvas_main.drawRect(x_pos - 8, y_pos - 8, 16, 16, tx_color_rgb565);
        canvas_main.fillRect(x_pos - 8, y_pos - 8, 16, 16, tx_color_rgb565);
        canvas_main.setTextColor(bg_color_rgb565);
      } else {
        canvas_main.setTextColor(tx_color_rgb565);
      }
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString(String(i), x_pos, y_pos);
      canvas_main.setTextColor(tx_color_rgb565);
    }
    
    // Draw instructions
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString("B:cycle A:add A long:done B long:del", canvas_center_x, canvas_h - 12);
    
    pushAll();
    M5.update();
    
    inputManager::update();
    
    // Button B: cycle through digits
    if (inputManager::isButtonBPressed()) {
      selected_digit = (selected_digit + 1) % 10;
      debounceDelay();
    }
    
    // Button A: add selected digit to number
    if (inputManager::isButtonAPressed()) {
      if (number * 10 + selected_digit <= maxNumber) {
        number = number * 10 + selected_digit;
      }
      debounceDelay();
    }
    
    // Button A long press: confirm and exit
    if (inputManager::isButtonALongPressed()) {
      appRunning = false;
      logMessage("Number input returning: " + String(number));
      selecting = false;
      debounceDelay();
    }
    
    // Button B long press: backspace (remove last digit)
    if (inputManager::isButtonBLongPressed()) {
      if (number > 0) {
        number = number / 10;
      }
      debounceDelay();
    }
  }
  
  return number;
  
  #else
  // Keyboard input version (original behavior)
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
  #endif
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
#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        debounceDelay();
        return defaultValue;
      }
      if(i=='t'){
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
#else
    inputManager::update();
    if(inputManager::isButtonAPressed()) {
      if(inputManager::isButtonBLongPressed()) {
        appRunning = false;
        debounceDelay();
        return defaultValue;
      }
      appRunning = false;
      logMessage("Bool input returning: " + String(toReturn));
      return toReturn;
    }
    if(inputManager::isButtonBPressed()) {
      toReturn = !toReturn;
    }
#endif
  }
}

String userInput(const String &prompt, String desc, int maxLen,  const String &initial){
  debounceDelay();
  String result = initial;
  
  // QWERTY keyboard layout with exact rows
  // Each row is a string of characters
  const char* kb_rows_lower[] = {
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
  };
  
  const char* kb_rows_upper[] = {
    "~!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    "ASDFGHJKL:\"",
    "ZXCVBNM<>?"
  };
  
  const char** kb_rows = kb_rows_lower;
  const char* special_keys = "BKSP ENTR SPC SHFT";
  
  bool shift_active = false;
  uint8_t current_row = 0;
  uint8_t current_col = 0;
  uint8_t max_rows = 4;
  
  auto get_max_col = [&]() -> size_t {
    if (current_row < 4) {
      return strlen(kb_rows[current_row]);
    }
    return (size_t)4; // special keys row
  };
  
  auto get_char = [&]() -> char {
    if (current_row < 4) {
      return kb_rows[current_row][current_col];
    }
    return '\0'; // special key
  };
  
  auto get_special_key = [&]() -> String {
    const char* keys[] = {"BKSP", "ENTR", "SPC", "SHFT"};
    if (current_row == 4 && current_col < 4) {
      return keys[current_col];
    }
    return "";
  };
  
  bool editing = true;
  while (editing) {
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setTextDatum(top_left);
    
    // Draw prompt and input box
    canvas_main.drawString(prompt, 6, 6);
    canvas_main.drawRect(4, 18, 232, 18, tx_color_rgb565);
    
    // Draw typed text
    canvas_main.setTextSize(1);
    canvas_main.setCursor(8, 22);
    if (result.length() == 0) {
      canvas_main.setTextColor(tx_color_rgb565 / 2);
      canvas_main.print("<empty>");
    } else {
      canvas_main.setTextColor(tx_color_rgb565);
      // Truncate if too long
      String display = result;
      if (display.length() > 28) {
        display = "..." + display.substring(display.length() - 25);
      }
      canvas_main.print(display);
    }
    
    // Draw layout indicator
    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    String mode = shift_active ? "UPPER" : "lower";
    canvas_main.drawString("[" + mode + "]", 200, 6);
    
    // Draw keyboard rows
    int start_y = 40;
    int row_height = 13;
    int key_width = 10;
    int key_height = 11;
    float row_offsets[] = {0.0, 0.0, 0.5, 1.5};
    
    for (int row = 0; row < 4; row++) {
      String row_str = kb_rows[row];
      int y = start_y + (row * row_height);
      
      for (int col = 0; col < row_str.length(); col++) {
        int x = 60 + (row_offsets[row] * key_width) + (col * key_width);
        
        // Highlight current selection
        if (row == current_row && col == current_col) {
          canvas_main.fillRect(x - 1, y - 1, key_width, key_height, tx_color_rgb565);
          canvas_main.setTextColor(bg_color_rgb565);
        } else {
          canvas_main.setTextColor(tx_color_rgb565);
        }
        
        char key = row_str[col];
        canvas_main.setCursor(x, y);
        canvas_main.printf("%c", key);
      }
    }
    
    // Draw special keys row
    int special_y = start_y + (4 * row_height);
    String special_keys_arr[] = {"BKSP", "ENTR", "SPC", "SHFT"};
    int special_x_positions[] = {6+40, 50+40, 94+40, 138+40};
    
    for (int i = 0; i < 4; i++) {
      int x = special_x_positions[i];
      int y = special_y;
      
      if (current_row == 4 && current_col == i) {
        canvas_main.fillRect(x - 1, y - 1, 40, key_height, tx_color_rgb565);
        canvas_main.setTextColor(bg_color_rgb565);
      } else {
        canvas_main.setTextColor(tx_color_rgb565);
      }
      
      canvas_main.setTextSize(1);
      canvas_main.drawString(special_keys_arr[i], x, y);
    }
    
    pushAll();
    
    M5.update();
    M5.update();
    
    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    
    if (inputManager::isButtonBPressed()) {
      debounceDelay();
      // Navigate to next key
      current_col++;
      int max_col = get_max_col();
      if (current_col >= max_col) {
        current_col = 0;
      }
    }
    
    if (inputManager::isButtonAPressed()) {
      debounceDelay();
      
      if (current_row < 4) {
        // Regular character key
        char selected = get_char();
        if (result.length() < maxLen) {
          result += selected;
        }
      } else {
        // Special key
        String special = get_special_key();
        if (special == "BKSP") {
          if (result.length() > 0) {
            result = result.substring(0, result.length() - 1);
          }
        } else if (special == "ENTR") {
          editing = false;
        } else if (special == "SPC") {
          if (result.length() < maxLen) {
            result += ' ';
          }
        } else if (special == "SHFT") {
          shift_active = !shift_active;
          kb_rows = shift_active ? kb_rows_upper : kb_rows_lower;
          current_col = 0;
        }
      }
    }
    
    if (inputManager::isButtonBLongPressed()) {
      debounceDelay();
      current_row++;
      if (current_row > 4) {
        current_row = 0;
      }
    }
    
    #else
    Keyboard_Class::KeysState keys = M5Cardputer.Keyboard.keysState();
    if (keys.enter) {
      debounceDelay();
      editing = false;
    } else if (M5Cardputer.Keyboard.isKeyPressed('`')) {
      debounceDelay();
      result = initial;
      editing = false;
    } else if (keys.del) {
      debounceDelay();
      if (result.length() > 0) {
        result = result.substring(0, result.length() - 1);
      }
    } else {
      // Check for printable characters
      for (uint8_t i = 32; i < 127; i++) {
        if (M5Cardputer.Keyboard.isKeyPressed(i)) {
          if (result.length() < maxLen) {
            result += (char)i;
          }
          debounceDelay();
          break;
        }
      }
    }
    #endif
    
    delay(100);
  }
  
  debounceDelay();
  return result;
}

String multiplyChar(char toMultiply, uint8_t literations){
  String toReturn;
  char temp = toMultiply;
  for(uint8_t i = 1; i>=literations; i++){
    toReturn = toReturn + temp;
  }
  return toReturn;
}

void setMID(){prevMID = 99;}

bool drawQuestionBox(String tittle, String info, String info2, String label) {
  appRunning = true;
  debounceDelay();
  bool selected = false;
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.clear(bg_color_rgb565);
    canvas_main.setTextSize(3);
    for(uint8_t size = 0; size<3;size++){
      if(canvas_main.textWidth(tittle) > 240){
        canvas_main.setTextSize(3-size);
      }
      else{
        break;
      }
    }
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString(tittle, canvas_center_x, canvas_h / 4);
    canvas_main.setTextSize(1.2);
    canvas_main.setTextDatum(middle_left);
    canvas_main.setCursor(2, 22 + canvas_main.textLength(tittle, canvas_main.textWidth(tittle)) +17);
    canvas_main.println(info + "\n" + info2);
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(middle_center);
    if(label.length()>5){
      //lets draw 2 squares with yes and no
      //yes
      if(selected){canvas_main.drawRect(canvas_center_x - 80, canvas_h - 30, 60, 15, tx_color_rgb565);}
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString("Yes", canvas_center_x - 50, canvas_h - 22);
      //no
      if(!selected){canvas_main.drawRect(canvas_center_x + 20, canvas_h - 30, 60, 15, tx_color_rgb565);}
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString("No", canvas_center_x + 50, canvas_h - 22);
      canvas_main.drawString( label, canvas_center_x, canvas_h * 0.9);
    }
    else{
      //yes
      if(selected){canvas_main.drawRect(canvas_center_x - 80, canvas_h - 20, 60, 15, tx_color_rgb565);}
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString("Yes", canvas_center_x - 50, canvas_h - 12);
      //no
      if(!selected){canvas_main.drawRect(canvas_center_x + 20, canvas_h - 20, 60, 15, tx_color_rgb565);}
      canvas_main.setTextDatum(middle_center);
      canvas_main.drawString("No", canvas_center_x + 50, canvas_h - 12);
    }

    

    pushAll();
    M5.update();
    M5.update();
    
    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    // Long press B to cancel/back
    if (inputManager::isButtonBLongPressed()) {
        Sound(10000, 100, sound);
        logMessage("No");
        debounceDelay();
        return false;
    }
    // Button B toggles between yes/no
    if (inputManager::isButtonBPressed()) {
        Sound(10000, 100, sound);
        selected = !selected;
        debounceDelay();
    }
    // Button A confirms current selection
    if (inputManager::isButtonAPressed()) {
        Sound(10000, 100, sound);
        if (selected) {
            logMessage("yes");
            debounceDelay();
            return true;
        } else {
            logMessage("No");
            debounceDelay();
            return false;
        }
    }
    #else
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}    
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if(status.enter){
      if(!selected){
        logMessage("No");
        debounceDelay();
        return false;
      }
      else{
        logMessage("yes");
        debounceDelay();
        return true;
      }
    }
    for(auto i : status.word){
      if(i=='`' && status.fn){
        appRunning = false;
        return false;
      }
      else if(i=='y'){
        logMessage("yes");
        debounceDelay();
        return true;
      }
      else if(i=='n'){
        logMessage("No");
        debounceDelay();
        return false;
      }
      else if(i=='/' || i==',' || i==';' || i=='.'){
        selected = !selected;
        debounceDelay();
      }
    }
    #endif
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
  
  static uint32_t marqueeTick = millis();
  static int marqueeOffset = 0;
  const uint32_t MARQUEE_DELAY_MS = 500;
  
  while(true){
    drawTopCanvas();
    drawBottomCanvas();
    M5.update();
    M5.update();  
    
    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    #else
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    #endif

    canvas_main.clear(bg_color_rgb565);
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, PADDING + 1);
    canvas_main.println(tittle);
    canvas_main.setTextSize(2);
    
    uint8_t startIdx = (menu_current_page - 1) * 4;
    if (startIdx >= menuSize) startIdx = 0;
    
    uint8_t remainingItems = (menuSize > startIdx) ? menuSize - startIdx : 0;
    uint8_t itemsToShow = min(remainingItems, (uint8_t)4);
    
    int maxW = canvas_main.width() - 18; // Leave space for scrollbar
    int lineH = 18;
    
    for (uint8_t j = 0; j < itemsToShow && (startIdx + j) < menuSize; j++) {
      uint8_t idx = startIdx + j;
      String itemText = toDraw[idx];
      int y = PADDING + (j * lineH) + 20;
      
      if (tempOpt == idx) {
        // Selected item: draw cursor and marquee text
        canvas_main.drawString(">", 0, y);
        
        int textX = canvas_main.textWidth("> ");
        int spaceW = maxW - textX;
        int fullW = canvas_main.textWidth(itemText);
        
        if (fullW <= spaceW) {
          // Text fits: no marquee needed
          canvas_main.drawString(itemText, textX, y);
          marqueeOffset = 0;
        } else {
          // Text too long: implement marquee
          int maxChars = itemText.length();
          while (maxChars > 0 && 
                 canvas_main.textWidth(itemText.substring(0, maxChars)) > spaceW) {
            maxChars--;
          }
          if (maxChars < 1) maxChars = 1;
          
          int maxOffset = itemText.length() - maxChars;
          if (maxOffset < 0) maxOffset = 0;
          
          uint32_t now = millis();
          if (now - marqueeTick >= MARQUEE_DELAY_MS) {
            marqueeTick = now;
            if (marqueeOffset < maxOffset) {
              marqueeOffset++;
            } else {
              marqueeOffset = 0;
            }
          }
          
          int start = constrain(marqueeOffset, 0, maxOffset);
          int end = start + maxChars;
          if (end > itemText.length()) end = itemText.length();
          
          String slice = itemText.substring(start, end);
          canvas_main.drawString(slice, textX, y);
        }
      } else {
        // Non-selected item: truncate if needed
        if (itemText.length() > 40) {
          itemText = itemText.substring(0, 37) + "...";
        }
        canvas_main.drawString("  " + itemText, 0, y);
      }
    }
    
    int sbX = canvas_main.width() - 6;
    int sbY = PADDING + 20;
    int sbH = 4 * lineH;   // full page height, not itemsToShow

    int totalPages = (menuSize + 3) / 4;
    int currentPage = menu_current_page - 1;

    float scrollRatio = (float)currentPage / max(1, totalPages - 1);
    float barRatio = (float)1 / totalPages;

    int barH = max(6, (int)(sbH * barRatio));
    int barY = sbY + (int)((sbH - barH) * scrollRatio);

    canvas_main.fillRect(sbX - 5, sbY, 20, sbH, bg_color_rgb565);
    canvas_main.fillRect(sbX - 2, barY, 4, barH, tx_color_rgb565);
    
    #ifdef BUTTON_ONLY_INPUT
    // Draw button help text for button-only mode
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(bottom_left);
    canvas_main.drawString("A:Select  B:Back", 2, canvas_main.height() - 2);
    #endif

    pushAll();

    #ifdef BUTTON_ONLY_INPUT
    // Button-based navigation: short B = next, short A = select, long B = back/exit
    inputManager::update();
    if (inputManager::isButtonBLongPressed()) {
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return -1;
    }

    if (inputManager::isButtonBPressed()) {
      // Navigate to next item (down)
      if (menu_current_opt < menu_len - 1) {
        menu_current_opt++;
        tempOpt++;
      } else {
        // Wrap around to first item
        menu_current_page = 1;
        menu_current_opt = 0;
        tempOpt = 0;
      }
      marqueeOffset = 0;
      marqueeTick = millis();
      Sound(10000, 100, sound);
      debounceDelay();
    }
    #else
    // Keyboard-based navigation
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
      marqueeOffset = 0;
      marqueeTick = millis();
      debounceDelay();
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
      marqueeOffset = 0;
      marqueeTick = millis();
      debounceDelay();
    }
    #endif
    
    if (!singlePage) {
      menu_current_page = (menu_current_opt / 4) + 1;
    }
    
    #ifdef BUTTON_ONLY_INPUT
    if (inputManager::isButtonAPressed()) {
      Sound(10000, 100, sound);
      menu_current_opt = tempOpt;
      menuID = prevMenuID;
      debounceDelay();
      return tempOpt;
    }
    #else
    if(isOkPressed()){
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      debounceDelay();
      return tempOpt;
    }
    #endif
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
    M5.update();  
#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
    keyboard_changed = M5Cardputer.Keyboard.isChange();
    if(keyboard_changed){Sound(10000, 100, sound);}
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
#else
    inputManager::update();
#endif

    canvas_main.clear(bg_color_rgb565);
    canvas_main.fillSprite(bg_color_rgb565); //Clears main display
    canvas_main.setTextSize(1.5);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.setTextDatum(top_left);
    canvas_main.setCursor(1, PADDING + 1);
    canvas_main.println(tittle);
    canvas_main.setTextSize(1);
    static char display_str[100] = "";
    uint16_t start = (menu_current_page - 1) * 8;
    uint16_t end = start + 8;
    if (end > menu_len) end = menu_len;

    for (uint16_t j = start; j < end; j++) {
        snprintf(display_str, sizeof(display_str), "%s %s", (tempOpt == j) ? ">" : " ",
                toDraw[j].c_str());
        int y = 8 + ((j - start) * 10) + 20;
        canvas_main.drawString(display_str, 0, y);
    }
    pushAll();

#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
    for(auto i : status.word){
      if(i=='`'){
        Sound(10000, 100, sound);
        menuID = prevMenuID;
        menu_current_opt = prevOpt;
        return -1;
      }
    }
#else
    inputManager::update();
    if (inputManager::isButtonBLongPressed()) {
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      return -1;
    }
#endif

    if (isNextPressed()) {
      if (menu_current_opt < menu_len - 1 ) {
        menu_current_opt++;
        tempOpt++;
      } else {
        menu_current_opt = 0;
        tempOpt = 0;
      }
      debounceDelay();
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
      debounceDelay();
    }
    if(!singlePage){
      float temp = 1+(menu_current_opt/8);
      menu_current_page = temp;
    }
    if(isOkPressed()){
      Sound(10000, 100, sound);
      menuID = prevMenuID;
      menu_current_opt = prevOpt;
      debounceDelay();
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
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
#else
        inputManager::update();
#endif
        M5.update();
        M5.update();
        if(isOkPressed()){break;}
        drawList(listToReturn, writeID);
        pushAll();
        if (isNextPressed()) {
            if (menu_current_opt < menu_len - 1 ) {
            menu_current_opt++;
          } else {
            menu_current_opt = 0;
          }
          debounceDelay();
        }

        if (isPrevPressed()) {
          if (menu_current_opt > 0) {
            menu_current_opt--;
          }
          else {
            menu_current_opt = (menu_len - 1);
          }
          debounceDelay();
        }
        if(!singlePage){
          if(menu_current_opt < 5 && menu_current_page != 1){
              menu_current_page= 1;
            
          } else if(menu_current_opt >= 5 && menu_current_page != 2){
              menu_current_page = 2;
          }
        }
      }
    }
  }
}

void drawList(String toDraw[], uint8_t menu_size) {
  menu_len = menu_size;

  M5.update();
  M5.update();

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
#ifndef BUTTON_ONLY_INPUT
  M5Cardputer.update();
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
#else
  inputManager::update();
  if (inputManager::isButtonBPressed()) {
    menu_current_opt = (menu_current_opt + 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
  }
  if (inputManager::isButtonAPressed()) {
    return;
  }
#endif
}

void drawMenuList(menu toDraw[], uint8_t menuIDPriv, uint8_t menu_size) {
  menuID = menuIDPriv;
  menu_len = menu_size;

  M5.update();
  M5.update();

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
  #ifdef BUTTON_ONLY_INPUT
  inputManager::update();
  
  if (isOkPressed()) {
    debounceDelay();
    runApp(toDraw[menu_current_opt].command);
    debounceDelay();
    return;
  }
  if (isNextPressed()) {
    if (toggleMenuBtnPressed()) {
      return;
    }
    menu_current_opt = (menu_current_opt + 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    
    return;
  }
  if (isPrevPressed()) {
    menu_current_opt = (menu_current_opt + menu_len - 1) % menu_len;
    marqueeOffset = 0;
    marqueeTick = millis();
    debounceDelay();
    return;
  }
  
  #else
  auto &keys = M5Cardputer.Keyboard;

  if (keys.isKeyPressed(KEY_ENTER)) {
    debounceDelay();
    runApp(toDraw[menu_current_opt].command);
    debounceDelay();
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
  #endif
}

void logVictim(String login, String pass){
  loginCaptured = login;
  passCaptured = pass;
  return;
}

// deprecated, leaved only for compatibility with older versions
inline void drawWifiInfoScreen(String wifiName, String wifiMac, String wifiRRSI, String wifiChanel){
  if(drawQuestionBox(wifiName, "Mac: " + wifiMac + ", " + wifiRRSI + " RRSI", ", Chanel: " + wifiChanel, "Clone this wifi?")){
    cloned = true;
    return;
  }
}



void pushAll(){
  if(coords_overlay){loggerTask(); delay(100);}
  drawBottomCanvas();
  drawTopCanvas();
  if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
  M5.Display.startWrite();
  canvas_top.pushSprite(0, 0);
  canvas_bot.pushSprite(0, canvas_top_h + canvas_h);
  canvas_main.pushSprite(0, canvas_top_h);
  M5.Display.endWrite();
  if (displayMutex) xSemaphoreGive(displayMutex);
  M5.update();
#ifndef BUTTON_ONLY_INPUT
  M5Cardputer.update();
  keyboard_changed = M5Cardputer.Keyboard.isChange();
  if(keyboard_changed){Sound(10000, 100, sound);}
#else
  inputManager::update();
#endif
}




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
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}  
        for(auto i : status.word){
          if(i=='`'){
            break;
          }
        }
#else
        inputManager::update();
#endif
        M5.update();
        M5.update();
        if(isOkPressed()){break;}
        // Convert vector to array for drawList
        String tempArr[listToReturn.size()];
        for (size_t i = 0; i < listToReturn.size(); ++i) tempArr[i] = listToReturn[i];
        drawList(tempArr, writeID);
        if (isNextPressed()) {
          if (menu_current_opt < menu_len - 1 ) {
            menu_current_opt++;
          } else {
            menu_current_opt = 0;
          }
          debounceDelay();
        }

        if (isPrevPressed()) {
          if (menu_current_opt > 0) {
            menu_current_opt--;
          }
          else {
            menu_current_opt = (menu_len - 1);
          }
          debounceDelay();
        }

        if(isOkPressed()){
          debounceDelay();
          break;
        }
        if(!singlePage){
          if(menu_current_opt < 5 && menu_current_page != 1){
              menu_current_page= 1;
            
          } else if(menu_current_opt >= 5 && menu_current_page != 2){
              menu_current_page = 2;
          }
        }
        pushAll();
        
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
    #ifdef BUTTON_ONLY_INPUT
    canvas_main.drawString("A:up B:next ok long A:save long B: exit", preview_x, preview_y + preview_h/2 + 12);
    #else
    canvas_main.drawString("Up/Down: value Left/Right: color OK set", preview_x, preview_y + preview_h/2 + 12);
    #endif
    pushAll();

    // Handle input
    M5.update();
#ifndef BUTTON_ONLY_INPUT
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
    }
#else
    inputManager::update();
    
    if (inputManager::isButtonBLongPressed()) {
      return "exited";
    }
    
    if (inputManager::isButtonBPressed()) {
      selected = (selected + 1) % 3;
    }
    
    if (inputManager::isButtonAPressed()) {
      if (selected == 0) r = min(255, r + 10);
      if (selected == 1) g = min(255, g + 10);
      if (selected == 2) b = min(255, b + 10);
    }

    if (inputManager::isButtonALongPressed()) {
      char hexStr[9];
      sprintf(hexStr, "#%02X%02X%02XFF", r, g, b);
      result = String(hexStr);
      done = true;
    }
#endif
    }
    delay(80);
  
  return result;
}

void coordsPickerUI() {
  appRunning = true;
  debounceDelay();
  // start in center of canvas
  int x = canvas_main.width() / 2;
  int y = canvas_main.height() / 2;
  int step = 1;
  uint16_t fillc = hexToRGB565(bg_color);
  while (true) {
    canvas_main.fillRect(0, 0, canvas_main.width(), canvas_main.height(), fillc);
    // draw crosshair
    canvas_main.fillRect(x, 0, 2, canvas_main.height(), tx_color_rgb565);
    canvas_main.fillRect(0, y, canvas_main.width(), 2, tx_color_rgb565);
    // show coords
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(top_left);
    canvas_main.setTextColor(tx_color_rgb565);
    canvas_main.drawString("X:" + String(x) + " Y:" + String(y), 4, 4);
    pushAll();
    M5.update();
#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if (status.fn) {
      for (auto k : status.word) {
        if (k == '`') { appRunning = false; return; }
      }
    }
    for (auto k : status.word) {
      if (k == ';') { y = max(0, y - step); }
      if (k == '.') { y = min((int)canvas_main.height() - 1, y + step); }
      if (k == ',') { x = max(0, x - step); }
      if (k == '/') { x = min((int)canvas_main.width() - 1, x + step); }
    }
    if (status.enter) {
      appRunning = false;
      drawInfoBox("Coords", "X:" + String(x) + " Y:" + String(y), "", true, false);
      return;
    }
#else
    inputManager::update();
    if (inputManager::isButtonBLongPressed()) {
      appRunning = false;
      return;
    }
    if (inputManager::isButtonBPressed()) {
      x = min((int)canvas_main.width() - 1, x + step);
    }
    if (inputManager::isButtonAPressed()) {
      appRunning = false;
      drawInfoBox("Coords", "X:" + String(x) + " Y:" + String(y), "", true, false);
      return;
    }
#endif
    delay(50);
  }
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
    canvas_main.setColor(tx_color_rgb565);
    canvas_main.fillRect(rect_x, rect_y, rect_w*fillProcent, rect_h);
    canvas_main.setColor(bg_color_rgb565);
    pushAll();
    M5.update();
#ifndef BUTTON_ONLY_INPUT
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
        if(brightness == 10){
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
#else
    inputManager::update();
    if (inputManager::isButtonBPressed()) {
      if(brightness < 245) brightness += 10;
      else brightness = 10;
    }
    if (inputManager::isButtonAPressed()) {
      debounceDelay();
      return brightness;
    }
#endif
    M5.Display.setBrightness(brightness);
  }
}

void debounceDelay(){
#ifndef BUTTON_ONLY_INPUT
  M5Cardputer.update();
  while(M5Cardputer.Keyboard.isPressed() != 0){
    M5Cardputer.update();
#else
  return;
  while(false){
    
#endif
    M5.update();
    delay(10);
  }
  M5.update();
  delay(40);
  M5.update();
}

void drawSysInfo(){
  drawTopCanvas();
  drawBottomCanvas();
  canvas_main.fillSprite(bg_color_rgb565);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextSize(2);
  canvas_main.setTextDatum(top_left);
  canvas_main.setCursor(1, PADDING + 1);
  canvas_main.println("System Stats");
  canvas_main.setTextSize(1);
  canvas_main.println("");
  canvas_main.println("Free Heap: " + String(ESP.getFreeHeap()) + " bytes");
  canvas_main.println("Sketch Size: " + String(ESP.getSketchSize()/1024) + " KB");
  canvas_main.println("Sketch Free: " + String(ESP.getFreeSketchSpace()/1024) + " KB");
  canvas_main.println("CPU Frequency: " + String(ESP.getCpuFreqMHz()) + " MHz");
  canvas_main.println("Chip ID: " + String(ESP.getChipModel()) + " Rev " + String(ESP.getChipRevision()));
  canvas_main.println("Flash Size: " + String(ESP.getFlashChipSize()/1024/1024) + " MB");
  canvas_main.println("Flash Speed: " + String(ESP.getFlashChipSpeed()/1000000) + " MHz");
  pushAll();
  debounceDelay();
  while(true){
    M5.update();
#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
#endif
    if(isOkPressed()) break;
#ifndef BUTTON_ONLY_INPUT
    M5Cardputer.update();
    if(M5Cardputer.Keyboard.isKeyPressed('`')) {
      debounceDelay();
      return;
    }
#else
    if (inputManager::isButtonAPressed() || inputManager::isButtonBPressed()) {
      debounceDelay();
      return;
    }
    inputManager::update();
#endif
    delay(100);
  }
}

void drawStats(){
  canvas_main.fillSprite(bg_color_rgb565);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextSize(2);
  canvas_main.setTextDatum(top_left);
  canvas_main.setCursor(5, 5);
  canvas_main.println("Usage statistics");
  canvas_main.setTextSize(1);
  canvas_main.println("");
  canvas_main.drawString("Prev run", 5, 25);
  canvas_main.drawString("Total", canvas_main.width()/2, 25);
  canvas_main.drawString("HS: " + String(lastSessionCaptures), 5, 35);
  canvas_main.drawString("HS: " + String(pwned_ap), canvas_main.width()/2, 35);
  canvas_main.drawString("P: " + String(lastSessionPeers), 5, 45);
  canvas_main.drawString("P: " + String(allTimePeers), canvas_main.width()/2, 45);
  canvas_main.drawString("D: " + String(lastSessionDeauths), 5, 55);
  canvas_main.drawString("D: " + String(allTimeDeauths), canvas_main.width()/2, 55);
  canvas_main.drawString("E: " + String(allTimeEpochs), canvas_main.width()/2, 65);
  canvas_main.drawString("T: " + String(lastSessionTime/60000) + "m", 5, 65);
  canvas_main.drawString("T: " + String(allSessionTime/60000) + "m", canvas_main.width()/2, 75);
  //now lets draw progress bar with level info and amont of captures user needs to advance to next level
  constexpr float XP_SCALE = 5.0f;
  constexpr float XP_EXPONENT = 0.75f;

  uint16_t level = (uint16_t)floor(pow(pwned_ap / XP_SCALE, XP_EXPONENT));

  float prev_level_xp = XP_SCALE * pow(level, 1.0f / XP_EXPONENT);
  float next_level_xp = XP_SCALE * pow(level + 1, 1.0f / XP_EXPONENT);

  float to_next_level = next_level_xp - pwned_ap;
  float progress = (pwned_ap - prev_level_xp) / (next_level_xp - prev_level_xp);
  canvas_main.drawString("Level: " + String(level) + ". Next level in: " + String((uint16_t)to_next_level) + " handshakes", 0, 85);
  //draw progress bar
  uint8_t bar_x = 5;
  uint8_t bar_y = 94;
  uint8_t bar_w = canvas_main.width() - 10;
  uint8_t bar_h = 10;
  canvas_main.drawRect(bar_x, bar_y, bar_w, bar_h, tx_color_rgb565);
  canvas_main.fillRect(bar_x, bar_y, bar_w * progress, bar_h, tx_color_rgb565);
  pushAll();
  debounceDelay();
  while(true){
    M5.update();
    M5.update();
    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    if (inputManager::isButtonAPressed() || inputManager::isButtonBPressed()) {
      debounceDelay();
      menuID = 0;
      return;
    }
    #else
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if (true) {
      for (auto k : status.word) {
        if (k == '`') {
          debounceDelay();
          menuID = 0;
          return;
        }
      }
    }
    if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
      debounceDelay();
      menuID = 0;
      return;
    }
    #endif
    delay(100);
  }
}

/* LittleFS manager UI */
void drawLittleFSManager() {
  debounceDelay();
  storageManager::init();

  drawTopCanvas();
  drawBottomCanvas();
  canvas_main.clear(bg_color_rgb565);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextSize(2);
  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString("LittleFS Manager", canvas_center_x, 10);
  canvas_main.setTextSize(1);
  canvas_main.setTextDatum(top_left);

  String info = storageManager::getDetailedStorageInfo();
  canvas_main.setCursor(2, 30);
  canvas_main.println(info);

  canvas_main.setTextDatum(middle_center);
  canvas_main.drawString("A: Back B: Format (hold B to confirm)", canvas_center_x, canvas_h - 12);
  pushAll();

  while (true) {
    M5.update();
#ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    if (inputManager::isButtonAPressed()) {
      debounceDelay();
      return;
    }
    if (inputManager::isButtonBLongPressed()) {
      // confirm format
      bool ok = drawQuestionBox("Format LittleFS?", "All files will be lost", "");
      if (ok) {
        LittleFS.format();
        storageManager::init();
        drawInfoBox("Info", "LittleFS formatted", "", true, false);
        return;
      }
    }
#else
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if (status.enter) { debounceDelay(); return; }
    for (auto c : status.word) {
      if (c == '`') { debounceDelay(); return; }
    }
#endif
    delay(100);
  }
}

#ifdef ENABLE_COREDUMP_LOGGING
#include "esp_core_dump.h"
#include "esp_system.h"

void sendCrashReport(){
  if (esp_core_dump_image_check() == ESP_OK) {
  } else {
    logMessage("Core dump image not found");
    drawInfoBox("Error", "No coredump log found", "Nothing to send", true, false);
    menuID = 0;
    return;
  }
  //inform user of state
  drawInfoBox("Info", "Trying to tonnect to wifi... Please wait", "", false, false);
  //first try to find saved wifi
  attemptConnectSavedNetworks();
  if(WiFi.status() == WL_CONNECTED){
  }
  else{
    bool answwer = drawQuestionBox("Error", "Saved wifi not found to send bug report", "Set up new one?", "Press Y for yes, N for no");
    if(answwer){
      runApp(43); //wifi setup app
      if(WiFi.status() == WL_CONNECTED){
        logMessage("Wifi connected, sending report...");
      }
      else{
        drawInfoBox("Error", "Cannot send report", "No wifi connected", true, false);
        return;
      }
    }
    else{
      drawInfoBox("Error", "Cannot send report", "No wifi connected", true, false);
      return;
    }
  }
  connectMQTT();
  bool ok = sendCoredump();
  if (ok) {
    drawInfoBox("Report sent", "Upload verified", "Thank you for helping to improve this software!", true, false);
  } else {
    drawInfoBox("Report pending", "Upload not verified", "Coredump kept for retry.", true, false);
  }
  drawInfoBox("Rebooting", "System will restart", "in 5 seconds...", false, false);
  delay(5000);
  ESP.restart();
  menuID = 0;
}

#endif

void themeMenu() {
  String themeOptions[] = {
    "White", "Dark", "Blue", "Green", "Red", "Purple", "Orange", // Original 7
    "Midnight", "Nord", "Forest", "Matrix", "Sepia",            // Pro 5
    "Sky", "Rose", "Lavender", "Coffee", "Gold",                // Soft 5
    "Gameboy", "C64", "Cyberpunk", "Dracula", "Ocean",          // Retro/Special 5
    "High Viz", "Custom", "Back"                                // Misc 3
  };

  // Total items: 25
  int themeChoice = drawMultiChoice("Theme", themeOptions, 25, 6, 0);
  
  bool shouldSave = true;

  switch(themeChoice) {
    // --- ORIGINAL COLORS ---
    case 0: bg_color = "#FFFFFFFF"; tx_color = "#000000FF"; break;
    case 1: bg_color = "#000000FF"; tx_color = "#FFFFFFFF"; break;
    case 2: bg_color = "#001F3FFF"; tx_color = "#FFFFFFFF"; break;
    case 3: bg_color = "#2ECC40FF"; tx_color = "#000000FF"; break;
    case 4: bg_color = "#FF4136FF"; tx_color = "#FFFFFFFF"; break;
    case 5: bg_color = "#B10DC9FF"; tx_color = "#FFFFFFFF"; break;
    case 6: bg_color = "#FF851BFF"; tx_color = "#000000FF"; break;

    // --- PROFESSIONAL ---
    case 7: bg_color = "#1A1B26FF"; tx_color = "#A9B1D6FF"; break; // Midnight
    case 8: bg_color = "#2E3440FF"; tx_color = "#ECEFF4FF"; break; // Nord
    case 9: bg_color = "#0B120BFF"; tx_color = "#95AD95FF"; break; // Forest
    case 10: bg_color = "#000000FF"; tx_color = "#00FF41FF"; break; // Matrix
    case 11: bg_color = "#F4ECD8FF"; tx_color = "#5B4636FF"; break; // Sepia

    // --- SOFT / MODERN ---
    case 12: bg_color = "#E0F2F1FF"; tx_color = "#004D40FF"; break; // Sky
    case 13: bg_color = "#FCE4ECFF"; tx_color = "#880E4FFF"; break; // Rose
    case 14: bg_color = "#F3E5F5FF"; tx_color = "#4A148CFF"; break; // Lavender
    case 15: bg_color = "#3E2723FF"; tx_color = "#D7CCC8FF"; break; // Coffee
    case 16: bg_color = "#FFF9C4FF"; tx_color = "#F57F17FF"; break; // Gold

    // --- RETRO & SPECIAL ---
    case 17: bg_color = "#9BBC0FFF"; tx_color = "#0F380FFF"; break; // Gameboy Green
    case 18: bg_color = "#352879FF"; tx_color = "#6C5EB5FF"; break; // Commodore 64 Blue
    case 19: bg_color = "#000000FF"; tx_color = "#F0E68CFF"; break; // Cyberpunk
    case 20: bg_color = "#282A36FF"; tx_color = "#FF79C6FF"; break; // Dracula Pink
    case 21: bg_color = "#0077BEFF"; tx_color = "#FFFFFFFF"; break; // Deep Ocean
    case 22: bg_color = "#FFFF00FF"; tx_color = "#000000FF"; break; // High Viz (Yellow/Black)

    case 23: { // Custom
      drawInfoBox("Custom Theme", "Pick background color via color picker...", "", false, false);
      delay(5000);
      String customBg = colorPickerUI(false, "#000000FF");
      if (customBg == "exited") { shouldSave = false; break; }
      drawInfoBox("Custom Theme", "Pick text color via color picker...", "", false, false);
      delay(5000);
      String customTx = colorPickerUI(true, customBg);
      if (customTx == "exited" || customBg == customTx) { shouldSave = false; break; }
      bg_color = customBg; tx_color = customTx;
      break;
    }

    default: // Back
      menuID = 6;
      return;
  }

  if (shouldSave) {
    if (saveSettings()) {
      drawInfoBox("Theme", "Saving Theme...", "Restarting...", false, false);
      delay(800);
      ESP.restart();
    } else {
      drawInfoBox("ERROR", "Save failed!", "Check SD Card", true, false);
      delay(2000);
    }
  }
  else{
    drawInfoBox("Theme","Invalid color selection", "No changes made.",  true, false);
    delay(1500);
  }

  menuID = 6;
}
// Storage display UI with usage bars
void drawStorageInfo() {
  debounceDelay();
  
  while (true) {
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextColor(tx_color_rgb565);
    
    // Title
    canvas_main.setTextSize(2);
    canvas_main.setTextDatum(middle_center);
    canvas_main.drawString("Storage", canvas_center_x, 10);
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(top_left);
    
    #ifdef USE_LITTLEFS
    // Get LittleFS info
    StorageManager::StorageInfo lfs_info = StorageManager::getStorageInfo();
    
    int y = 30;
    int bar_height = 10;
    int bar_y = y + 25;
    int bar_width = 200;
    
    // LittleFS section
    canvas_main.drawString("LittleFS:", 6, y);
    
    // Draw percentage
    String lfs_used_mb = String((float)lfs_info.usedBytes / 1024.0f / 1024.0f, 1);
    String lfs_total_mb = String((float)lfs_info.totalBytes / 1024.0f / 1024.0f, 1);
    String lfs_percent = String((int)lfs_info.percentUsed);
    canvas_main.drawString(lfs_used_mb + "MB / " + lfs_total_mb + "MB (" + lfs_percent + "%)", 6, y + 10);
    
    // Draw usage bar
    canvas_main.drawRect(6, bar_y, bar_width, bar_height, tx_color_rgb565);
    int filled_width = (bar_width * lfs_info.percentUsed) / 100.0f;
    canvas_main.fillRect(6, bar_y, filled_width, bar_height, tx_color_rgb565);
    
    y += 30;
    bar_y = y + 12;
    
    #else
    // If SD card is being used
    int y = 30;
    int bar_height = 10;
    int bar_y = y + 25;
    int bar_width = 200;
    
    canvas_main.drawString("SD Card:", 6, y);
    
    uint64_t card_size = FSYS.cardSize();
    uint64_t used_size = 0;
    
    // Calculate used space (rough estimate)
    File root = FSYS.open("/");
    if (root) {
      // Simple dir traversal for used space
      File file = root.openNextFile();
      while (file) {
        if (!file.isDirectory()) {
          used_size += file.size();
        }
        file = root.openNextFile();
      }
      root.close();
    }
    
    float percent_used = (card_size > 0) ? ((float)used_size / card_size * 100.0f) : 0;
    String sd_used_mb = String((float)used_size / 1024.0f / 1024.0f, 1);
    String sd_total_mb = String((float)card_size / 1024.0f / 1024.0f, 1);
    String sd_percent = String((int)percent_used);
    
    canvas_main.drawString(sd_used_mb + "MB / " + sd_total_mb + "MB (" + sd_percent + "%)", 6, y + 10);
    
    // Draw usage bar
    canvas_main.drawRect(6, bar_y, bar_width, bar_height, tx_color_rgb565);
    int filled_width = (bar_width * percent_used) / 100.0f;
    canvas_main.fillRect(6, bar_y, filled_width, bar_height, tx_color_rgb565);
    
    y += 30;
    
    #endif
    
    // Instructions
    canvas_main.setTextSize(1);
    canvas_main.setTextDatum(middle_center);
    #ifdef BUTTON_ONLY_INPUT
    canvas_main.drawString("A: Back", canvas_center_x, canvas_main.height() - 12);
    #else
    canvas_main.drawString("Enter or ` to go back", canvas_center_x, canvas_main.height() - 12);
    #endif
    
    pushAll();
    
    M5.update();
    M5.update();
    
    #ifdef BUTTON_ONLY_INPUT
    inputManager::update();
    if (inputManager::isButtonAPressed()) {
      debounceDelay();
      return;
    }
    #else
    Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
    if (status.enter) { 
      debounceDelay(); 
      return; 
    }
    for (auto c : status.word) {
      if (c == '`') { 
        debounceDelay(); 
        return; 
      }
    }
    #endif
    
    delay(100);
  }
}
