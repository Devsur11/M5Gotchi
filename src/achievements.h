#pragma once
#include <Arduino.h>
#include <vector>
#include <ArduinoJson.h>
#define ACHIEVEMENTS_CONFIG_FILE "/M5Gotchi/achievements.conf"
#define PWNGRID_ENROLL_FAIL_FLAG "/M5Gotchi/pwngrid_enroll_failed"
// Achievement ID enumeration
enum AchievementID : uint8_t {
    ACH_FIRST_PWN = 0,
    ACH_1ST_LVL = 1,
    ACH_10_LVL = 2,
    ACH_50_LVL = 3,
    ACH_100_LVL = 4,
    ACH_NAME_CHANGE = 5,
    ACH_SECRET_NAME = 6,
    ACH_PERSONALITY_CHANGE = 7,
    ACH_ENROLL_PWNGRID = 8,
    ACH_FIRST_MEETING = 9,
    ACH_FAMILY = 10,
    ACH_FRIENDS = 11,
    ACH_DEV_MODE = 12,
    ACH_PWNADISE = 13,
    ACH_DEV_VER = 14,
    ACH_SKILL_ISSUE = 15,
    ACH_WARDRIVE = 16,
    ACH_WIGLE_NET = 17,
    ACH_PMKID_GRABBER = 18,
    ACH_TERMINAL = 19,
    ACH_WPA_SEC_API = 20,
    ACH_MANUAL_GRAB = 21,
    ACH_TEST = 22,
    ACH_HAVE_YOU_TRIED_TURNING_IT_OFF_ON_AGAIN = 23,
    ACH_CHEATER = 24,
    ACH_PAPIEZOWO = 25,
    ACH_GOT_MAIL = 26,
    ACH_CUSTOMIZATION_GOD = 27,
    ACH_DAVE = 28, //I'm sorry dave, I'm afraid I can't do that.
    ACH_100_EPOCH = 29,
    ACH_1000_EPOCH = 30,
    ACH_10000_EPOCH = 31,
    ACH_1000_DEAUTH = 32,
    ACH_10000_DEAUTH = 33,
    ACH_10_PEERS = 34,
    ACH_50_PEERS = 35,
    ACH_100_PEERS = 36,
    ACH_1_HOUR_SESSION = 37,
    ACH_6_HOUR_SESSION = 38,
    ACH_CHILD = 39,
    ACH_SKID = 40,
    ACH_COUNT = 41
};

// Achievement metadata
struct AchievementData {
    AchievementID id;
    const char* name;
    const char* description;
    bool is_secret;
    static const uint8_t* icon;
};

struct AchievementState {
    bool unlocked = false;
    uint32_t unlock_time = 0;  // Unix timestamp when unlocked
};

const AchievementData ACHIEVEMENTS[ACH_COUNT] = {
    {ACH_FIRST_PWN, "First Pwn", "Get your first pwn", false},//d
    {ACH_1ST_LVL, "Level 1", "Reach level 1", false},//d
    {ACH_10_LVL, "Level 10", "Reach level 10", false},//d
    {ACH_50_LVL, "Level 50", "Reach level 50", false},//d
    {ACH_100_LVL, "Level 100", "Reach level 100", false},//d
    {ACH_NAME_CHANGE, "Identity Crisis", "Change your name", false},//d
    {ACH_SECRET_NAME, "Just like the god intended", "Change your name to Pwnagotchi", true}, //d
    {ACH_PERSONALITY_CHANGE, "Personality Crisis", "Change your personality settings", false},
    {ACH_ENROLL_PWNGRID, "PwnGrid Enroller", "Enroll in PwnGrid", false},//d
    {ACH_FIRST_MEETING, "First Meeting", "Meet another Pwnagotchi", false},//d
    {ACH_FAMILY, "Family Reunion", "Meet 5 different Pwnagotchis in single run", false},//d
    {ACH_FRIENDS, "Making Friends", "Add any unit to friends list", false},//d
    {ACH_DEV_MODE, "D3V?", "Enable developer mode", true},//d
    {ACH_PWNADISE, "Pwnadise Found", "Discover Pwnadise", true}, // still dont know what this will be :/ can't be obtained
    {ACH_DEV_VER, "Helping hands", "Run a developer version of the firmware", true},//d
    {ACH_SKILL_ISSUE, "Skill Issue", "Fail an attack", true},
    {ACH_WARDRIVE, "Wardriver", "Capture GPS coordinates with a handshake", false},
    {ACH_WIGLE_NET, "WiGLE.net", "Upload a capture to WiGLE.net", false},
    {ACH_PMKID_GRABBER, "PMKID Grabber", "Capture a PMKID", false},
    {ACH_TERMINAL, "Terminal Master", "Find the terminal", true},//d
    {ACH_WPA_SEC_API, "WPA SEC API", "Use the WPA-SEC", false},
    {ACH_MANUAL_GRAB, "Manual Grab", "Manually capture a handshake using the EAPOL sniffer", false},
    {ACH_TEST, "Test Achievement", "This is a test achievement - I don't know how did you get it", true},
    {ACH_HAVE_YOU_TRIED_TURNING_IT_OFF_ON_AGAIN, "Have you tried turning it off and on again?", "Fix the pwngrid by restarting", true},
    {ACH_CHEATER, "Cheater", "Unlock an achievement using a cheat code", true},
    {ACH_PAPIEZOWO, "Papieżowo", "Pan, kiedyś stanął nad brzegiem...", true}, // note for design - draw piece of cake here - unlocks when typed 2137 into secret terminal
    {ACH_GOT_MAIL, "You've got mail!", "Receive a message in the inbox", false},
    {ACH_CUSTOMIZATION_GOD, "Customization God", "Change splash texts", false},
    {ACH_DAVE, "I'm sorry Dave", "Try to delete system folder", true}, //d
    {ACH_100_EPOCH, "Century Club", "Complete 100 epochs", false},
    {ACH_1000_EPOCH, "Millennium Club", "Complete 1000 epochs", false},
    {ACH_10000_EPOCH, "Decamillennium Club", "Complete 10000 epochs", false},
    {ACH_1000_DEAUTH, "Deauth Enthusiast", "Send 1000 deauth packets", false},
    {ACH_10000_DEAUTH, "Deauth Master", "Send 10000 deauth packets", false},
    {ACH_10_PEERS, "Social Butterfly", "Discover 10 peers", false},
    {ACH_50_PEERS, "People Person", "Discover 50 peers", false},
    {ACH_100_PEERS, "Traveller", "Discover 100 peers",false},
    {ACH_1_HOUR_SESSION, "One Hour Wonder", "Have a single session that lasts 1 hour", false},
    {ACH_6_HOUR_SESSION, "Endurance Runner", "Have a single session that lasts 6 hours", false},
    {ACH_CHILD, "Child", "YOU KNOW WHAT YOU DID!", true}, //- unlocks when typed 67 into secret terminal
    {ACH_SKID, "Skid", "Master of nothing, god of chatGPT", true} //can't be obtained
};

bool achievements_register(AchievementID id);
bool achievements_load();
bool achievements_save();
bool achievements_is_unlocked(AchievementID id);
uint32_t achievements_get_unlock_time(AchievementID id);
const AchievementData* achievements_get_data(AchievementID id);
uint8_t achievements_get_unlocked_count();
void achievements_init();
const std::vector<AchievementState>& achievements_get_all_states();
#define LOCK_HEIGHT 30
#define LOCK_WIDTH 40

// array size is 150
static const uint8_t lock[]  = {
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0xfc, 0x00, 0x00, 
  0x00, 0x03, 0xff, 0x00, 0x00, 
  0x00, 0x07, 0xcf, 0x80, 0x00, 
  0x00, 0x07, 0x03, 0xc0, 0x00, 
  0x00, 0x0e, 0x00, 0xe0, 0x00, 
  0x00, 0x0e, 0x00, 0xe0, 0x00, 
  0x00, 0x1c, 0x00, 0x70, 0x00, 
  0x00, 0x1c, 0x00, 0x70, 0x00, 
  0x00, 0x18, 0x00, 0x30, 0x00, 
  0x00, 0x18, 0x00, 0x30, 0x00, 
  0x00, 0x1f, 0xff, 0xf0, 0x00, 
  0x00, 0x1f, 0xff, 0xf0, 0x00, 
  0x00, 0x18, 0x00, 0x30, 0x00, 
  0x00, 0x18, 0x38, 0x30, 0x00, 
  0x00, 0x18, 0x7c, 0x30, 0x00, 
  0x00, 0x18, 0x7c, 0x30, 0x00, 
  0x00, 0x18, 0x7c, 0x30, 0x00, 
  0x00, 0x18, 0x38, 0x30, 0x00, 
  0x00, 0x18, 0x38, 0x30, 0x00, 
  0x00, 0x18, 0x38, 0x30, 0x00, 
  0x00, 0x18, 0x38, 0x30, 0x00, 
  0x00, 0x18, 0x10, 0x30, 0x00, 
  0x00, 0x18, 0x00, 0x30, 0x00, 
  0x00, 0x1f, 0xff, 0xf0, 0x00, 
  0x00, 0x1f, 0xff, 0xf0, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00
};

#define UNLOCK_HEIGHT 30
#define UNLOCK_WIDTH 40

// array size is 150
static const byte unlock[] PROGMEM  = {
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x01, 0xf8, 0x00, 0x00, 0x00, 
  0x07, 0xfe, 0x00, 0x00, 0x00, 
  0x0f, 0x9f, 0x00, 0x00, 0x00, 
  0x0e, 0x07, 0x80, 0x00, 0x00, 
  0x1c, 0x01, 0xc0, 0x00, 0x00, 
  0x1c, 0x01, 0xc0, 0x00, 0x00, 
  0x38, 0x00, 0xe0, 0x00, 0x00, 
  0x38, 0x00, 0xe0, 0x00, 0x00, 
  0x30, 0x00, 0x60, 0x00, 0x00, 
  0x30, 0x00, 0x60, 0x00, 0x00, 
  0x00, 0x00, 0x7f, 0xff, 0xc0, 
  0x00, 0x00, 0x7f, 0xff, 0xc0, 
  0x00, 0x00, 0x60, 0x00, 0xc0, 
  0x00, 0x00, 0x60, 0xe0, 0xc0, 
  0x00, 0x00, 0x61, 0xf0, 0xc0, 
  0x00, 0x00, 0x61, 0xf0, 0xc0, 
  0x00, 0x00, 0x61, 0xf0, 0xc0, 
  0x00, 0x00, 0x60, 0xe0, 0xc0, 
  0x00, 0x00, 0x60, 0xe0, 0xc0, 
  0x00, 0x00, 0x60, 0xe0, 0xc0, 
  0x00, 0x00, 0x60, 0xe0, 0xc0, 
  0x00, 0x00, 0x60, 0x40, 0xc0, 
  0x00, 0x00, 0x60, 0x00, 0xc0, 
  0x00, 0x00, 0x7f, 0xff, 0xc0, 
  0x00, 0x00, 0x7f, 0xff, 0xc0, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00
};