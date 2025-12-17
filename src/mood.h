#include "M5Cardputer.h"
#include <SD.h>

#define MOOD_BROKEN 19


void setMood(uint8_t mood, String face = "", String phrase = "", bool broken = false);
String getCurrentMoodFace();
String getCurrentMoodPhrase();

// Initialize moods subsystem: create default files if missing and load moods from SD
bool initMoodsFromSD();

// Create default mood files on SD (faces + texts)
bool createDefaultMoodFiles();

// Reload mood files from SD (useful after editing files on the SD card)
bool reloadMoodFiles();

void setMoodToStatus();
void setMoodToDeauth(const String& ssid);
void setMoodToPeerNearby(const String& peerName);
void setMoodToNewHandshake(uint8_t handshakes);
void setMoodToAttackFailed(const String& targetName);
void setMoodSleeping();
void setMoodToStartup();
void setMoodSad();
void setMoodHappy();
void setMoodBroken();
void setMoodLooking(uint8_t durationSeconds);
void setGeneratingKeysMood();
void setChannelFreeMood(uint8_t channel);
void setMoodApSelected(const String& ssid);
void setNewMessageMood(uint8_t messages);
void setIDLEMood();