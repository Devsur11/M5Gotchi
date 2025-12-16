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