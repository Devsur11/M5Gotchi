#include <Update.h>
#include <FS.h>
#include <SD.h>
#include <WiFi.h>
#include "logger.h"

#define SD_CS    12  // G12
#define SD_MOSI  14  // G14
#define SD_SCK   40  // G40
#define SD_MISO  39  // G39

void rebootEspWithReason(String reason);
void updateFromFS(fs::FS &fs);
void updateFromSd();
void performUpdate(Stream &updateSource, size_t updateSize);
void updateFromHTML();