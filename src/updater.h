#include <Update.h>
#include <FS.h>
#include <SD.h>



void rebootEspWithReason(String reason);
void updateFromFS(fs::FS &fs);
void updateFromSd();
void performUpdate(Stream &updateSource, size_t updateSize);