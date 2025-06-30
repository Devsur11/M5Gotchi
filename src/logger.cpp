#include <cstdio>
#include <string>
#include "logger.h"
#include "M5Cardputer.h"
#include "Arduino.h"
#include "settings.h"

void logMessage(String message) {
    #ifdef SERIAL_LOGS
    // Format: [I][logger.cpp:logMessage][time:12345] Message
    printf("[%lu][I][logger.cpp:11] %s\n", millis(), message.c_str());
    #endif
}