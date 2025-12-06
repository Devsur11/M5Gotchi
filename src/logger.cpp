#include <cstdio>
#include <string>
#include "logger.h"
#include "M5Cardputer.h"
#include "Arduino.h"
#include "settings.h"
#include "SD.h"

// void logMessage(String message) {
//     #ifdef SERIAL_LOGS
//     // Format: [I][logger.cpp:logMessage][time:12345] Message
//     printf("[%lu][I][logger.cpp:11] %s\n", millis(), message.c_str());

//     if(sd_logging)
//     {if(SD.exists("/log.txt")) {
//         File logFile = SD.open("/log.txt", FILE_APPEND);
//         if (logFile) {
//             logFile.printf("[%lu][I][logger.cpp:11] %s\n", millis(), message.c_str());
//             logFile.close();
//         }
//     } else {
//         File logFile = SD.open("/log.txt", FILE_WRITE);
//         if (logFile) {
//             logFile.printf("[%lu][I][logger.cpp:11] %s\n", millis(), message.c_str());
//             logFile.close();
//         }
//     }}
//     #endif
// }

void logMessage(String message) {
    printf("[%lu][I][logger.cpp:11] %s\n", millis(), message.c_str());
}

#include <stdarg.h>

void fLogMessage(const char *format, ...) {
    const size_t BUF_SZ = 512;
    char buf[BUF_SZ];

    va_list args;
    va_start(args, format);
    vsnprintf(buf, BUF_SZ, format, args);
    va_end(args);

    logMessage(String(buf));
}


