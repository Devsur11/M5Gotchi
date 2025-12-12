#include <cstdio>
#include <string>
#include <deque>
#include <vector>
#include <algorithm>
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

// In-memory circular buffer for overlay logs with timestamps
struct OverlayEntry { uint32_t ts; String txt; };
static std::deque<OverlayEntry> overlayLogs;
static bool overlayEnabled = false;
static const size_t MAX_OVERLAY_LOGS = 8;

void loggerSetOverlayEnabled(bool enabled) {
    overlayEnabled = enabled;
}

bool loggerIsOverlayEnabled() {
    return overlayEnabled;
}

void loggerGetLines(std::vector<String> &out, int maxLines) {
    out.clear();
    uint32_t now_ms = millis();
    // remove expired entries (>5s)
    while (!overlayLogs.empty() && (now_ms - overlayLogs.front().ts > 5000)) {
        overlayLogs.pop_front();
    }
    int count = 0;
    // add up to maxLines from the tail (latest)
    for (auto it = overlayLogs.rbegin(); it != overlayLogs.rend() && count < maxLines; ++it) {
        out.push_back(it->txt);
        count++;
    }
    std::reverse(out.begin(), out.end());
}

void logMessage(String message) {
    printf("[%lu][I][logger.cpp] %s\n", millis(), message.c_str());
    if (overlayEnabled) {
        // keep timestamps minimal for overlay
        OverlayEntry e{millis(), String(millis()) + ": " + message};
        overlayLogs.push_back(e);
        while (overlayLogs.size() > MAX_OVERLAY_LOGS) overlayLogs.pop_front();
    }
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


