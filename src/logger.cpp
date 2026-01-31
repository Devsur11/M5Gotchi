#include "settings.h"
#include <cstdio>
#include <string>
#include <deque>
#include <vector>
#include <algorithm>
#include "logger.h"
#ifndef BUTTON_ONLY_INPUT
#include "M5Cardputer.h"
#endif
#include "Arduino.h"
#include "SD.h"

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

void drawOverlayLogs() {
    if (!overlayEnabled) return;

    const int startX = 5;
    const int startY = 20;
    const int lineHeight = 12;
    const int maxLines = 8;
    
    M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
    M5.Display.setTextSize(1);

    uint32_t now_ms = millis();
    // remove expired entries (>5s)
    while (!overlayLogs.empty() && (now_ms - overlayLogs.front().ts > 5000)) {
        overlayLogs.pop_front();
    }

    int lineNum = 0;
    for (auto it = overlayLogs.rbegin(); it != overlayLogs.rend() && lineNum < maxLines; ++it, ++lineNum) {
        M5.Display.setCursor(startX, startY + lineNum * lineHeight);
        M5.Display.fillRect(startX, startY,lineNum * lineHeight, 256, TFT_BLACK);
        M5.Display.print(it->txt);
    }
}

void loggerTask() {
    if (!overlayEnabled) return;

    static uint32_t lastDrawTime = 0;
    uint32_t now = millis();
    if (now - lastDrawTime >= 100) { // update every 1000ms
        drawOverlayLogs();
        lastDrawTime = now;
    }
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
    loggerTask();
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


