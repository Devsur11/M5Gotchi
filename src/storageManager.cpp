#include "storageManager.h"
#include "logger.h"

namespace storageManager {
    
bool init() {
    if (!LittleFS.begin(true)) {
        logMessage("LittleFS initialization failed!");
        return false;
    }
    logMessage("LittleFS initialized successfully");
    return true;
}

uint32_t getTotalSize() {
    return LittleFS.totalBytes();
}

uint32_t getUsedSize() {
    return LittleFS.usedBytes();
}

uint32_t getAvailableSize() {
    return LittleFS.totalBytes() - LittleFS.usedBytes();
}

uint8_t getUsedPercentage() {
    uint32_t total = LittleFS.totalBytes();
    if (total == 0) return 0;
    return (uint8_t)((LittleFS.usedBytes() * 100) / total);
}

String getStorageInfo() {
    uint32_t used = getUsedSize();
    uint32_t total = getTotalSize();
    uint8_t percentage = getUsedPercentage();
    
    String usedKB = String(used / 1024);
    String totalKB = String(total / 1024);
    
    return "Used: " + usedKB + " KB / " + totalKB + " KB (" + String(percentage) + "%)";
}

String getDetailedStorageInfo() {
    uint32_t used = getUsedSize();
    uint32_t total = getTotalSize();
    uint32_t available = getAvailableSize();
    uint8_t percentage = getUsedPercentage();
    
    String usedKB = String(used / 1024);
    String totalKB = String(total / 1024);
    String availableKB = String(available / 1024);
    
    return "Storage Status:\n"
           "Used: " + usedKB + " KB\n"
           "Available: " + availableKB + " KB\n"
           "Total: " + totalKB + " KB\n"
           "Usage: " + String(percentage) + "%";
}

}
