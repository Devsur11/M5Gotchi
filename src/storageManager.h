#pragma once

#include <LittleFS.h>
#include <Arduino.h>

namespace storageManager {
    // Initialize LittleFS
    bool init();
    
    // Get total storage in bytes
    uint32_t getTotalSize();
    
    // Get used storage in bytes
    uint32_t getUsedSize();
    
    // Get available storage in bytes
    uint32_t getAvailableSize();
    
    // Get used percentage (0-100)
    uint8_t getUsedPercentage();
    
    // Get formatted storage info string
    String getStorageInfo();
    
    // Format: "Used: XXX KB / Total: XXX KB (XX%)"
    String getDetailedStorageInfo();
}
