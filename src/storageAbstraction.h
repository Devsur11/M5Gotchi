#pragma once

#include <Arduino.h>
#include <FS.h>

#ifdef USE_LITTLEFS
#include <LittleFS.h>
#define StorageFS LittleFS
#define STORAGE_TYPE "LittleFS"
#else
#define StorageFS SD
#define STORAGE_TYPE "SD"
#endif

// Storage abstraction utilities
namespace StorageManager {
  
  // Initialize storage
  bool initStorage();
  
  // Get storage info
  struct StorageInfo {
    uint64_t totalBytes;
    uint64_t usedBytes;
    uint64_t freeBytes;
    float percentUsed;
  };
  
  StorageInfo getStorageInfo();
  
  // File operations
  bool fileExists(const String &path);
  bool dirExists(const String &path);
  bool removeFile(const String &path);
  bool removeDir(const String &path);
  bool createDir(const String &path);
  bool renameFile(const String &oldPath, const String &newPath);
  
  // Get FS reference
  fs::FS& getFS();
  
  // Get storage type string
  const char* getStorageType();
}
