#include "settings.h"
#include "storageAbstraction.h"
#include "logger.h"


namespace StorageManager {
  
  // Forward declaration
  uint64_t calculateDirSize(File dir);
  
  bool initStorage() {
    #ifdef USE_LITTLEFS
    if (!LittleFS.begin(true)) {
      logMessage("LittleFS mount failed");
      return false;
    }
    logMessage("LittleFS initialized");
    return true;
    #else
    if (!FSYS.begin()) {
      logMessage("SD mount failed");
      return false;
    }
    logMessage("SD initialized");
    return true;
    #endif
  }
  
  StorageInfo getStorageInfo() {
    StorageInfo info = {0, 0, 0, 0};
    
    #ifdef USE_LITTLEFS
    info.totalBytes = LittleFS.totalBytes();
    info.usedBytes = LittleFS.usedBytes();
    info.freeBytes = info.totalBytes - info.usedBytes;
    if (info.totalBytes > 0) {
      info.percentUsed = (float)info.usedBytes / info.totalBytes * 100.0f;
    }
    #else
    uint64_t cardSize = FSYS.cardSize();
    info.totalBytes = cardSize;
    
    File root = FSYS.open("/");
    uint64_t usedBytes = calculateDirSize(root);
    root.close();
    
    info.usedBytes = usedBytes;
    info.freeBytes = cardSize - usedBytes;
    if (cardSize > 0) {
      info.percentUsed = (float)usedBytes / cardSize * 100.0f;
    }
    #endif
    
    return info;
  }
  
  bool fileExists(const String &path) {
    return StorageFS.exists(path);
  }
  
  bool dirExists(const String &path) {
    File f = StorageFS.open(path);
    if (!f) return false;
    bool isDir = f.isDirectory();
    f.close();
    return isDir;
  }
  
  bool removeFile(const String &path) {
    return StorageFS.remove(path);
  }
  
  bool removeDir(const String &path) {
    File dir = StorageFS.open(path);
    if (!dir || !dir.isDirectory()) {
      if (dir) dir.close();
      return false;
    }
    
    File file = dir.openNextFile();
    bool success = true;
    while (file) {
      if (file.isDirectory()) {
        if (!removeDir(file.path())) {
          success = false;
        }
      } else {
        if (!StorageFS.remove(file.path())) {
          success = false;
        }
      }
      file = dir.openNextFile();
    }
    dir.close();
    
    return success && StorageFS.rmdir(path);
  }
  
  bool createDir(const String &path) {
    return StorageFS.mkdir(path);
  }
  
  bool renameFile(const String &oldPath, const String &newPath) {
    return StorageFS.rename(oldPath, newPath);
  }
  
  fs::FS& getFS() {
    return StorageFS;
  }
  
  const char* getStorageType() {
    return STORAGE_TYPE;
  }
  
  // Helper function for SD card space calculation
  uint64_t calculateDirSize(File dir) {
    uint64_t size = 0;
    File file = dir.openNextFile();
    while (file) {
      if (file.isDirectory()) {
        size += calculateDirSize(file);
      } else {
        size += file.size();
      }
      file = dir.openNextFile();
    }
    return size;
  }
}
