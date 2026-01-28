#include "usbMassStorage.h"

#ifdef USE_LITTLEFS
#include "logger.h"

#include <USB.h>
#include <USBMSCDevice.h>
#include <LittleFS.h>

namespace USBMassStorage {
  
  static USBMSCDevice usb_msc;
  static bool is_active = false;
  
  // MSC callbacks
  static int msc_read_callback(uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize) {
    return usb_msc.readSector(lba, offset, buffer, bufsize);
  }
  
  static int msc_write_callback(uint32_t lba, uint32_t offset, uint8_t *buffer, uint32_t bufsize) {
    return usb_msc.writeSector(lba, offset, buffer, bufsize);
  }
  
  bool begin(int pinD_minus, int pinD_plus) {
    if (is_active) {
      return true;
    }
    
    // Configure USB pins (optional - defaults to standard pins)
    // USB.setPins(pinD_minus, pinD_plus, 5, 6);  // D-, D+, rx, tx
    
    // Initialize MSC device with LittleFS
    if (!usb_msc.begin(LittleFS.blockCount() * LittleFS.blockSize(), 
                       LittleFS.blockSize())) {
      logMessage("USBMSCDevice.begin failed");
      return false;
    }
    
    // Register MSC callbacks
    usb_msc.setReadCallback(msc_read_callback);
    usb_msc.setWriteCallback(msc_write_callback);
    
    // Start USB
    USB.begin();
    
    is_active = true;
    logMessage("USB Mass Storage enabled - LittleFS exposed as USB drive");
    
    return true;
  }
  
  void end() {
    if (is_active) {
      USB.end();
      usb_msc.end();
      is_active = false;
      logMessage("USB Mass Storage disabled");
    }
  }
  
  bool isActive() {
    return is_active;
  }
}

#endif
