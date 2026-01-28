#pragma once

#include <Arduino.h>

#ifdef USE_LITTLEFS

// USB Mass Storage Device for LittleFS
namespace USBMassStorage {
  
  // Initialize USB mass storage (exposes LittleFS as USB drive)
  bool begin(int pinD_minus = 18, int pinD_plus = 20);
  
  // Stop USB mass storage
  void end();
  
  // Check if USB is active
  bool isActive();
}

#endif
