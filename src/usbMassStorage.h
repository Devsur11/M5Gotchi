#pragma once

#include <Arduino.h>


// Web-based File Manager for LittleFS
// Provides a complete web interface for managing files on the ESP32.
// Users can upload, download, edit, copy, delete files and directories.
// The server runs on port 8080 and must be explicitly shutdown to free resources.
namespace USBMassStorage {
  
  // Initialize the web file manager server
  // Starts an AsyncWebServer on port 8080 with a complete file management UI
  // Features:
  //  - Browse directories
  //  - Upload files
  //  - Download files
  //  - Create folders
  //  - Edit text files directly in browser
  //  - Delete files and folders
  //  - Real-time storage info display
  // Parameters:
  //  - pinD_minus: (deprecated, ignored) kept for API compatibility
  //  - pinD_plus: (deprecated, ignored) kept for API compatibility
  bool begin(int pinD_minus = 18, int pinD_plus = 20);
  
  // Shutdown the web file manager server and free all resources
  // IMPORTANT: Call this to prevent memory leaks when done using the file manager
  // After calling end(), call begin() again to restart the server
  void end();
  
  // Check if the web file manager is currently active
  bool isActive();
}

