#pragma once

#include <Arduino.h>

namespace sdmanager {
  void runFileManager();
  String selectFile(const String allowedExtentions);
}
