#include <cstdio>
#include <string>
#include "logger.h"
#include "M5Cardputer.h"
#include "Arduino.h"

void logMessage(String message) {
    printf("%s\n", message.c_str());
}