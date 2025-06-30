#include "Arduino.h"

#pragma once

void setWhitelistFromArray(String* arr);
void addToWhitelist(String valueToAdd);
String* parseWhitelist();
void pwnagothiLoop();
bool pwnagothiBegin();
void delayWithUI(uint16_t delayTime);
void removeItemFromWhitelist(String valueToRemove);