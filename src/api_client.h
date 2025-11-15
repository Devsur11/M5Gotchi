#pragma once
#include <Arduino.h>
#include <vector>
#include <string>

namespace api_client {
bool init(const String &keysPath);
bool enrollWithGrid(); // registers, stores token in /token.json
bool sendMessageTo(const String &recipientFingerprint, const String &cleartext);
bool pollInbox(); // fetches messages, verifies and decrypts, prints to Serial
String getNameFromFingerprint(String fingerprint);
}