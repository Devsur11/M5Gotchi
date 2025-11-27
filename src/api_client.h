#pragma once
#include <Arduino.h>
#include <vector>
#include <string>
struct NetRequest {
    String url;
    String body;
    bool doPost;
    bool auth;
    int id;
};

struct NetResponse {
    int id;
    String body;
    int code;
};


namespace api_client {
bool init(const String &keysPath);
bool enrollWithGrid(); // registers, stores token in /token.json
bool sendMessageTo(const String &recipientFingerprint, const String &cleartext);
bool pollInbox(); // fetches messages, verifies and decrypts, prints to Serial
String getNameFromFingerprint(String fingerprint);
time_t timegm(struct tm* t);
uint32_t isoToUnix(const String &iso);
void initTime();
bool sub_init(const String &keysPath);
}