#pragma once
#include <Arduino.h>
#include <vector>
#include <string>

namespace pwngrid {
namespace crypto {

bool ensureKeys(const String &keysPath);
bool signMessage(const std::vector<uint8_t> &msg, std::vector<uint8_t> &outSig);
bool verifyMessageWithPubPEM(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig, const String &pubPEM);
bool encryptFor(const std::vector<uint8_t> &cleartext, const String &recipientPubPEM, std::vector<uint8_t> &out);
bool decrypt(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &outCleartext);
bool loadPrivatePEM(String &out);
bool loadPublicPEM(String &out);
String publicPEMBase64();
String base64Encode(const std::vector<uint8_t> &data);
std::vector<uint8_t> base64Decode(const String &b64);
String encryptWithPassword(const std::vector<uint8_t> &plaintext, const String &password);
bool decryptWithPassword(const String &ciphertext_b64, const String &password, std::vector<uint8_t> &outPlaintext);
static String normalizePublicPEM(const String &pem_in) {
    std::string s((const char*)pem_in.c_str(), pem_in.length());
    const std::string in_begin = "-----BEGIN PUBLIC KEY-----";
    const std::string in_end   = "-----END PUBLIC KEY-----";
    const std::string out_begin = "-----BEGIN RSA PUBLIC KEY-----";
    const std::string out_end   = "-----END RSA PUBLIC KEY-----";

    size_t p = s.find(in_begin);
    if (p != std::string::npos) s.replace(p, in_begin.length(), out_begin);
    p = s.find(in_end);
    if (p != std::string::npos) s.replace(p, in_end.length(), out_end);

    // normalize trailing newlines to exactly one '\n'
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    s.push_back('\n');

    return String(s.c_str());
}
static String deNormalizePublicPEM(const String &pem_in) {
    std::string s((const char*)pem_in.c_str(), pem_in.length());
    const std::string in_begin = "-----BEGIN RSA PUBLIC KEY-----";
    const std::string in_end   = "-----END RSA PUBLIC KEY-----";
    const std::string out_begin = "-----BEGIN PUBLIC KEY-----";
    const std::string out_end   = "-----END PUBLIC KEY-----";

    size_t p = s.find(in_begin);
    if (p != std::string::npos) s.replace(p, in_begin.length(), out_begin);
    p = s.find(in_end);
    if (p != std::string::npos) s.replace(p, in_end.length(), out_end);

    // normalize trailing newlines to exactly one '\n'
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    s.push_back('\n');

    return String(s.c_str());
}

static String trimString(const String &s) {
    int start = 0;
    int end = s.length() - 1;
    while (start <= end && isspace((unsigned char)s[start])) start++;
    while (end >= start && isspace((unsigned char)s[end])) end--;
    if (start == 0 && end == (int)s.length() - 1) return s;
    if (end < start) return String();
    return s.substring(start, end + 1);
}

} // namespace crypto
} // namespace pwngrid
