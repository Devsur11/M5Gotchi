#pragma once
#include <Arduino.h>
#include <vector>
#include <string>

namespace pwngrid {
namespace crypto {

// Initialize / ensure keys exist under keysPath (e.g. "/sd/keys").
// If missing, generates RSA keypair (VERY SLOW for 4096 bits).
// Returns true on success.
bool ensureKeys(const String &keysPath);

// Sign message bytes using RSA-PSS + SHA256. outSig filled with signature bytes.
// Returns true on success.
bool signMessage(const std::vector<uint8_t> &msg, std::vector<uint8_t> &outSig);

// Verify signature (RSA-PSS + SHA256) using provided public PEM (text).
bool verifyMessageWithPubPEM(const std::vector<uint8_t> &msg, const std::vector<uint8_t> &sig, const String &pubPEM);

// Encrypt cleartext for recipient public key PEM. Output format:
// nonce(12) || keySize(4 little endian) || encKey || ciphertext || tag(16)
// Returns true on success.
bool encryptFor(const std::vector<uint8_t> &cleartext, const String &recipientPubPEM, std::vector<uint8_t> &out);

// Decrypt messages produced by encryptFor (inverse format).
// Returns true and fills outCleartext on success.
bool decrypt(const std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &outCleartext);

// Load PEM strings from SD (private/public). Return true on success.
bool loadPrivatePEM(String &out);
bool loadPublicPEM(String &out);

// Convenience: return public key PEM as base64-encoded string (like server expects).
String publicPEMBase64();

// Base64 helpers
String base64Encode(const std::vector<uint8_t> &data);
std::vector<uint8_t> base64Decode(const String &b64);

// Helper to meet all pwngrid api requiements
static String normalizePublicPEM(const String &pem_in);

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
