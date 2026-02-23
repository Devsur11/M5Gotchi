#pragma once
#include <Arduino.h>
#include <FS.h>
#include <vector>
#include <cstring>

#define WPA2_EAPOL_MAX_LEN  256

// PCAP link-layer types we support
#define LINKTYPE_IEEE802_11         105   // Plain 802.11, no radiotap
#define LINKTYPE_IEEE802_11_RADIOTAP 127  // 802.11 with radiotap header

// PCAP file structures
struct PcapPacket {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

// WPA2 Handshake data structure for cracking
struct WPA2Handshake {
    uint8_t  ssid[32];
    uint16_t ssid_len;
    uint8_t  bssid[6];
    uint8_t  client_mac[6];
    uint8_t  eapol[WPA2_EAPOL_MAX_LEN];  // EAPOL frame data (M2, with MIC field intact)
    uint16_t eapol_len;
    uint8_t  mic[16];                     // MIC extracted from M2
    // prf_data layout (76 bytes):
    //   [0..5]   AP MAC (BSSID)
    //   [6..11]  Client MAC
    //   [12..43] ANonce (from M1)
    //   [44..75] SNonce (from M2)
    uint8_t  prf_data[76];
};

// Handshake info extracted from PCAP
struct HandshakeInfo {
    String   ssid;
    uint8_t  bssid[6];
    uint8_t  clientMac[6];
    bool     valid;
    bool     hasEAPOL;
    uint32_t packetCount;
    uint32_t fileSize;
    uint32_t linkType;    // PCAP link-layer type (105 or 127)
    WPA2Handshake hs;
};

// Cracking attempt result (returned by blocking attemptCrack)
struct CrackResult {
    bool     cracked;
    String   password;
    uint32_t attemptsCount;
};

// Live status snapshot returned by getCrackStatus()
struct CrackStatus {
    bool     running;           // true while the cracker task is alive
    bool     cracked;           // true if password was found
    uint32_t totalCandidates;   // total words in wordlist (0 until wordlist is loaded)
    uint32_t attemptsDone;      // words tested so far
    float    triesPerSecond;    // rolling 1-second average
    float    progress;          // 0.0 - 1.0
    String   lastTested;        // most recent passphrase attempted
    String   foundPassword;     // set when cracked == true
};

HandshakeInfo validateHandshake(const String& filePath);
bool extractPcapInfo(File &file, HandshakeInfo &outInfo);
bool extractHandshakeData(const uint8_t *pcapData, uint32_t dataLen, HandshakeInfo &outInfo);
String convertToHashcatFormat(const String &pcapPath, const String &outputPath);
std::vector<String> loadWordlist(const String &wordlistPath, uint16_t maxWords = 1000);
bool startCrackTask(const HandshakeInfo &info, const String &wordlistPath);
void stopCrackTask();
CrackStatus getCrackStatus();
bool isCrackRunning();
CrackResult attemptCrack(const HandshakeInfo &info, const String &wordlistPath);
bool wpa2_check_passphrase(const WPA2Handshake &hs, const char *pass);
void wpa_prf512_sha1(const uint8_t pmk[32], const uint8_t *data, uint8_t ptk[64]);
String getValidationStatus(const HandshakeInfo &info);
String bssidToString(const uint8_t *bssid);
String ssidToHex(const String &ssid);