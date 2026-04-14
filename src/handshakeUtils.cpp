#include "handshakeUtils.h"
#include "logger.h"
#include "settings.h"
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <cstring>
#include <algorithm>

// ============================================================
// PCAP constants
// ============================================================
static const uint32_t PCAP_MAGIC         = 0xa1b2c3d4;
static const uint32_t PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;

// Ethernet type for EAPOL (802.1X)
static const uint16_t ETH_TYPE_EAPOL = 0x888E;

// 802.11 EAPOL-Key descriptor type for RSN/WPA2
static const uint8_t EAPOL_KEY_DESC_RSN = 0x02;

// ============================================================
// EAPOL-Key frame layout offsets (relative to key[0] = KeyDescType)
// Cross-referenced against hostap/wpa_supplicant struct wpa_eapol_key:
//
//  key[ 0]      Key Descriptor Type   (1)
//  key[ 1- 2]   Key Information       (2)   big-endian
//  key[ 3- 4]   Key Length            (2)
//  key[ 5-12]   Replay Counter        (8)
//  key[13-44]   Nonce                 (32)  ANonce in M1, SNonce in M2
//  key[45-60]   Key IV                (16)  ← 16 bytes (not 8!)
//  key[61-68]   Key RSC               (8)
//  key[69-76]   Key ID (reserved)     (8)   ← always 0x00..00 in WPA2
//  key[77-92]   MIC                   (16)  ← real MIC offset is 77
//  key[93-94]   Key Data Length       (2)
//  key[95+]     Key Data              (variable)
// ============================================================
static const uint32_t EAPOL_KEY_INFO_OFFSET  = 1;
static const uint32_t EAPOL_KEY_NONCE_OFFSET = 13;
static const uint32_t EAPOL_KEY_MIC_OFFSET   = 77;   // corrected from 69
static const uint32_t EAPOL_KEY_MIN_LEN      = 95;   // up to and including KeyDataLen

// 802.1X header: ver(1) type(1) bodyLen(2)
static const uint32_t DOT1X_HDR_LEN = 4;

// Offset of MIC within the complete EAPOL frame (from buf[0] = 802.1X version byte):
//   4 bytes 802.1X header + 77 bytes into key descriptor = 81
static const uint32_t EAPOL_MIC_IN_FRAME = DOT1X_HDR_LEN + EAPOL_KEY_MIC_OFFSET; // = 81

// ============================================================
// 802.11 MAC header offsets (after optional radiotap)
// ============================================================
static const uint32_t DOT11_HDR_LEN        = 24;
static const uint32_t DOT11_MGMT_FIXED_LEN = 12;  // fixed params in Beacon/ProbeResp
static const uint32_t DOT11_ADDR1_OFF      = 4;
static const uint32_t DOT11_ADDR2_OFF      = 10;
static const uint32_t DOT11_ADDR3_OFF      = 16;

static const uint8_t DOT11_TAG_SSID        = 0x00;

// ============================================================
// Helpers
// ============================================================
static bool macIsZero(const uint8_t *m) {
    for (int i = 0; i < 6; i++) if (m[i]) return false;
    return true;
}

static void macCopy(uint8_t *dst, const uint8_t *src) {
    memcpy(dst, src, 6);
}

// Parse radiotap header length (little-endian at bytes [2..3]).
// Returns 0 if the buffer is too short, revision != 0, or length is implausible.
static uint16_t radiotapLen(const uint8_t *buf, uint32_t bufLen) {
    if (bufLen < 8) return 0;
    if (buf[0] != 0x00) return 0;  // radiotap revision must be 0
    uint16_t len = (uint16_t)buf[2] | ((uint16_t)buf[3] << 8);
    if (len < 8 || len > bufLen) return 0;
    return len;
}

// ============================================================
// WPA2 PRF-512 (HMAC-SHA1 based)
//
// prf_data[76]:
//   [0..5]   AP MAC (BSSID)
//   [6..11]  Client MAC
//   [12..43] ANonce
//   [44..75] SNonce
//
// IEEE 802.11i §8.5.1.2 / hostap wpa_common.c:
//   PTK = PRF-X(PMK, "Pairwise key expansion",
//               Min(AA,SA) || Max(AA,SA) || Min(ANonce,SNonce) || Max(ANonce,SNonce))
//
// Both MACs AND nonces are sorted (lower value first).
// ============================================================
void wpa_prf512_sha1(const uint8_t pmk[32],
                     const uint8_t prf_data[76],
                     uint8_t ptk[64])
{
    static const char label[] = "Pairwise key expansion";
    const size_t labelLen = strlen(label) + 1; // include NUL terminator

    const uint8_t *apMac     = prf_data;        // [0..5]
    const uint8_t *clientMac = prf_data + 6;    // [6..11]
    const uint8_t *aNonce    = prf_data + 12;   // [12..43]
    const uint8_t *sNonce    = prf_data + 44;   // [44..75]

    uint8_t orderedData[76];

    // Sort MACs: lower MAC first
    if (memcmp(apMac, clientMac, 6) < 0) {
        memcpy(orderedData,     apMac,     6);
        memcpy(orderedData + 6, clientMac, 6);
    } else {
        memcpy(orderedData,     clientMac, 6);
        memcpy(orderedData + 6, apMac,     6);
    }

    // Sort nonces: lower nonce first
    if (memcmp(aNonce, sNonce, 32) < 0) {
        memcpy(orderedData + 12, aNonce, 32);
        memcpy(orderedData + 44, sNonce, 32);
    } else {
        memcpy(orderedData + 12, sNonce, 32);
        memcpy(orderedData + 44, aNonce, 32);
    }

    uint8_t digest[20];
    uint8_t ctr = 0;
    size_t  pos = 0;

    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);

    while (pos < 64) {
        mbedtls_md_hmac_starts(&ctx, pmk, 32);
        mbedtls_md_hmac_update(&ctx, (const uint8_t *)label, labelLen);
        mbedtls_md_hmac_update(&ctx, orderedData, 76);
        mbedtls_md_hmac_update(&ctx, &ctr, 1);
        mbedtls_md_hmac_finish(&ctx, digest);

        size_t chunk = std::min((size_t)20, (size_t)(64 - pos));
        memcpy(ptk + pos, digest, chunk);
        pos += chunk;
        ctr++;
    }

    mbedtls_md_free(&ctx);
}

// ============================================================
// Verify a WPA2 passphrase against the captured handshake.
//
// Steps:
//   1. PBKDF2-SHA1(pass, ssid, 4096, 32)       → PMK
//   2. PRF-512(PMK, MACs+Nonces)                → PTK
//   3. HMAC-SHA1(KCK=PTK[0:16], zeroed-EAPOL)  → MIC
//   4. memcmp(computed MIC[0:16], hs.mic)
// ============================================================
bool wpa2_check_passphrase(const WPA2Handshake &hs, const char *pass)
{
    if (hs.ssid_len == 0 || hs.eapol_len == 0) return false;
    if (hs.eapol_len > WPA2_EAPOL_MAX_LEN)      return false;
    if (EAPOL_MIC_IN_FRAME + 16 > hs.eapol_len) return false;

    uint8_t pmk[32];
    uint8_t ptk[64];
    uint8_t mic[20]; // SHA1 produces 20 bytes; we compare only first 16

    // Step 1: PMK via PBKDF2-SHA1
    {
        mbedtls_md_context_t hctx;
        mbedtls_md_init(&hctx);
        mbedtls_md_setup(&hctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
        mbedtls_pkcs5_pbkdf2_hmac(
            &hctx,
            (const uint8_t *)pass, strlen(pass),
            hs.ssid, hs.ssid_len,
            4096, 32, pmk);
        mbedtls_md_free(&hctx);
    }

    // Step 2: PTK via PRF-512
    wpa_prf512_sha1(pmk, hs.prf_data, ptk);

    // Step 3: MIC — over EAPOL frame with MIC field zeroed
    uint8_t eapolCopy[WPA2_EAPOL_MAX_LEN];
    memcpy(eapolCopy, hs.eapol, hs.eapol_len);
    memset(eapolCopy + EAPOL_MIC_IN_FRAME, 0, 16);

    mbedtls_md_hmac(
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
        ptk, 16,                  // KCK = first 16 bytes of PTK
        eapolCopy, hs.eapol_len,
        mic
    );

    return memcmp(mic, hs.mic, 16) == 0;
}

// ============================================================
// parseEapolKey
// Parse a single EAPOL-Key frame starting at the 802.1X header.
// Fills ANonce (M1) or SNonce + MIC + EAPOL copy (M2) into hs.
// Sets isMsgM1 accordingly.
// Returns false if the frame is not a recognisable WPA2 EAPOL-Key M1 or M2.
// ============================================================
static bool parseEapolKey(const uint8_t *buf, uint32_t len,
                           WPA2Handshake &hs, bool &isMsgM1)
{
    isMsgM1 = false;

    if (len < DOT1X_HDR_LEN + EAPOL_KEY_MIN_LEN + 1) {
        logMessage("[EAPOL] Too short: " + String(len));
        return false;
    }

    // 802.1X type field: 0x03 = EAPOL-Key
    if (buf[1] != 0x03) {
        logMessage("[EAPOL] Not EAPOL-Key, type=0x" + String(buf[1], HEX));
        return false;
    }

    uint16_t bodyLen = (uint16_t)(buf[2] << 8) | buf[3];
    if ((uint32_t)bodyLen + DOT1X_HDR_LEN > len) {
        logMessage("[EAPOL] bodyLen " + String(bodyLen) + " overruns buf " + String(len));
        return false;
    }
    if (bodyLen < EAPOL_KEY_MIN_LEN) {
        logMessage("[EAPOL] bodyLen too small: " + String(bodyLen));
        return false;
    }

    const uint8_t *key = buf + DOT1X_HDR_LEN;

    // Key Descriptor Type: 0x02 = RSN/WPA2, 0xFE = WPA1
    if (key[0] != EAPOL_KEY_DESC_RSN) {
        logMessage("[EAPOL] Unexpected key desc type: 0x" + String(key[0], HEX));
        return false;
    }

    // Key Information word (big-endian)
    uint16_t keyInfo = (uint16_t)(key[EAPOL_KEY_INFO_OFFSET] << 8)
                 |            key[EAPOL_KEY_INFO_OFFSET + 1];

    bool keyAck    = (keyInfo >> 7) & 1;
    bool keyMic    = (keyInfo >> 8) & 1; 
    bool keySecure = (keyInfo >> 9) & 1; 

    isMsgM1      = keyAck  && !keyMic;              // M1: Ack=1, MIC=0
    bool isM3    = keyAck  &&  keyMic;              // M3: Ack=1, MIC=1
    bool isM2    = !keyAck &&  keyMic && !keySecure; 

    logMessage("[EAPOL] keyInfo=0x" + String(keyInfo, HEX) +
               " KeyAck=" + String(keyAck) +
               " KeyMIC=" + String(keyMic));

    if (!isMsgM1 && !isM2 && !isM3) {
        logMessage("[EAPOL] Not M1/M2/M3, skipping");
        return false;
    }

    const uint8_t *nonce = key + EAPOL_KEY_NONCE_OFFSET;

    if (isMsgM1 || isM3) {
        // M1 and M3 both carry ANonce from the AP
        // Always overwrite - the last M1/M3 before M2 is the correct one
        memcpy(hs.prf_data + 12, nonce, 32);
        logMessage("[EAPOL] " + String(isMsgM1 ? "M1" : "M3") + " - ANonce captured");
        // M3 also has a MIC+SNonce situation, but we use M2 for cracking; just return true for ANonce
        if (isM3) {
            isMsgM1 = true; // treat M3 as providing ANonce for our purposes
            return true;
        }
    }

    if (isM2) {
        memcpy(hs.prf_data + 44, nonce, 32);             // SNonce
        memcpy(hs.mic, key + EAPOL_KEY_MIC_OFFSET, 16);  // MIC

        uint32_t frameLen = DOT1X_HDR_LEN + bodyLen;
        if (frameLen <= WPA2_EAPOL_MAX_LEN) {
            memcpy(hs.eapol, buf, frameLen);
            hs.eapol_len = (uint16_t)frameLen;
        } else {
            logMessage("[EAPOL] M2 frame too large: " + String(frameLen));
        }
        logMessage("[EAPOL] M2 - SNonce + MIC captured, eapol_len=" + String(hs.eapol_len));
    }

    return true;
}

// ============================================================
// parseDot11Frame
// Given a pointer to the start of an 802.11 MAC header (radiotap
// already removed), extract SSID/BSSID/clientMAC/EAPOL into outInfo.
// Returns true only if a WPA2 EAPOL-Key M1 or M2 was found.
// ============================================================
static bool parseDot11Frame(const uint8_t *dot11, uint32_t dot11Len, HandshakeInfo &outInfo)
{
    if (dot11Len < DOT11_HDR_LEN) return false;

    uint8_t fc0 = dot11[0];
    uint8_t fc1 = dot11[1];

    uint8_t frameType    = (fc0 >> 2) & 0x03; // 0=Mgmt 1=Ctrl 2=Data
    uint8_t frameSubtype = (fc0 >> 4) & 0x0F;

    // ---- Management frames: harvest SSID from Beacon / Probe Response ----
    if (frameType == 0x00) {
        if (frameSubtype == 8 || frameSubtype == 5) { // Beacon=8, ProbeResponse=5
            // In management frames BSSID = Addr3
            if (macIsZero(outInfo.bssid)) {
                macCopy(outInfo.bssid, dot11 + DOT11_ADDR3_OFF);
                macCopy(outInfo.hs.prf_data, outInfo.bssid);
            }

            uint32_t tagStart = DOT11_HDR_LEN + DOT11_MGMT_FIXED_LEN;
            if (tagStart >= dot11Len) return false;

            uint32_t pos = tagStart;
            while (pos + 2 <= dot11Len) {
                uint8_t tagNum = dot11[pos];
                uint8_t tagLen = dot11[pos + 1];
                if (pos + 2 + (uint32_t)tagLen > dot11Len) break;

                if (tagNum == DOT11_TAG_SSID && tagLen > 0 && tagLen <= 32
                    && outInfo.hs.ssid_len == 0) {
                    memcpy(outInfo.hs.ssid, dot11 + pos + 2, tagLen);
                    outInfo.hs.ssid_len = tagLen;
                    outInfo.ssid = String((char *)(dot11 + pos + 2), tagLen);
                    logMessage("[SSID] Found: \"" + outInfo.ssid + "\"");
                }
                pos += 2 + tagLen;
            }
        }
        return false;
    }

    // ---- Data frames: look for EAPOL ----
    if (frameType != 0x02) return false;

    bool toDS   = (fc1 >> 0) & 1;
    bool fromDS = (fc1 >> 1) & 1;

    // 4-address WDS frames - not relevant to infrastructure WPA2
    if (toDS && fromDS) return false;

    // Determine AP MAC and Client MAC from address roles:
    // IBSS  (toDS=0, fromDS=0): Addr1=DA, Addr2=SA(client), Addr3=BSSID(AP)
    // To AP (toDS=1, fromDS=0): Addr1=BSSID(AP), Addr2=SA(client), Addr3=DA
    // From AP (toDS=0, fromDS=1): Addr1=DA(client), Addr2=BSSID(AP), Addr3=SA
    const uint8_t *macAP, *macClient;
    if (!toDS && !fromDS) {
        macAP     = dot11 + DOT11_ADDR3_OFF;
        macClient = dot11 + DOT11_ADDR2_OFF;
    } else if (toDS) {
        macAP     = dot11 + DOT11_ADDR1_OFF;
        macClient = dot11 + DOT11_ADDR2_OFF;
    } else { // fromDS
        macAP     = dot11 + DOT11_ADDR2_OFF;
        macClient = dot11 + DOT11_ADDR1_OFF;
    }

    // Always update AP MAC from data frames - beacons may not appear before EAPOL
    // For fromDS (AP→Client): Addr2=BSSID is definitive; Addr1=DA may be unicast client
    // For toDS  (Client→AP): Addr1=BSSID is definitive; Addr2=SA is the client
    // Overwrite only if we have a better (non-broadcast, non-zero) address
    auto isBetter = [](const uint8_t *candidate, const uint8_t *current) -> bool {
        if (macIsZero(candidate)) return false;
        if (candidate[0] & 0x01) return false; // multicast/broadcast bit set
        if (macIsZero(current))  return true;   // anything beats zero
        return false; // keep existing once we have a good one
    };

    if (isBetter(macAP, outInfo.bssid)) {
        macCopy(outInfo.bssid, macAP);
        macCopy(outInfo.hs.prf_data, macAP);
    }
    if (isBetter(macClient, outInfo.clientMac)) {
        macCopy(outInfo.clientMac, macClient);
        macCopy(outInfo.hs.prf_data + 6, macClient);
    }
    // For fromDS (M1: AP→Client), Addr1 (DA/client) might be unicast but
    // Addr1 for broadcast probe-responses could be ff:ff:ff:ff:ff:ff.
    // Addr3 in fromDS = SA = also the AP (same as Addr2 = BSSID here), so no help.
    // If clientMac is still zero after fromDS frame, try Addr1 even if it looks like broadcast
    // only as a last resort (M1 is always unicast directed to the client).
    if (fromDS && macIsZero(outInfo.clientMac) && !macIsZero(dot11 + DOT11_ADDR1_OFF)) {
        macCopy(outInfo.clientMac, dot11 + DOT11_ADDR1_OFF);
        macCopy(outInfo.hs.prf_data + 6, dot11 + DOT11_ADDR1_OFF);
    }

    // QoS Data frames carry an extra 2-byte QoS Control field after the base header
    bool     isQoS   = (frameSubtype & 0x08) != 0;
    uint32_t dataOff = DOT11_HDR_LEN + (isQoS ? 2 : 0);

    // LLC/SNAP: AA AA 03 00 00 00 <EtherType 2 bytes>  (8 bytes total)
    if (dataOff + 8 > dot11Len) return false;
    const uint8_t *llc = dot11 + dataOff;

    logMessage("[DBG] LLC bytes: " +
               String(llc[0], HEX) + " " + String(llc[1], HEX) + " " +
               String(llc[2], HEX) + " ET:" +
               String((uint16_t)(llc[6] << 8) | llc[7], HEX) +
               " toDS:" + String(toDS) + " fromDS:" + String(fromDS) +
               " QoS:" + String(isQoS));

    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03) return false;

    uint16_t etherType = (uint16_t)(llc[6] << 8) | llc[7];
    if (etherType != ETH_TYPE_EAPOL) return false;

    const uint8_t *eapol    = llc + 8;
    uint32_t       eapolLen = dot11Len - dataOff - 8;

    bool isMsgM1 = false;
    bool ok = parseEapolKey(eapol, eapolLen, outInfo.hs, isMsgM1);

    // After a successful M1, lock in the MACs from this specific frame
    // (most reliable source since it's the actual handshake frame)
    if (ok && isMsgM1) {
        // For M1 (AP→Client, fromDS=1): AP=Addr2, Client=Addr1
        if (!macIsZero(macAP)) {
            macCopy(outInfo.bssid, macAP);
            macCopy(outInfo.hs.prf_data, macAP);
        }
        if (!macIsZero(macClient) && !(macClient[0] & 0x01)) {
            macCopy(outInfo.clientMac, macClient);
            macCopy(outInfo.hs.prf_data + 6, macClient);
        }
        logMessage("[DBG] M1 MACs - AP: " + bssidToString(outInfo.bssid) +
                   " Client: " + bssidToString(outInfo.clientMac));
    }

    return ok;
}

// ============================================================
// extractHandshakeData
// Strips radiotap (if link type is 127), then parses the 802.11 frame.
// outInfo.linkType must be set before calling (done by extractPcapInfo).
// ============================================================
bool extractHandshakeData(const uint8_t *buf, uint32_t len, HandshakeInfo &outInfo)
{
    const uint8_t *dot11    = buf;
    uint32_t       dot11Len = len;

    if (outInfo.linkType == LINKTYPE_IEEE802_11_RADIOTAP) {
        uint16_t rtLen = radiotapLen(buf, len);
        if (rtLen == 0 || rtLen >= len) return false;
        dot11    = buf + rtLen;
        dot11Len = len - rtLen;
    }
    // LINKTYPE_IEEE802_11 (105) = raw 802.11, no radiotap; parse as-is.

    return parseDot11Frame(dot11, dot11Len, outInfo);
}

// ============================================================
// extractPcapInfo
// Validates the PCAP global header and stores the link-layer type.
// ============================================================
bool extractPcapInfo(File &file, HandshakeInfo &outInfo)
{
    uint8_t header[24];
    file.seek(0);
    if (file.readBytes((char *)header, 24) != 24) return false;

    uint32_t magic = *(uint32_t *)header;
    if (magic != PCAP_MAGIC && magic != PCAP_MAGIC_SWAPPED) {
        logMessage("[Handshake] Invalid PCAP magic: 0x" + String(magic, HEX));
        return false;
    }

    uint32_t linkType = *(uint32_t *)(header + 20);
    outInfo.linkType  = linkType;

    if (linkType == LINKTYPE_IEEE802_11_RADIOTAP) {
        logMessage("[Handshake] Link type: 802.11 + radiotap (127)");
    } else if (linkType == LINKTYPE_IEEE802_11) {
        logMessage("[Handshake] Link type: 802.11 plain (105)");
    } else {
        logMessage("[Handshake] Unknown link type " + String(linkType) +
                   " - falling back to plain 802.11");
        outInfo.linkType = LINKTYPE_IEEE802_11;
    }

    return true;
}

// ============================================================
// validateHandshake
// ============================================================
HandshakeInfo validateHandshake(const String &filePath)
{
    HandshakeInfo info = {};
    memset(&info.hs, 0, sizeof(WPA2Handshake));

    SD_LOCK();
    File file = FSYS.open(filePath, FILE_READ);
    if (!file) { SD_UNLOCK(); logMessage("[Handshake] Failed to open: " + filePath); return info; }
    SD_UNLOCK();

    info.fileSize = file.size();
    logMessage("[Handshake] Opened: " + filePath + " (" + String(info.fileSize) + " bytes)");

    if (!extractPcapInfo(file, info)) {
        file.close();
        return info;
    }

    bool gotM1 = false, gotM2 = false;
    uint8_t aNoncePrev[32] = {};
    uint8_t sNoncePrev[32] = {};

    file.seek(24); // skip PCAP global header

    static uint8_t buffer[1600]; // static to avoid stack overflow on ESP32

    while (file.available()) {
        uint8_t pktHeader[16];
        if (file.readBytes((char *)pktHeader, 16) != 16) break;

        uint32_t inclLen = *(uint32_t *)(pktHeader + 8);
        if (inclLen == 0) continue;
        if (inclLen > sizeof(buffer)) {
            // Packet too large for buffer - skip it
            if (file.seek(file.position() + inclLen) == false) break;
            continue;
        }

        if ((uint32_t)file.readBytes((char *)buffer, inclLen) != inclLen) break;

        info.packetCount++;

        memcpy(aNoncePrev, info.hs.prf_data + 12, 32);
        memcpy(sNoncePrev, info.hs.prf_data + 44, 32);

        bool foundEapol = extractHandshakeData(buffer, inclLen, info);

        if (foundEapol) {
            info.hasEAPOL = true;
            // gotM1 fires if ANonce slot changed (written by M1 or M3)
            if (memcmp(aNoncePrev, info.hs.prf_data + 12, 32) != 0) {
                if (!gotM1) logMessage("[Handshake] ANonce captured in packet #" + String(info.packetCount));
                gotM1 = true;
            }
            // gotM2 fires if SNonce slot changed (written by M2)
            if (memcmp(sNoncePrev, info.hs.prf_data + 44, 32) != 0) {
                if (!gotM2) logMessage("[Handshake] SNonce+MIC captured in packet #" + String(info.packetCount));
                gotM2 = true;
            }
        }
    }

    file.close();

    // A complete crackable handshake needs M1 (ANonce) + M2 (SNonce + MIC + EAPOL) + SSID + BSSID
    bool complete = gotM1 && gotM2 && info.hs.eapol_len > 0;
    info.valid    = complete && info.hs.ssid_len > 0 && !macIsZero(info.bssid);

    logMessage("[Handshake] Result: " + String(info.valid ? "VALID" : "INVALID") +
               " | SSID: \"" + info.ssid + "\""
               " | Pkts: " + String(info.packetCount) +
               " | M1: " + String(gotM1) +
               " | M2: " + String(gotM2) +
               " | EAPOL len: " + String(info.hs.eapol_len) +
               " | SSID len: " + String(info.hs.ssid_len));

    return info;
}

// ============================================================
// loadWordlist
// ============================================================
std::vector<String> loadWordlist(const String &wordlistPath, uint16_t maxWords)
{
    std::vector<String> words;
    words.reserve(std::min((int)maxWords, 512));

    SD_LOCK();
    File file = FSYS.open(wordlistPath, FILE_READ);
    SD_UNLOCK();
    if (!file || file.isDirectory()) {
        logMessage("[Wordlist] Failed to open: " + wordlistPath);
        return words;
    }

    String   line;
    uint16_t count = 0;

    while (file.available() && count < maxWords) {
        int c = file.read();
        if (c == '\n' || c == '\r') {
            // Trim trailing whitespace
            while (line.length() > 0) {
                char last = line[line.length() - 1];
                if (last == '\r' || last == '\n' || last == ' ') {
                    line.remove(line.length() - 1);
                } else break;
            }
            // WPA2 passphrases must be 8-63 printable ASCII characters
            if (line.length() >= 8 && line.length() <= 63) {
                words.push_back(line);
                count++;
            }
            line = "";
            // Consume paired \r\n
            if (c == '\r' && file.available() && file.peek() == '\n') file.read();
        } else if (c > 0) {
            line += (char)c;
        }
    }

    // Handle file not ending with a newline
    if (line.length() >= 8 && line.length() <= 63 && count < maxWords) {
        words.push_back(line);
    }

    file.close();
    logMessage("[Wordlist] Loaded " + String(words.size()) + " candidates from " + wordlistPath);
    return words;
}

// ============================================================
// Async cracker - FreeRTOS task
// ============================================================

// Internal state shared between the cracker task and the public API.
// All fields written by the task; read by any core via getCrackStatus().
// The mutex must be held for any multi-field read or write.
struct CrackState {
    // Config (set before task starts, read-only during run)
    WPA2Handshake hs;
    String        wordlistPath;

    // Live stats (written by task, read by caller)
    volatile bool     running;
    volatile bool     stopRequested;
    volatile bool     cracked;
    volatile uint32_t totalCandidates;   // total words in wordlist
    volatile uint32_t attemptsDone;      // words tested so far
    volatile float    triesPerSecond;
    char              lastTested[64];    // last passphrase attempted (NUL-terminated)
    char              foundPassword[64]; // set on success
};

static CrackState   s_crackState;
static TaskHandle_t s_crackTask   = nullptr;
static SemaphoreHandle_t s_crackMutex = nullptr;

// One-time init - called lazily
static void crackMutexInit() {
    if (s_crackMutex == nullptr) {
        s_crackMutex = xSemaphoreCreateMutex();
    }
}

// The FreeRTOS task function - runs on core 1, stack ~8 KB
static void crackerTaskFn(void *param)
{
    CrackState *st = &s_crackState;

    // ---- Load wordlist (file I/O before tight crypto loop) ----
    std::vector<String> wordlist = loadWordlist(st->wordlistPath, 50000);

    {
        xSemaphoreTake(s_crackMutex, portMAX_DELAY);
        st->totalCandidates = (uint32_t)wordlist.size();
        xSemaphoreGive(s_crackMutex);
    }

    if (wordlist.empty()) {
        logMessage("[Crack] Wordlist empty - task exiting");
        xSemaphoreTake(s_crackMutex, portMAX_DELAY);
        st->running = false;
        xSemaphoreGive(s_crackMutex);
        s_crackTask = nullptr;
        vTaskDelete(nullptr);
        return;
    }

    logMessage("[Crack] Task started | " + String(wordlist.size()) + " candidates");

    // ---- Timing helpers ----
    uint32_t taskStart    = millis();
    uint32_t windowStart  = taskStart;
    uint32_t windowCount  = 0;           // attempts in current 1-second window
    const uint32_t WINDOW_MS = 1000;

    // ---- Main crack loop ----
    for (size_t i = 0; i < wordlist.size(); i++) {

        // Check stop flag - no mutex needed, it's a single volatile bool
        if (st->stopRequested) {
            logMessage("[Crack] Stop requested - aborting at attempt " + String(i));
            break;
        }

        const char *candidate = wordlist[i].c_str();

        // Update last-tested (short critical section for the char copy)
        {
            xSemaphoreTake(s_crackMutex, portMAX_DELAY);
            strncpy(st->lastTested, candidate, sizeof(st->lastTested) - 1);
            st->lastTested[sizeof(st->lastTested) - 1] = '\0';
            st->attemptsDone = (uint32_t)(i + 1);
            xSemaphoreGive(s_crackMutex);
        }

        // Crypto check
        if (wpa2_check_passphrase(st->hs, candidate)) {
            xSemaphoreTake(s_crackMutex, portMAX_DELAY);
            st->cracked = true;
            strncpy(st->foundPassword, candidate, sizeof(st->foundPassword) - 1);
            st->foundPassword[sizeof(st->foundPassword) - 1] = '\0';
            xSemaphoreGive(s_crackMutex);

            uint32_t elapsed = millis() - taskStart;
            logMessage("[Crack] SUCCESS | Password: \"" + String(candidate) +
                       "\" | Attempts: " + String(i + 1) +
                       " | Time: " + String(elapsed) + "ms");
            break;
        }

        windowCount++;

        // Update tries/sec once per second without blocking the crypto loop long
        uint32_t now = millis();
        if (now - windowStart >= WINDOW_MS) {
            float tps = (float)windowCount * 1000.0f / (float)(now - windowStart);
            xSemaphoreTake(s_crackMutex, portMAX_DELAY);
            st->triesPerSecond = tps;
            xSemaphoreGive(s_crackMutex);

            logMessage("[Crack] " + String(i + 1) + "/" + String(st->totalCandidates) +
                       " | " + String(tps, 1) + " t/s");

            windowStart = now;
            windowCount = 0;
        }

        // Yield every 10 attempts so higher-priority tasks and the watchdog are served
        if (i % 10 == 0) vTaskDelay(pdMS_TO_TICKS(1));
    }

    // ---- Cleanup ----
    uint32_t totalElapsed = millis() - taskStart;
    logMessage("[Crack] Done | Attempts: " + String(st->attemptsDone) +
               " | Time: " + String(totalElapsed) + "ms" +
               " | Cracked: " + String(st->cracked ? "YES" : "NO"));

    xSemaphoreTake(s_crackMutex, portMAX_DELAY);
    st->running        = false;
    st->triesPerSecond = 0.0f;
    xSemaphoreGive(s_crackMutex);

    s_crackTask = nullptr;
    vTaskDelete(nullptr);
}

// ============================================================
// startCrackTask
// Validates the handshake then launches the cracker on core 1.
// Returns false if already running or handshake invalid.
// ============================================================
bool startCrackTask(const HandshakeInfo &info, const String &wordlistPath)
{
    crackMutexInit();

    xSemaphoreTake(s_crackMutex, portMAX_DELAY);
    bool alreadyRunning = s_crackState.running;
    xSemaphoreGive(s_crackMutex);

    if (alreadyRunning) {
        logMessage("[Crack] Already running - call stopCrackTask() first");
        return false;
    }

    if (!info.valid) {
        logMessage("[Crack] Handshake not valid - cannot start");
        return false;
    }

    // Sanity check nonces
    bool aNonceOk = false, sNonceOk = false;
    for (int i = 0; i < 32; i++) {
        if (info.hs.prf_data[12 + i]) aNonceOk = true;
        if (info.hs.prf_data[44 + i]) sNonceOk = true;
    }
    if (!aNonceOk || !sNonceOk) {
        logMessage("[Crack] Nonces are zero - cannot start");
        return false;
    }

    // Populate shared state
    xSemaphoreTake(s_crackMutex, portMAX_DELAY);
    memcpy(&s_crackState.hs, &info.hs, sizeof(WPA2Handshake));
    s_crackState.wordlistPath    = wordlistPath;
    s_crackState.running         = true;
    s_crackState.stopRequested   = false;
    s_crackState.cracked         = false;
    s_crackState.totalCandidates = 0;
    s_crackState.attemptsDone    = 0;
    s_crackState.triesPerSecond  = 0.0f;
    s_crackState.lastTested[0]   = '\0';
    s_crackState.foundPassword[0]= '\0';
    xSemaphoreGive(s_crackMutex);

    // 8 KB stack - PBKDF2 is stack-hungry; do not reduce below 6 KB
    BaseType_t ok = xTaskCreatePinnedToCore(
        crackerTaskFn,
        "wpa2_crack",
        8192,
        nullptr,
        1,              // priority 1 - low enough not to starve UI/WiFi
        &s_crackTask,
        1               // pin to core 1 (core 0 runs the Arduino loop / WiFi)
    );

    if (ok != pdPASS) {
        logMessage("[Crack] xTaskCreate failed (out of memory?)");
        xSemaphoreTake(s_crackMutex, portMAX_DELAY);
        s_crackState.running = false;
        xSemaphoreGive(s_crackMutex);
        return false;
    }

    logMessage("[Crack] Task launched | SSID: \"" + info.ssid + "\"");
    return true;
}

// ============================================================
// stopCrackTask
// Signals the cracker to stop. Returns immediately; the task
// will finish its current PBKDF2 iteration then exit (≤ ~100 ms).
// ============================================================
void stopCrackTask()
{
    crackMutexInit();
    s_crackState.stopRequested = true; // volatile write, no mutex needed
    logMessage("[Crack] Stop signal sent");
}

// ============================================================
// getCrackStatus
// Thread-safe snapshot of the cracker's current state.
// Safe to call from any task or the Arduino loop at any time.
// ============================================================
CrackStatus getCrackStatus()
{
    crackMutexInit();

    CrackStatus out = {};
    xSemaphoreTake(s_crackMutex, portMAX_DELAY);

    out.running         = s_crackState.running;
    out.cracked         = s_crackState.cracked;
    out.totalCandidates = s_crackState.totalCandidates;
    out.attemptsDone    = s_crackState.attemptsDone;
    out.triesPerSecond  = s_crackState.triesPerSecond;
    out.lastTested      = String(s_crackState.lastTested);
    out.foundPassword   = String(s_crackState.foundPassword);

    // Progress 0.0-1.0; guard against division by zero before wordlist loads
    if (s_crackState.totalCandidates > 0) {
        out.progress = (float)s_crackState.attemptsDone /
                       (float)s_crackState.totalCandidates;
    } else {
        out.progress = 0.0f;
    }

    xSemaphoreGive(s_crackMutex);
    return out;
}

// ============================================================
// isCrackRunning - lightweight convenience check
// ============================================================
bool isCrackRunning()
{
    return s_crackState.running; // single volatile bool read, no mutex needed
}

// ============================================================
// attemptCrack - kept for backwards compatibility.
// Blocking wrapper around the async task: starts it, polls until
// done, then returns the result. Avoid in UI contexts; prefer
// startCrackTask / getCrackStatus directly.
// ============================================================
CrackResult attemptCrack(const HandshakeInfo &info, const String &wordlistPath)
{
    CrackResult result = {};

    if (!startCrackTask(info, wordlistPath)) return result;

    // Block until the task finishes
    while (isCrackRunning()) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    CrackStatus st   = getCrackStatus();
    result.cracked      = st.cracked;
    result.password     = st.foundPassword;
    result.attemptsCount = st.attemptsDone;
    return result;
}

// ============================================================
// buildHc22000Line
// Builds a single WPA*02 hash line in the hc22000 format:
//
//   WPA*02*<MIC>*<MAC_AP>*<MAC_CLIENT>*<ESSID>*<ANONCE>*<EAPOL_M2>*<MSGPAIR>
//
// All fields are lowercase hex, no separators inside fields.
// MACs are 12 hex chars (no colons).
// MESSAGEPAIR byte:
//   bits 2-0: pair type - 000 = M1+M2, EAPOL from M2 (most common)
//   bit  7:   not-replaycount-checked (set to 1 since we do minimal RC checks)
// We use 0x80 (128) to signal "RC not verified" which hashcat handles fine.
// ============================================================
static String buildHc22000Line(const HandshakeInfo &info)
{
    // Helper lambda: bytes → lowercase hex string
    auto toHex = [](const uint8_t *data, size_t len) -> String {
        String s;
        s.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            char buf[3];
            snprintf(buf, sizeof(buf), "%02x", data[i]);
            s += buf;
        }
        return s;
    };

    // MIC (16 bytes)
    String mic = toHex(info.hs.mic, 16);

    // MACs - 6 bytes each, no colons
    String macAP     = toHex(info.bssid,     6);
    String macClient = toHex(info.clientMac, 6);

    // ESSID - raw SSID bytes as hex (NOT ASCII)
    String essid = toHex(info.hs.ssid, info.hs.ssid_len);

    // ANonce - prf_data[12..43]
    String anonce = toHex(info.hs.prf_data + 12, 32);

    // EAPOL M2 frame - full raw frame as hex
    String eapol = toHex(info.hs.eapol, info.hs.eapol_len);

    // MESSAGEPAIR: 0x80 = M1+M2, EAPOL from M2, replaycount not verified
    // Use 0x02 instead if you want to signal M2+M3 pair (AP-less mode)
    String msgpair = "80";

    return "WPA*02*" + mic + "*" +
           macAP    + "*" +
           macClient + "*" +
           essid    + "*" +
           anonce   + "*" +
           eapol    + "*" +
           msgpair;
}

// ============================================================
// convertToHashcatFormat
//
// Validates the PCAP at `pcapPath`, and if valid writes a .hc22000
// file to `outputPath`.
//
// Returns a human-readable status string describing what happened.
// On success the string starts with "OK:".
// On failure the string starts with "ERR:".
// ============================================================
String convertToHashcatFormat(const String &pcapPath, const String &outputPath)
{
    // ---- Validate the handshake ----
    HandshakeInfo info = validateHandshake(pcapPath);

    if (!info.valid) {
        String reason = "ERR: Handshake invalid - ";
        if (!info.hasEAPOL) {
            reason += "no EAPOL frames found in capture";
        } else if (info.hs.ssid_len == 0) {
            reason += "SSID not found (missing beacon/probe in capture)";
        } else if (macIsZero(info.bssid)) {
            reason += "AP BSSID could not be determined";
        } else {
            reason += "incomplete handshake (need both ANonce and SNonce+MIC)";
        }
        logMessage("[hc22000] " + reason);
        return reason;
    }

    // ---- Build the hash line ----
    String hashLine = buildHc22000Line(info);
    hashLine += "\n"; // hc22000 files are newline-terminated

    // ---- Write the output file ----
    SD_LOCK();
    File out = FSYS.open(outputPath, FILE_WRITE);
    SD_UNLOCK();
    if (!out) {
        String err = "ERR: Could not open output file: " + outputPath;
        logMessage("[hc22000] " + err);
        return err;
    }

    size_t written = out.print(hashLine);
    out.close();

    if (written != hashLine.length()) {
        String err = "ERR: Write incomplete (" + String(written) +
                     "/" + String(hashLine.length()) + " bytes)";
        logMessage("[hc22000] " + err);
        return err;
    }

    logMessage("[hc22000] Written to: " + outputPath);
    logMessage("[hc22000] Hash line:  " + hashLine);

    // ---- Return success summary ----
    String ok = "OK: " + outputPath + "\n";
    ok += "SSID:   " + info.ssid + "\n";
    ok += "BSSID:  " + bssidToString(info.bssid) + "\n";
    ok += "Client: " + bssidToString(info.clientMac) + "\n";
    ok += "\nhashcat -m 22000 " + outputPath + " wordlist.txt";
    return ok;
}

// ============================================================
// getValidationStatus
// ============================================================
String getValidationStatus(const HandshakeInfo &info)
{
    String status;

    if (info.valid) {
        status = "Status:  Valid Handshake (ready to crack)\n";
    } else if (info.hasEAPOL) {
        status = "Status:  Partial - EAPOL found but handshake incomplete\n";
        status += "         Ensure capture contains both M1 and M2\n";
    } else {
        status = "Status:  Invalid - no EAPOL frames found\n";
    }

    status += "SSID:    " + info.ssid + "\n";
    status += "BSSID:   " + bssidToString(info.bssid) + "\n";

    if (!macIsZero(info.clientMac)) {
        status += "Client:  " + bssidToString(info.clientMac) + "\n";
    }

    status += "Packets: " + String(info.packetCount) + "\n";
    status += "Size:    " + String(info.fileSize) + " bytes\n";
    status += "Link:    " + String(info.linkType) + "\n";

    return status;
}

// ============================================================
// Utility helpers
// ============================================================
String bssidToString(const uint8_t *bssid)
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(buf);
}

String ssidToHex(const String &ssid)
{
    String result;
    result.reserve(ssid.length() * 2);
    for (size_t i = 0; i < (size_t)ssid.length(); i++) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", (uint8_t)ssid[i]);
        result += buf;
    }
    return result;
}