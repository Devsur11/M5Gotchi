#include <Arduino.h>
#include <vector>
#include <SD.h>
#include <map>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "wardrive.h"
#include "logger.h"
#include "crypto.h"
#include "settings.h"

static const int GPS_RX_PIN = 15; // AT6H TX -> ESP RX
static const int GPS_TX_PIN = 13; // AT6H RX <- ESP TX
static const int GPS_BAUD = 115200;
int tot_observed_networks = 0;

// Session filename state
static String currentWardrivePath = "/wardriving/first_seen.csv";
static bool filenameLocked = false; // once set by startWardriveSession, stays until explicitly changed

// First-seen map (persistent on SD)
static const char* FIRST_SEEN_PATH = "/wardriving/first_seen.csv";

// Internal representation of a parsed fix
struct GpsFix {
    bool valid = false;
    double lat = 0.0;
    double lon = 0.0;
    double hdop = 0.0;
    double alt = 0.0;
    String timeIso; // ISO timestamp if available (UTC)
    String fixType; // "GPRMC" or "GPGGA"
};

// ---- helpers (unchanged, lightly adjusted) ----
static double nmeaToDecimal(const String& field, char dir) {
    if (field.length() < 4) return NAN;
    double val = field.toFloat();
    int degDigits = (dir == 'N' || dir == 'S') ? 2 : 3;
    double degrees = floor(val / 100.0);
    double minutes = val - (degrees * 100.0);
    double dec = degrees + (minutes / 60.0);
    if (dir == 'S' || dir == 'W') dec = -dec;
    return dec;
}

static String makeIsoTimestamp(const String& timestr, const String& datestr) {
    if (timestr.length() < 6) return String();
    int hour = timestr.substring(0,2).toInt();
    int minute = timestr.substring(2,4).toInt();
    int second = timestr.substring(4,6).toInt();
    int day=0, month=0, year=0;
    if (datestr.length() >= 6) {
        day = datestr.substring(0,2).toInt();
        month = datestr.substring(2,4).toInt();
        year = datestr.substring(4,6).toInt() + 2000;
    } else {
        char buf[64];
        snprintf(buf, sizeof(buf), "T%02d:%02d:%02dZ", hour, minute, second);
        return String(buf);
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second);
    return String(buf);
}

static void parseNmeaLine(const String& line, GpsFix& fix) {
    if (line.length() < 5) return;
    if (!(line.startsWith("$GPRMC") || line.startsWith("$GNRMC") || line.startsWith("$GPGGA") || line.startsWith("$GNGGA") || line.startsWith("$GNZDA"))) return;

    std::vector<String> fields;
    size_t start = 0;
    for (;;) {
        int idx = line.indexOf(',', start);
        if (idx == -1) {
            fields.push_back(line.substring(start));
            break;
        }
        fields.push_back(line.substring(start, idx));
        start = idx + 1;
    }

    if (line.startsWith("$GPRMC") || line.startsWith("$GNRMC")) {
        if (fields.size() >= 10) {
            String timeStr = fields[1];
            String statField = fields[2];
            if (statField == "A") {
                String latField = fields[3];
                char latDir = (fields[4].length()>0)?fields[4][0]:'N';
                String lonField = fields[5];
                char lonDir = (fields[6].length()>0)?fields[6][0]:'E';
                String dateStr = fields[9];

                double lat = nmeaToDecimal(latField, latDir);
                double lon = nmeaToDecimal(lonField, lonDir);

                if (!isnan(lat) && !isnan(lon)) {
                    fix.valid = true;
                    fix.lat = lat;
                    fix.lon = lon;
                    fix.timeIso = makeIsoTimestamp(timeStr, dateStr);
                    fix.fixType = "GPRMC";
                }
            }
        }
    } else if (line.startsWith("$GPGGA") || line.startsWith("$GNGGA")) {
        if (fields.size() >= 10) {
            String timeStr = fields[1];
            String latField = fields[2];
            char latDir = (fields[3].length()>0)?fields[3][0]:'N';
            String lonField = fields[4];
            char lonDir = (fields[5].length()>0)?fields[5][0]:'E';
            String hdopStr = fields[8];
            String altStr = fields[9];

            double lat = nmeaToDecimal(latField, latDir);
            double lon = nmeaToDecimal(lonField, lonDir);

            if (!isnan(lat) && !isnan(lon)) {
                fix.valid = true;
                fix.lat = lat;
                fix.lon = lon;
                if (hdopStr.length()) fix.hdop = hdopStr.toFloat();
                if (altStr.length()) fix.alt = altStr.toFloat();
                fix.fixType = "GPGGA";
                if (timeStr.length() >= 6) {
                    char buf[32];
                    int hour = timeStr.substring(0,2).toInt();
                    int minute = timeStr.substring(2,4).toInt();
                    int second = timeStr.substring(4,6).toInt();
                    snprintf(buf, sizeof(buf), "T%02d:%02d:%02dZ", hour, minute, second);
                    fix.timeIso = String(buf);
                }
            }
        }
    } else if (line.startsWith("$GNZDA")) {
        if (true) {
            String timeStr = fields[1];
            String dayStr = fields[2];
            String monthStr = fields[3];
            String yearStr = fields[4];

            if (timeStr.length() >= 6 && dayStr.length() >= 1 && monthStr.length() >= 1 && yearStr.length() >= 4) {
                int day = dayStr.toInt();
                int month = monthStr.toInt();
                int year = yearStr.toInt();
                int hour = timeStr.substring(0,2).toInt();
                int minute = timeStr.substring(2,4).toInt();
                int second = timeStr.substring(4,6).toInt();

                char buf[64];
                snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second);
                fix.timeIso = String(buf);
            }
        }
    }
}

static String bssidToString(const uint8_t bssid[6]) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(buf);
}

static int channelToFrequency(int ch) {
    if (ch <= 0) return 0;
    if (ch <= 14) return 2407 + ch * 5; // 2.4GHz
    return 5000 + ch * 5; // rough 5GHz mapping (approx)
}

// ---- first-seen persistence ----
static void ensureWardrivingDir() {
    // ensure directory exists; SD.mkdir returns true if directory created or already exists
    if (!SD.exists("/wardriving")) {
        SD.mkdir("/wardriving");
    }
}

// Public helper: manually set filename (if user wants to override)
void setWardriveFilename(const String& path) {
    ensureWardrivingDir();
    currentWardrivePath = path;
    filenameLocked = true;
}

// Public: start session and attempt to get GPS timestamp to build filename.
// If it fails, fallback to millis() style filename.
void startWardriveSession(unsigned long gpsTimeoutMs) {
    // attempt quick GPS read to get ISO timestamp
    if(!useCustomGPSPins){
        Serial2.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    }
    else{
        Serial2.begin(GPS_BAUD, SERIAL_8N1, gpsRx, gpsTx);
    }
    GpsFix bestFix;
    unsigned long start = millis();
    String lineBuf;
    while (millis() - start < gpsTimeoutMs) {
        while (Serial2.available()) {
            char c = (char)Serial2.read();
            if (c == '\r') continue;
            if (c == '\n') {
                String line = lineBuf;
                lineBuf = String();
                if (line.length() > 6) {
                    GpsFix temp = bestFix;
                    parseNmeaLine(line, temp);
                    if (temp.valid) {
                        bestFix = temp;
                        // if we have a full ISO date/time, we can break early
                        if (bestFix.timeIso.length() >= 20) break;
                    }
                }
            } else {
                lineBuf += c;
                if (lineBuf.length() > 120) lineBuf = lineBuf.substring(lineBuf.length() - 120);
            }
        }
        if (bestFix.valid && bestFix.timeIso.length() >= 16) break;
        delay(5);
    }

    ensureWardrivingDir();
    String fname;
    if (bestFix.valid && bestFix.timeIso.length() >= 10) {
        // construct YYYYMMDD_HHMMSS
        String ts = bestFix.timeIso; // maybe "YYYY-MM-DDTHH:MM:SSZ" or "T..." fallback
        // try to extract date/time components
        int year = 1970, month = 1, day = 1, hour = 0, min = 0, sec = 0;
        if (ts.startsWith("T")) {
            // no date, fallback to millis-based name
        } else {
            // parse "YYYY-MM-DDTHH:MM:SSZ"
            year = ts.substring(0,4).toInt();
            month = ts.substring(5,7).toInt();
            day = ts.substring(8,10).toInt();
            hour = ts.substring(11,13).toInt();
            min = ts.substring(14,16).toInt();
            sec = ts.substring(17,19).toInt();
            char buf[64];
            snprintf(buf, sizeof(buf), "wardriving/wardrive_%04d%02d%02d_%02d%02d%02d.csv",
                     year, month, day, hour, min, sec);
            fname = String(buf);
        }
    }
    if (fname.length() == 0) {
        // fallback: use millis timestamp
        unsigned long t = millis();
        char buf[64];
        snprintf(buf, sizeof(buf), "wardriving/wardrive_millis_%lu.csv", t);
        fname = String(buf);
    }
    currentWardrivePath = "/" + fname; // ensure leading slash
    filenameLocked = true;

    fLogMessage("Wardrive session file set to: %s", currentWardrivePath.c_str());
}

// ---- upload to Wigle ----
// Wigle accepts Basic-auth style API name/token. The "Encoded for use" token you get from your
// account page is a base64-encoded credential and can be used directly in an Authorization header.
// See community references on Wigle token usage. :contentReference[oaicite:1]{index=1}
//
// This function opens `csvPath`, reads the contents, and POSTs it to an upload endpoint with
// Authorization: Basic <encodedToken>. If Wigle API endpoint requires different path/params,
// change the URL below.
//
// Returns true on HTTP 2xx. If outHttpCode provided, filled with returned HTTP code.
bool uploadToWigle(const String& encodedToken, const char* csvPath, int* outHttpCode) {
    if (!SD.exists(csvPath)) {
        fLogMessage("uploadToWigle: file does not exist: %s", csvPath);
        if (outHttpCode) *outHttpCode = 0;
        return false;
    }

    File f = SD.open(csvPath, FILE_READ);
    if (!f) {
        if (outHttpCode) *outHttpCode = 0;
        return false;
    }

    size_t fileSize = f.size();
    fLogMessage("uploadToWigle: streaming upload, file size: %u bytes", (unsigned)fileSize);

    WiFiClientSecure client;
    client.setInsecure();

    const char* uploadUrl = "https://api.wigle.net/api/v2/file/upload";
    const char* host = "api.wigle.net";

    if (!client.connect(host, 443)) {
        fLogMessage("uploadToWigle: connection failed");
        if (outHttpCode) *outHttpCode = 0;
        f.close();
        return false;
    }

    // Use multipart/form-data with a boundary so the Wigle API accepts the upload
    String filename = csvPath;
    int lastSlash = filename.lastIndexOf('/');
    if (lastSlash >= 0) filename = filename.substring(lastSlash + 1);

    // Create a reasonably-unique boundary
    String boundary = "----WiGLEBoundary" + String(millis());

    String preamble = String("--") + boundary + "\r\n";
    preamble += String("Content-Disposition: form-data; name=\"file\"; filename=\"") + filename + "\"\r\n";
    preamble += "Content-Type: text/csv\r\n\r\n";

    String closing = String("\r\n--") + boundary + "--\r\n";

    // Compute total content length: preamble + file + closing
    size_t contentLength = preamble.length() + (size_t)fileSize + closing.length();

    client.print(String("POST /api/v2/file/upload HTTP/1.1\r\n"));
    client.print(String("Host: ") + host + "\r\n");
    // Normalize the provided API key/token. Users may provide either:
    // - a plain "name:token" pair (we will base64-encode it),
    // - a base64-encoded credential (as provided by Wigle's "Encoded for use" token), or
    // - a bare token (less likely to work; we send it as-is and log a warning).
    String authHeaderB64;
    String key = encodedToken;
    key.trim();
    if (key.length() == 0) {
        fLogMessage("uploadToWigle: warning: empty Wigle API key provided");
    }
    // If it contains a colon, treat as plain name:token and base64-encode
    if (key.indexOf(':') >= 0) {
        std::vector<uint8_t> bytes;
        bytes.reserve(key.length());
        for (size_t i = 0; i < (size_t)key.length(); ++i) bytes.push_back((uint8_t)key[i]);
        authHeaderB64 = pwngrid::crypto::base64Encode(bytes);
        fLogMessage("uploadToWigle: encoded plain name:token into base64 credential");
    } else {
        // Try to base64-decode and check if it yields a name:token; if so, assume it's valid
        auto dec = pwngrid::crypto::base64Decode(key);
        bool dec_has_colon = false;
        for (auto b : dec) if (b == (uint8_t)':') { dec_has_colon = true; break; }
        if (dec_has_colon) {
            authHeaderB64 = key; // already proper base64-encoded credential
            fLogMessage("uploadToWigle: using provided base64-encoded credential");
        } else {
            // Ambiguous: user provided token only (no colon, not decodable to name:token)
            // Send it as-is but log a warning suggesting correct formats.
            authHeaderB64 = key;
            fLogMessage("uploadToWigle: warning: API key appears to be a bare token; consider using 'name:token' or the encoded credential from https://wigle.net/account");
        }
    }
    client.print(String("Authorization: Basic ") + authHeaderB64 + "\r\n");
    client.print("User-Agent: M5Gotchi-ESPBlaster/1.0\r\n");
    client.print(String("Content-Type: multipart/form-data; boundary=") + boundary + "\r\n");
    client.print("Connection: close\r\n");
    client.print(String("Content-Length: ") + contentLength + "\r\n\r\n");

    // Send preamble
    client.print(preamble);

    // Stream the file body
    const size_t bufSize = 2048;
    uint8_t buf[bufSize];
    while (true) {
        int r = f.read(buf, bufSize);
        if (r <= 0) break;
        client.write(buf, r);
    }

    // Send closing boundary
    client.print(closing);
    f.close();

    // Read response headers
    String line;
    int httpCode = 0;

    unsigned long timeout = millis() + 8000;
    while (millis() < timeout) {
        if (client.available()) {
            line = client.readStringUntil('\n');
            if (line.startsWith("HTTP/1.1 ")) {
                httpCode = line.substring(9, 12).toInt();
            }
            if (line == "\r") break;
        }
    }

    if (outHttpCode) *outHttpCode = httpCode;
    fLogMessage("uploadToWigle: HTTP %d", httpCode);

    // Read response body (if any) for debugging and log a short snippet
    String respBody;
    unsigned long bodyTimeout = millis() + 3000;
    while (millis() < bodyTimeout) {
        while (client.available()) {
            respBody += client.readString();
            // prevent unbounded growth
            if (respBody.length() > 2048) {
                respBody = respBody.substring(0, 2048);
                break;
            }
        }
        if (!client.connected()) break;
    }
    if (respBody.length()) {
        // Log only beginning to avoid huge logs
        String snippet = respBody;
        if (snippet.length() > 512) snippet = snippet.substring(0, 512);
        fLogMessage("uploadToWigle: response body: %s", snippet.c_str());
    }

    return (httpCode >= 200 && httpCode < 300);
}


// ---- main wardrive function (signature changed: no filename param) ----
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// Returns wardriveStatus as before (keeps same struct contents)
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs) {
    if (networks.empty()) return {false, false, 0.0, 0.0, 0.0, 0.0, String(), 0, 0};

    // ensure SD dir is there
    ensureWardrivingDir();

    // Ensure firstSeenMap loaded - TOO HEAVY ON MEMORY
    // if (firstSeenMap.empty()) loadFirstSeenMap();

    // Initialize GPS serial (Serial2)
    Serial2.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    GpsFix bestFix;
    unsigned long start = millis();
    String lineBuf;

    while (millis() - start < timeoutMs) {
        while (Serial2.available()) {
            char c = (char)Serial2.read();
            if (c == '\r') continue;
            if (c == '\n') {
                String line = lineBuf;
                lineBuf = String();
                if (line.length() > 6) {
                    GpsFix temp = bestFix;
                    parseNmeaLine(line, temp);
                    if (temp.valid) {
                        if (!bestFix.valid) {
                            bestFix = temp;
                        } else {
                            if (temp.fixType == "GPGGA" || (temp.hdop > 0 && bestFix.hdop == 0)) {
                                bestFix = temp;
                            } else {
                                bestFix.lat = temp.lat;
                                bestFix.lon = temp.lon;
                                bestFix.timeIso = temp.timeIso;
                            }
                        }
                    }
                }
            } else {
                lineBuf += c;
                if (lineBuf.length() > 120) lineBuf = lineBuf.substring(lineBuf.length() - 120);
            }
        }
        delay(5);
    }

    fLogMessage("Best GPS fix: valid=%d lat=%.6f lon=%.6f hdop=%.2f alt=%.2f time=%s",
               bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso.c_str());

    // Open session file for append (create with wigle header if new)
    File f = SD.open(currentWardrivePath.c_str(), FILE_APPEND);
    if (!f) {
        fLogMessage("Cannot open wardrive file: %s", currentWardrivePath.c_str());
        return {false, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, 0, 0};
    }

    if (f.size() == 0) {
        // Wigle CSV header (matching the template in the screenshot)
        // Columns: BSSID,SSID,Capabilities,First timestamp seen,Channel,Frequency,RSSI,Latitude,Longitude,Altitude,Accuracy,RCOIs,MfgId,Type
        f.println("WigleWifi-1.4,appRelease=M5Gotchi,model=M5Gotchi,release=1");
        f.println("\"BSSID\",\"SSID\",\"Capabilities\",\"First timestamp seen\",\"Channel\",\"Frequency\",\"RSSI\",\"Latitude\",\"Longitude\",\"Altitude\",\"Accuracy\",\"RCOIs\",\"MfgId\",\"Type\"");
    }

    uint8_t written = 0;
    for (const auto& net : networks) {
        // require GPS location for wigle entries (kismet/wigle behavior)
        if (!bestFix.valid) {
            fLogMessage("No valid GPS fix; skipping network logging for SSID: %s", net.ssid.c_str());
            continue;
        }

        String macStr = bssidToString(net.bssid);
        String ssidEsc = net.ssid;
        ssidEsc.replace("\"", "\"\"");

        // Capabilities: we have limited info; approximate
        String caps = "[ESS]";
        if (net.secure) {
            caps = "[WPA2-PSK-CCMP][ESS]";
        }
        int ch = net.channel;
        int freq = channelToFrequency(ch);
        int rssi = net.rssi;
        // First seen: always match Wigle CSV timestamp format
        WigleEntry entry;
        entry.bssid = macStr;
        entry.ssid = ssidEsc;
        entry.capabilities = caps;
        entry.channel = ch;
        entry.frequency = freq;
        entry.rssi = rssi;
        entry.lat = bestFix.lat;
        entry.lon = bestFix.lon;
        entry.alt = bestFix.alt;
        entry.accuracy = bestFix.hdop;
        entry.rcois = "";
        entry.mfgid = "";
        entry.type = "WIFI";

        //skipped - to heavy on memory
        if (false){//firstSeenMap.find(macStr) != firstSeenMap.end()) {
            //entry.firstSeen = firstSeenMap[macStr].firstSeen;
        } else {
            entry.firstSeen = bestFix.timeIso;
            // appendFirstSeenToDisk(entry);
        }

        String latStr = String(bestFix.lat, 6);
        String lonStr = String(bestFix.lon, 6);
        String altStr = (bestFix.alt != 0.0) ? String(bestFix.alt, 2) : "";
        String accStr = (bestFix.hdop > 0) ? String(bestFix.hdop, 2) : "";

        // Assemble CSV line matching Wigle template
        // Escape SSID already; MAC and simple numeric fields safe
        char buf[1024];
        snprintf(buf, sizeof(buf),
                 "\"%s\",\"%s\",\"%s\",\"%s\",%d,%d,%d,%s,%s,%s,%s,,\"%s\"",
                 macStr.c_str(),
                 ssidEsc.c_str(),
                 caps.c_str(),
                 entry.firstSeen.c_str(),
                 ch,
                 freq,
                 rssi,
                 latStr.c_str(),
                 lonStr.c_str(),
                 altStr.c_str(),
                 accStr.c_str(),
                 "WIFI");

        f.println(buf);
        written++;
    }

    f.close();
    tot_observed_networks += written;
    return {written > 0, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, tot_observed_networks, (uint8_t)written};
}
