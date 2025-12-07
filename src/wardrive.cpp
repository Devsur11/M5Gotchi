#include <Arduino.h>
#include <vector>
#include <SD.h>
#include <map>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "wardrive.h"
#include "logger.h"

static const int GPS_RX_PIN = 15; // AT6H TX -> ESP RX
static const int GPS_TX_PIN = 13; // AT6H RX <- ESP TX
static const int GPS_BAUD = 115200;
int tot_observed_networks = 0;

// Session filename state
static String currentWardrivePath = "/wardriving/wardrive.csv";
static bool filenameLocked = false; // once set by startWardriveSession, stays until explicitly changed

// First-seen map (persistent on SD)
static const char* FIRST_SEEN_PATH = "/wardriving/first_seen.csv";
static std::map<String, WigleEntry> firstSeenMap;

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

static void loadFirstSeenMap() {
    firstSeenMap.clear();
    ensureWardrivingDir();

    if (!SD.exists(FIRST_SEEN_PATH)) return;
    File f = SD.open(FIRST_SEEN_PATH, FILE_READ);
    if (!f) return;

    // skip header
    String header = f.readStringUntil('\n');

    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() == 0) continue;

        std::vector<String> cols;
        int start = 0;
        for (;;) {
            int idx = line.indexOf(',', start);
            if (idx == -1) {
                cols.push_back(line.substring(start));
                break;
            }
            cols.push_back(line.substring(start, idx));
            start = idx + 1;
        }
        if (cols.size() < 14) continue;

        WigleEntry e;
        e.bssid       = cols[0];
        e.ssid        = cols[1];
        e.capabilities= cols[2];
        e.firstSeen   = cols[3];
        e.channel     = cols[4].toInt();
        e.frequency   = cols[5].toInt();
        e.rssi        = cols[6].toInt();
        e.lat         = cols[7].toFloat();
        e.lon         = cols[8].toFloat();
        e.alt         = cols[9].toFloat();
        e.accuracy    = cols[10].toFloat();
        e.rcois       = cols[11];
        e.mfgid       = cols[12];
        e.type        = cols[13];

        firstSeenMap[e.bssid] = e;
    }
    f.close();
}


static void appendFirstSeenToDisk(const WigleEntry& e) {
    ensureWardrivingDir();
    File f = SD.open(FIRST_SEEN_PATH, FILE_APPEND);
    if (!f) return;

    f.printf("%s,%s,%s,%s,%d,%d,%d,%.6f,%.6f,%.2f,%.2f,%s,%s,%s\n",
        e.bssid.c_str(),
        e.ssid.c_str(),
        e.capabilities.c_str(),
        e.firstSeen.c_str(),
        e.channel,
        e.frequency,
        e.rssi,
        e.lat,
        e.lon,
        e.alt,
        e.accuracy,
        e.rcois.c_str(),
        e.mfgid.c_str(),
        e.type.c_str()
    );
    f.close();

    firstSeenMap[e.bssid] = e;
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
    Serial2.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
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

    // pre-load first seen map
    loadFirstSeenMap();

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

    // Read file into memory (careful with large files; wardrive files are usually small enough)
    File f = SD.open(csvPath, FILE_READ);
    if (!f) {
        if (outHttpCode) *outHttpCode = 0;
        return false;
    }
    String csv;
    while (f.available()) {
        csv += f.readStringUntil('\n');
        csv += '\n';
    }
    f.close();

    // Put your preferred endpoint here. For many upload flows the web endpoint accepts a POST
    // with CSV body and Basic auth. If Wigle requires multipart/form-data or other params,
    // this function will need a small change.
    const char* uploadUrl = "https://wigle.net/upload"; // tweak if API endpoint differs

    WiFiClientSecure *client = new WiFiClientSecure();
    client->setInsecure(); // or use proper cert validation
    HTTPClient https;
    https.begin(*client, uploadUrl);
    // "Encoded for use" already base64, so set header:
    https.addHeader("Authorization", String("Basic ") + encodedToken);
    https.addHeader("Content-Type", "text/csv");
    https.addHeader("User-Agent", "M5Gotchi-ESPBlaster/1.0");

    int code = https.POST((uint8_t*)csv.c_str(), csv.length());
    String resp;
    if (code > 0) resp = https.getString();
    else resp = String();

    if (outHttpCode) *outHttpCode = code;
    fLogMessage("uploadToWigle: POST %s -> HTTP %d, resp len %u", uploadUrl, code, (unsigned)resp.length());
    https.end();
    delete client;

    return (code >= 200 && code < 300);
}

// ---- main wardrive function (signature changed: no filename param) ----
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// Returns wardriveStatus as before (keeps same struct contents)
wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs) {
    if (networks.empty()) return {false, false, 0.0, 0.0, 0.0, 0.0, String(), 0, 0};

    // ensure SD dir is there
    ensureWardrivingDir();

    // Ensure firstSeenMap loaded
    if (firstSeenMap.empty()) loadFirstSeenMap();

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

    int written = 0;
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

        if (firstSeenMap.find(macStr) != firstSeenMap.end()) {
            entry.firstSeen = firstSeenMap[macStr].firstSeen;
        } else {
            entry.firstSeen = bestFix.timeIso;
            appendFirstSeenToDisk(entry);
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
