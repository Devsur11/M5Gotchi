#include "settings.h"
#include <Arduino.h>
#include <vector>
#include "SD.h"
#include <map>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include "wardrive.h"
#include "logger.h"
#include "crypto.h"
#include "achievements.h"
#include "ui.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"


static const int GPS_RX_PIN = 15;
static const int GPS_TX_PIN = 13;
static const int GPS_BAUD_DEFAULT = 115200;
int tot_observed_networks = 0;

bool wardrive_achievement_flag = false;

SemaphoreHandle_t wardriveMutex = nullptr;
QueueHandle_t wardriveSaveQueue = nullptr;

static String currentWardrivePath = "/M5Gotchi/wardriving/first_seen.csv";
static bool filenameLocked = false;

static const char* FIRST_SEEN_PATH = "/M5Gotchi/wardriving/first_seen.csv";

// WiGLE CSV header lines - exact format required by WiGLE
static const char* WIGLE_META_HEADER   = "WigleWifi-1.4,appRelease=M5Gotchi,model=M5Gotchi,release=1.0,device=M5Gotchi,display=M5Gotchi,board=ESP32,brand=M5Stack";
static const char* WIGLE_COLUMN_HEADER = "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type";

struct GpsFix {
    bool valid = false;
    double lat = 0.0;
    double lon = 0.0;
    double hdop = 0.0;
    double alt = 0.0;
    String timeIso;
    String fixType;
};

// Convert ISO timestamp "YYYY-MM-DDTHH:MM:SSZ" to WiGLE format "YYYY-MM-DD HH:MM:SS"
static String isoToWigleTimestamp(const String& iso) {
    String ts = iso;
    ts.replace("T", " ");
    if (ts.endsWith("Z")) ts = ts.substring(0, ts.length() - 1);
    return ts;
}

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

static String bssidToString(const uint8_t bssid[6]) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(buf);
}

static int channelToFrequency(int ch) {
    if (ch <= 0) return 0;
    if (ch <= 14) return 2407 + ch * 5;
    return 5000 + ch * 5;
}

// Build a single WiGLE CSV data row from a network + GPS fix.
// Returned string does NOT include a trailing newline.
static String buildWigleRow(const wifiSpeedScan& net, const GpsFix& fix) {
    String macStr = bssidToString(net.bssid);

    String ssidEsc = net.ssid;
    ssidEsc.replace("\"", "\"\"");

    String caps = "[ESS]";
    if (net.secure) caps = "[WPA2-PSK-CCMP][ESS]";

    int ch   = net.channel;
    int freq = channelToFrequency(ch);
    int rssi = net.rssi;

    // Timestamp must be "YYYY-MM-DD HH:MM:SS" for WiGLE
    String firstSeen = isoToWigleTimestamp(fix.timeIso);

    String latStr = String(fix.lat, 6);
    String lonStr = String(fix.lon, 6);
    String altStr = (fix.alt != 0.0) ? String(fix.alt, 2) : "";
    String accStr = (fix.hdop > 0)   ? String(fix.hdop, 2) : "";

    // WiGLE column order: MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,
    //                     CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type
    char buf[1024];
    snprintf(buf, sizeof(buf),
             "%s,\"%s\",%s,%s,%d,%d,%d,%s,%s,%s,%s,WIFI",
             macStr.c_str(),
             ssidEsc.c_str(),
             caps.c_str(),
             firstSeen.c_str(),
             ch,
             freq,
             rssi,
             latStr.c_str(),
             lonStr.c_str(),
             altStr.c_str(),
             accStr.c_str());

    return String(buf);
}

void startWardriveSession(unsigned long gpsTimeoutMs) {
    if (!useCustomGPSPins)
        Serial2.begin(gpsBaudRate, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    else
        Serial2.begin(gpsBaudRate, SERIAL_8N1, gpsRx, gpsTx);

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

    String fname;
    if (bestFix.valid && bestFix.timeIso.length() >= 10) {
        String ts = bestFix.timeIso;
        if (!ts.startsWith("T")) {
            int year  = ts.substring(0,4).toInt();
            int month = ts.substring(5,7).toInt();
            int day   = ts.substring(8,10).toInt();
            int hour  = ts.substring(11,13).toInt();
            int min   = ts.substring(14,16).toInt();
            int sec   = ts.substring(17,19).toInt();
            char buf[64];
            snprintf(buf, sizeof(buf), "wardriving/wardrive_%04d%02d%02d_%02d%02d%02d.csv",
                     year, month, day, hour, min, sec);
            fname = String(buf);
        }
    }
    if (fname.length() == 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "wardriving/wardrive_millis_%lu.csv", millis());
        fname = String(buf);
    }

    currentWardrivePath = "/M5Gotchi/" + fname;
    filenameLocked = true;
    fLogMessage("Wardrive session file set to: %s", currentWardrivePath.c_str());
}

void waitUntillLock() {
    if (!useCustomGPSPins)
        Serial2.begin(gpsBaudRate, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    else
        Serial2.begin(gpsBaudRate, SERIAL_8N1, gpsRx, gpsTx);

    GpsFix bestFix;
    String lineBuf;
    while (true) {
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
}

bool waitForGpsLock(int rxPin, int txPin, unsigned long timeoutMs) {
    Serial2.begin(gpsBaudRate, SERIAL_8N1, rxPin, txPin);
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
                        bestFix = temp;
                        if (bestFix.timeIso.length() >= 20) return true;
                    }
                }
            } else {
                lineBuf += c;
                if (lineBuf.length() > 120) lineBuf = lineBuf.substring(lineBuf.length() - 120);
            }
        }
        if (bestFix.valid && bestFix.timeIso.length() >= 16) return true;
        delay(5);
    }
    return false;
}

bool uploadToWigle(const String& encodedToken, const char* csvPath, int* outHttpCode) {
    if (!FSYS.exists(csvPath)) {
        fLogMessage("uploadToWigle: file does not exist: %s", csvPath);
        if (outHttpCode) *outHttpCode = 0;
        return false;
    }

    File f = FSYS.open(csvPath, FILE_READ);
    if (!f) {
        if (outHttpCode) *outHttpCode = 0;
        return false;
    }

    size_t fileSize = f.size();
    fLogMessage("uploadToWigle: streaming upload, file size: %u bytes", (unsigned)fileSize);

    WiFiClientSecure client;
    client.setInsecure();

    const char* host = "api.wigle.net";
    if (!client.connect(host, 443)) {
        fLogMessage("uploadToWigle: connection failed");
        if (outHttpCode) *outHttpCode = 0;
        f.close();
        return false;
    }

    String filename = csvPath;
    int lastSlash = filename.lastIndexOf('/');
    if (lastSlash >= 0) filename = filename.substring(lastSlash + 1);

    String boundary = "----WiGLEBoundary" + String(millis());

    String preamble  = String("--") + boundary + "\r\n";
    preamble += String("Content-Disposition: form-data; name=\"file\"; filename=\"") + filename + "\"\r\n";
    preamble += "Content-Type: text/csv\r\n\r\n";

    String closing = String("\r\n--") + boundary + "--\r\n";

    size_t contentLength = preamble.length() + (size_t)fileSize + closing.length();

    client.print("POST /api/v2/file/upload HTTP/1.1\r\n");
    client.print(String("Host: ") + host + "\r\n");

    String authHeaderB64;
    String key = encodedToken;
    key.trim();
    if (key.length() == 0) {
        fLogMessage("uploadToWigle: warning: empty Wigle API key provided");
    }
    if (key.indexOf(':') >= 0) {
        std::vector<uint8_t> bytes;
        bytes.reserve(key.length());
        for (size_t i = 0; i < (size_t)key.length(); ++i) bytes.push_back((uint8_t)key[i]);
        authHeaderB64 = pwngrid::crypto::base64Encode(bytes);
        fLogMessage("uploadToWigle: encoded plain name:token into base64 credential");
    } else {
        auto dec = pwngrid::crypto::base64Decode(key);
        bool dec_has_colon = false;
        for (auto b : dec) if (b == (uint8_t)':') { dec_has_colon = true; break; }
        if (dec_has_colon) {
            authHeaderB64 = key;
            fLogMessage("uploadToWigle: using provided base64-encoded credential");
        } else {
            authHeaderB64 = key;
            fLogMessage("uploadToWigle: warning: API key appears to be a bare token; consider using 'name:token' or the encoded credential from https://wigle.net/account");
        }
    }

    client.print(String("Authorization: Basic ") + authHeaderB64 + "\r\n");
    client.print("User-Agent: M5Gotchi/1.0\r\n");
    client.print(String("Content-Type: multipart/form-data; boundary=") + boundary + "\r\n");
    client.print("Connection: close\r\n");
    client.print(String("Content-Length: ") + contentLength + "\r\n\r\n");

    client.print(preamble);

    const size_t bufSize = 2048;
    uint8_t buf[bufSize];
    while (true) {
        int r = f.read(buf, bufSize);
        if (r <= 0) break;
        client.write(buf, r);
    }

    client.print(closing);
    f.close();

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

    String respBody;
    unsigned long bodyTimeout = millis() + 3000;
    while (millis() < bodyTimeout) {
        while (client.available()) {
            respBody += client.readString();
            if (respBody.length() > 2048) {
                respBody = respBody.substring(0, 2048);
                break;
            }
        }
        if (!client.connected()) break;
    }
    if (respBody.length()) {
        String snippet = respBody;
        if (snippet.length() > 512) snippet = snippet.substring(0, 512);
        fLogMessage("uploadToWigle: response body: %s", snippet.c_str());
    }

    bool success = (httpCode >= 200 && httpCode < 300);
    if (success) drawNewAchUnlock(ACH_WIGLE_NET);
    return success;
}

#include "ui.h"

wardriveStatus wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs) {
    if (wardriveMutex == nullptr) {
        wardriveMutex = xSemaphoreCreateMutex();
    }
    if (wardriveMutex == nullptr) {
        fLogMessage("wardrive: mutex creation failed");
        return {false, false, 0.0, 0.0, 0.0, 0.0, String(), 0, 0};
    }
    if (xSemaphoreTake(wardriveMutex, portMAX_DELAY) != pdTRUE) {
        fLogMessage("wardrive: failed to acquire mutex");
        return {false, false, 0.0, 0.0, 0.0, 0.0, String(), 0, 0};
    }

    if (networks.empty()) {
        xSemaphoreGive(wardriveMutex);
        return {false, false, 0.0, 0.0, 0.0, 0.0, String(), 0, 0};
    }

    if (Serial2) {
        // already initialized
    } else if (!useCustomGPSPins) {
        Serial2.begin(gpsBaudRate, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    } else {
        Serial2.begin(gpsBaudRate, SERIAL_8N1, gpsRx, gpsTx);
    }

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
                                bestFix.lat    = temp.lat;
                                bestFix.lon    = temp.lon;
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

    uint8_t written = 0;

    if (pwnagotchiTaskHandle != nullptr) {
        logMessage("Task save on");
        String body;

        for (const auto& net : networks) {
            if (!bestFix.valid) {
                fLogMessage("No valid GPS fix; skipping network logging for SSID: %s", net.ssid.c_str());
                continue;
            }
            body += buildWigleRow(net, bestFix) + "\n";
            written++;
        }

        if (wardriveSaveQueue == nullptr) {
            wardriveSaveQueue = xQueueCreate(5, sizeof(WardriveSaveRequest*));
            if (!wardriveSaveQueue) {
                fLogMessage("wardrive: failed to create wardriveSaveQueue");
            }
        }

        if (written > 0 && wardriveSaveQueue) {
            WardriveSaveRequest* req = new WardriveSaveRequest();
            if (!req) {
                fLogMessage("ERR: alloc WardriveSaveRequest failed");
                xSemaphoreGive(wardriveMutex);
                return {false, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, tot_observed_networks, 0};
            }
            snprintf(req->filename, sizeof(req->filename), "%s", currentWardrivePath.c_str());
            req->body = body;
            req->ensureWigleHeader = true;

            if (xQueueSend(wardriveSaveQueue, &req, portMAX_DELAY) != pdTRUE) {
                fLogMessage("ERR: wardriveSaveQueue send failed");
                delete req;
                xSemaphoreGive(wardriveMutex);
                return {false, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, tot_observed_networks, 0};
            }
        }

        tot_observed_networks += written;
        xSemaphoreGive(wardriveMutex);
        return {written > 0, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, tot_observed_networks, written};
    }

    // ---- Fallback / direct SD write path ----
    File f = FSYS.open(currentWardrivePath.c_str(), FILE_APPEND);
    if (!f) {
        fLogMessage("Cannot open wardrive file: %s", currentWardrivePath.c_str());
        xSemaphoreGive(wardriveMutex);
        return {false, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, 0, 0};
    }

    if (f.size() == 0) {
        f.println(WIGLE_META_HEADER);
        f.println(WIGLE_COLUMN_HEADER);
    }

    for (const auto& net : networks) {
        if (!bestFix.valid) {
            fLogMessage("No valid GPS fix; skipping network logging for SSID: %s", net.ssid.c_str());
            continue;
        }
        f.println(buildWigleRow(net, bestFix));
        written++;
    }

    f.close();
    tot_observed_networks += written;
    xSemaphoreGive(wardriveMutex);

    if (written > 0 && bestFix.valid) {
        wardrive_achievement_flag = true;
    }

    return {written > 0, bestFix.valid, bestFix.lat, bestFix.lon, bestFix.hdop, bestFix.alt, bestFix.timeIso, tot_observed_networks, written};
}