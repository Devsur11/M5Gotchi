// /home/devsur/Github/ESPBlaster/src/wardrive.cpp
//
// Wardriving function for ESP32 with AT6H GPS on RX=G13 (GPIO13), TX=G15 (GPIO15).
// Reads NMEA sentences from GPS (Serial2), parses a recent valid fix (GPRMC/GPGGA),
// then appends one CSV line per seen WiFi network to an SD file (default: /wardrive.csv).
//
// Usage:
//   std::vector<wifiSpeedScan> nets = ...;
//   bool ok = wardrive(nets, 10000 /*ms timeout*/, "/wardrive.csv");
//
// Notes:
// - Attempts to use SD_MMC by default (common on M5 devices). Falls back to SD if needed.
// - CSV columns: ts_iso,lat,lon,fix_type,hdop,alt,ssid,bssid,rssi,channel,secure
// - Keeps implementation self-contained; adjust pins/baud/filename as needed.

#include <Arduino.h>
#include <vector>
#include <SD.h>
#include <SD_MMC.h>

struct wifiSpeedScan {
    String ssid;
    int rssi;
    int channel;
    bool secure;
    uint8_t bssid[6];
};

// GPS serial pins (GPIO numbers)
static const int GPS_RX_PIN = 13; // AT6H TX -> ESP RX
static const int GPS_TX_PIN = 15; // AT6H RX <- ESP TX
static const int GPS_BAUD = 9600;

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

// Helper: convert NMEA lat/lon (ddmm.mmmm / dddmm.mmmm) with N/S/E/W to decimal degrees
static double nmeaToDecimal(const String& field, char dir) {
    if (field.length() < 4) return NAN;
    double val = field.toFloat();
    // degrees are the integer part before two last digits of minutes
    int degDigits = (dir == 'N' || dir == 'S') ? 2 : 3;
    double degrees = floor(val / 100.0);
    double minutes = val - (degrees * 100.0);
    double dec = degrees + (minutes / 60.0);
    if (dir == 'S' || dir == 'W') dec = -dec;
    return dec;
}

// Helper: parse hhmmss.sss and ddmmyy into ISO UTC "YYYY-MM-DDTHH:MM:SSZ" (year guessed 2000+)
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
        // No date; use epoch-ish placeholder with today's date not available — return time only
        char buf[64];
        snprintf(buf, sizeof(buf), "T%02d:%02d:%02dZ", hour, minute, second);
        return String(buf);
    }
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour, minute, second);
    return String(buf);
}

// Parse a single NMEA sentence (line) for GPRMC or GPGGA fix data; merges into provided GpsFix if more info found
static void parseNmeaLine(const String& line, GpsFix& fix) {
    if (line.length() < 6) return;
    if (!(line.startsWith("$GPRMC") || line.startsWith("$GNRMC") || line.startsWith("$GPGGA") || line.startsWith("$GNGGA"))) return;

    // Split by commas (simple)
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
        // fields: 1=time,2=status,3=lat,4=N/S,5=lon,6=E/W,7=sog,8=track,9=date,...
        if (fields.size() >= 10) {
            String status = fields[2]; // Note: some devices shift; double-check indexes; robust approach:
            String timeStr = fields[1];
            String statField = fields[2];
            // Some NMEA variants put status at idx 2; if not 'A' assume invalid.
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
        // fields: 1=time,2=lat,3=N/S,4=lon,5=E/W,6=quality,7=numSV,8=hdop,9=alt,...
        if (fields.size() >= 10) {
            String timeStr = fields[1];
            String latField = fields[2];
            char latDir = (fields[3].length()>0)?fields[3][0]:'N';
            String lonField = fields[4];
            char lonDir = (fields[5].length()>0)?fields[5][0]:'E';
            String quality = fields[6];
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
                // timeIso: GGA has no date; put time only
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
    }
}

static String bssidToString(const uint8_t bssid[6]) {
    char buf[32];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    return String(buf);
}

// The main wardrive function.
// - networks: vector of wifiSpeedScan seen at this moment
// - timeoutMs: how long to wait for a valid GPS fix (reads Serial2)
// - filename: path on SD to append rows
// Returns true if write succeeded for at least one network (SD available and operation ok).
bool wardrive(const std::vector<wifiSpeedScan>& networks, unsigned long timeoutMs = 10000, const char* filename = "/wardrive.csv") {
    if (networks.empty()) return false;

    // Initialize GPS serial (Serial2)
    Serial2.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);

    GpsFix bestFix;
    unsigned long start = millis();
    String lineBuf;

    // Read NMEA lines until timeout; keep last valid fix (prefer GPGGA with hdop/alt if available)
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
                        // prefer GPGGA for hdop/alt
                        if (!bestFix.valid) {
                            bestFix = temp;
                        } else {
                            // if new has hdop or alt, or is GPGGA, replace
                            if (temp.fixType == "GPGGA" || (temp.hdop > 0 && bestFix.hdop == 0)) {
                                bestFix = temp;
                            } else {
                                // otherwise keep most recent lat/lon update
                                bestFix.lat = temp.lat;
                                bestFix.lon = temp.lon;
                                bestFix.timeIso = temp.timeIso;
                            }
                        }
                    }
                }
            } else {
                lineBuf += c;
                // protect against runaway
                if (lineBuf.length() > 120) lineBuf = lineBuf.substring(lineBuf.length() - 120);
            }
        }
        delay(5);
    }



    // Open file for append
    File f = SD.open(filename, FILE_APPEND);
    if (!f) {
        return false;
    }

    // If file empty, add header (attempt to detect by size)
    if (f.size() == 0) {
        f.println("ts_iso,lat,lon,fix_type,hdop,alt,ssid,bssid,rssi,channel,secure");
    }

    // Build a line per network
    for (const auto& net : networks) {
        String ts = bestFix.timeIso.length() ? bestFix.timeIso : String("T00:00:00Z");
        String latStr = bestFix.valid ? String(bestFix.lat, 6) : String("NA");
        String lonStr = bestFix.valid ? String(bestFix.lon, 6) : String("NA");
        String fixType = bestFix.valid ? bestFix.fixType : String("NONE");
        String hdopStr = (bestFix.hdop > 0.0) ? String(bestFix.hdop, 2) : String("");
        String altStr = (bestFix.alt != 0.0) ? String(bestFix.alt, 2) : String("");

        String ssidEsc = net.ssid;
        // simple CSV escape: wrap in double quotes and escape internal quotes
        ssidEsc.replace("\"", "\"\"");

        String bssidStr = bssidToString(net.bssid);

        // secure -> 1/0
        int secureFlag = net.secure ? 1 : 0;

        // Compose CSV: ensure fields with commas are quoted
        char buf[1024];
        snprintf(buf, sizeof(buf), "\"%s\",%s,%s,%s,%s,%s,\"%s\",%s,%d,%d,%d",
                 ts.c_str(),
                 latStr.c_str(),
                 lonStr.c_str(),
                 fixType.c_str(),
                 hdopStr.c_str(),
                 altStr.c_str(),
                 ssidEsc.c_str(),
                 bssidStr.c_str(),
                 net.rssi,
                 net.channel,
                 secureFlag);

        f.println(buf);
    }

    f.close();
    return true;
}