#include <WiFi.h>
#include <HTTPClient.h>
#include <FS.h>
#include <SD.h>
#include <ArduinoJson.h>
#include "Arduino.h"
#include "logger.h"
#include <vector>
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <DNSServer.h>
#include "esp_sntp.h"
#include "settings.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <cstring>

extern const uint8_t _binary_certs_wpa_sec_root_pem_start[] asm("_binary_certs_wpa_sec_root_pem_start");
extern const uint8_t _binary_certs_wpa_sec_root_pem_end[]   asm("_binary_certs_wpa_sec_root_pem_end");

// forward declarations for async upload helper
static bool startWpaSecUploadAsync(const char* a0, const char* a1, const char* a2, unsigned int a3);



String userInputFromWebServer(String titleOfEntryToGet) {
    String api_key = "";
    bool api_key_received = false;
    // Create AP
    DNSServer dnsServer;

    WiFi.mode(WIFI_AP);
    WiFi.softAP("CardputerSetup"); // open network, no password

    // DNS server for captive portal
    
    if(dnsServer.start(53, "*", WiFi.softAPIP())){
        delay(100);
    }
    
    // AsyncWebServer on port 80
    AsyncWebServer server(80);

    // Root handler with form
    server.on("/", HTTP_GET, [&](AsyncWebServerRequest *request) {
        String html = "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                      "<title>Setup</title></head><body style='display:flex;justify-content:center;align-items:center;height:100vh;'>"
                      "<form action='/submit' method='post'>"
                      "<h2>" + titleOfEntryToGet + "</h2>"
                      "<input type='text' name='input' style='width:250px;height:30px;font-size:16px;text-align:center;' required><br><br>"
                      "<input type='submit' value='Submit' style='width:100px;height:30px;'>"
                      "</form></body></html>";
        request->send(200, "text/html", html);
    });

    // Form handler
    server.on("/submit", HTTP_POST, [&](AsyncWebServerRequest *request) {
        if (request->hasParam("input", true)) {
            api_key = request->getParam("input", true)->value();
            api_key_received = true;
            logMessage("Received API Key: " + api_key);
            request->send(200, "text/html",
                          "<html><body><h2>Saved! You can close this page.</h2></body></html>");
        } else {
            request->send(400, "text/plain", "Bad Request");
        }
    });
    server.onNotFound([&](AsyncWebServerRequest *request) {
        String captivePortalHtml = "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                      "<title>Setup</title></head><body style='display:flex;justify-content:center;align-items:center;height:100vh;'>"
                      "<form action='/submit' method='post'>"
                      "<h2>" + titleOfEntryToGet + "</h2>"
                      "<input type='text' name='input' style='width:250px;height:30px;font-size:16px;text-align:center;' required><br><br>"
                      "<input type='submit' value='Submit' style='width:100px;height:30px;'>"
                      "</form></body></html>";
        request->send(200, "text/html", captivePortalHtml);
    });


    server.begin();
    logMessage("WebServer started. Connect to SSID 'CardputerSetup' and enter your key.");

    // Wait for input (blocks until received)
    while (!api_key_received) {
        dnsServer.processNextRequest();
        delay(10);
    }
    sntp_stop();
    delay(100);
    server.end();
    WiFi.softAPdisconnect(true);
    wifion();

    return api_key;
}

struct CrackedEntry {
    String ssid;
    String bssid;     // NEW: store BSSID
    String password;
};

// Reads all cracked entries from SD:/cracked.json
std::vector<CrackedEntry> getCrackedEntries() {
    std::vector<CrackedEntry> entries;

    if (!SD.exists("/cracked.json")) {
        logMessage("No cracked.json found on SD card.");
        return entries; // empty
    }

    File file = SD.open("/cracked.json", FILE_READ);
    if (!file) {
        logMessage("Failed to open cracked.json for reading.");
        return entries;
    }

    DynamicJsonDocument doc(16 * 1024); // 16 KB buffer, adjust if needed
    DeserializationError error = deserializeJson(doc, file);
    file.close();

    if (error) {
        logMessage("Failed to parse cracked.json: " + String(error.c_str()));
        return entries;
    }

    if (!doc.is<JsonArray>()) {
        logMessage("cracked.json does not contain a JSON array.");
        return entries;
    }

    JsonArray arr = doc.as<JsonArray>();
    for (JsonVariant v : arr) {
        if (v["ssid"].is<String>() && v["password"].is<String>()) {
            CrackedEntry entry;
            entry.ssid = v["ssid"].as<String>();
            entry.password = v["password"].as<String>();
            entry.bssid = v["bssid"].is<String>() ? v["bssid"].as<String>() : "";
            entries.push_back(entry);
        }
    }

    logMessage("Loaded " + String(entries.size()) + " cracked entries.");
    return entries;
}

// Helper: check if filename exists in uploaded.json
bool isAlreadyUploaded(const char* fileName, JsonDocument &doc) {
    if (!doc.is<JsonArray>()) return false;
    for (JsonVariant v : doc.as<JsonArray>()) {
        if (v.as<String>() == String(fileName)) return true;
    }
    return false;
}

// Helper: save uploaded.json back to SD (pretty)
void saveUploadedList(JsonDocument &doc) {
    File jsonFile = SD.open("/uploaded.json", FILE_WRITE);
    if (!jsonFile) {
        logMessage("Failed to open /uploaded.json for writing");
        return;
    }
    serializeJsonPretty(doc, jsonFile);
    jsonFile.close();
    logMessage("uploaded.json updated");
}

// Append single filename to /uploaded.json safely (no duplicate)
static void appendToUploadedList(const char* fileName) {
    DynamicJsonDocument doc(2048);
    if (SD.exists("/uploaded.json")) {
        File upf = SD.open("/uploaded.json", FILE_READ);
        if (upf) {
            DeserializationError err = deserializeJson(doc, upf);
            upf.close();
            if (err) {
                logMessage("uploaded.json parse error, resetting list");
                doc.to<JsonArray>();
            }
        } else {
            logMessage("Failed to open /uploaded.json for reading (append)");
            doc.to<JsonArray>();
        }
    } else {
        doc.to<JsonArray>();
    }

    if (!doc.is<JsonArray>()) {
        doc.to<JsonArray>();
    }

    if (isAlreadyUploaded(fileName, doc)) return;
    doc.as<JsonArray>().add(String(fileName));
    saveUploadedList(doc);
}

// Upload single PCAP to wpa-sec via HTTPS (raw request)
bool uploadToWpaSec(const char* apiKey, const char* pcapPath, const char* fileName, uint32_t timeoutMs = 30000) {
    if (!SD.exists(pcapPath)) {
        logMessage("File not found: " + String(pcapPath));
        return false;
    }

    File f = SD.open(pcapPath, FILE_READ);
    if (!f) {
        logMessage("Failed to open " + String(pcapPath));
        return false;
    }

    uint32_t fileSize = (uint32_t)f.size();
    logMessage("Preparing upload: " + String(fileName) + " (" + String(fileSize) + " bytes)");

    WiFiClientSecure client;
    logMessage("Free heap before TLS connect: " + String(ESP.getFreeHeap()));
    client.setCACert((const char*)_binary_certs_wpa_sec_root_pem_start);

    const char* host = "wpa-sec.stanev.org";
    const uint16_t port = 443;
    logMessage("Free heap before TLS connect: " + String(ESP.getFreeHeap()));
    delay(10);
    if (!client.connect(host, port)) {
        logMessage("TLS connect failed to " + String(host) + " (attempting insecure fallback)");
        // Try insecure fallback if verification fails (last resort)
        client.setInsecure();
        delay(10);
        if (!client.connect(host, port)) {
            logMessage("Insecure TLS connect also failed to " + String(host));
            f.close();
            return false;
        }
        logMessage("Insecure TLS connect succeeded (no cert verification)");
    }

    String boundary = "WPASECBOUNDARY123456";
    String head = String("--") + boundary + "\r\n";
    head += "Content-Disposition: form-data; name=\"file\"; filename=\"" + String(fileName) + "\"\r\n";
    head += "Content-Type: application/vnd.tcpdump.pcap\r\n\r\n";
    String tail = "\r\n--" + boundary + "--\r\n";

    size_t contentLength = head.length() + (size_t)fileSize + tail.length();

    // Send HTTP request headers
    client.print(String("POST ") + "/" + " HTTP/1.1\r\n");
    client.print(String("Host: ") + host + "\r\n");
    client.print("User-Agent: M5Cardputer/1.0\r\n");
    client.print("Accept: */*\r\n");
    client.print("Connection: close\r\n");
    client.print(String("Cookie: key=") + apiKey + "\r\n");
    client.print(String("Content-Type: multipart/form-data; boundary=") + boundary + "\r\n");
    client.print(String("Content-Length: ") + String(contentLength) + "\r\n\r\n");

    // Send multipart head
    client.print(head);

    // Stream file content in chunks
    const size_t bufSize = 512;
    uint8_t buffer[bufSize];
    while (f.available()) {
        size_t r = f.read(buffer, bufSize);
        if (r == 0) break;
        size_t sent = 0;
        while (sent < r) {
            int w = client.write(buffer + sent, r - sent);
            if (w < 0) {
                logMessage("Client write error during upload");
                f.close();
                client.stop();
                return false;
            }
            sent += (size_t)w;
        }
    }

    // Send multipart tail
    client.print(tail);

    f.close();
    logMessage("Upload finished sending bytes, awaiting response...");

    // Read response with timeout
    String response;
    unsigned long start = millis();
    while (millis() - start < timeoutMs) {
        while (client.available()) {
            char c = (char)client.read();
            response += c;
        }
        if (!client.connected() && !client.available()) break;
        delay(1);
    }
    client.stop();
    logMessage("Free heap after TLS download: " + String(ESP.getFreeHeap()));
    logMessage("Response received, length: " + String(response.length()));
    logMessage("Response: " + response); // Debug log
    logMessage("Free heap after TLS: " + String(ESP.getFreeHeap()));

    // Parse HTTP status code
    int statusCode = 0;
    int firstSpace = response.indexOf(' ');
    if (firstSpace > 0) {
        int secondSpace = response.indexOf(' ', firstSpace + 1);
        if (secondSpace > firstSpace) {
            statusCode = response.substring(firstSpace + 1, secondSpace).toInt();
        }
    }

    if (statusCode == 200) {
        if (response.indexOf("already submitted") >= 0) {
            logMessage("Already submitted: " + String(fileName));
            return true;
        }
        if (response.indexOf("OK") >= 0 || response.indexOf("uploaded") >= 0) {
            logMessage("Successfully uploaded: " + String(fileName));
            return true;
        }
        // Some servers return 200 with a different body
        logMessage("Upload returned 200 but unrecognized body. Sample: " + response.substring(0, min(200, int(response.length()))));
        return true; // treat as success in ambiguous cases
    }

    logMessage("Upload failed for " + String(fileName) + " HTTP=" + String(statusCode));
    return false;
}

// Main batch function: upload new PCAPs and pull cracked results into cracked.json

// ---------- helpers ----------
String decodeChunkedBody(const String &chunked) {
    String out;
    int pos = 0;
    while (pos < (int)chunked.length()) {
        // read chunk-size line
        int rn = chunked.indexOf("\r\n", pos);
        if (rn == -1) break;
        String lenStr = chunked.substring(pos, rn);
        lenStr.trim();
        if (lenStr.length() == 0) { pos = rn + 2; continue; }
        // parse hex length
        unsigned long len = strtoul(lenStr.c_str(), nullptr, 16);
        if (len == 0) break; // last-chunk
        int chunkStart = rn + 2;
        if (chunkStart + (int)len > (int)chunked.length()) {
            // incomplete chunk, stop
            break;
        }
        out += chunked.substring(chunkStart, chunkStart + len);
        // move to start of next chunk-size line (skip trailing CRLF after chunk)
        pos = chunkStart + len + 2;
    }
    return out;
}

static void parseAndSavePotfileBody(const String &bodyRaw) {
    // Load or init cracked.json
    DynamicJsonDocument crackedDoc(8 * 1024);
    if (SD.exists("/cracked.json")) {
        File cf = SD.open("/cracked.json", FILE_READ);
        if (cf) {
            DeserializationError err = deserializeJson(crackedDoc, cf);
            cf.close();
            if (err) {
                logMessage("cracked.json parse error, resetting");
                crackedDoc.to<JsonArray>();
            }
        } else {
            logMessage("Failed to open cracked.json for reading, creating new");
            crackedDoc.to<JsonArray>();
        }
    } else {
        crackedDoc.to<JsonArray>();
    }
    JsonArray arr = crackedDoc.as<JsonArray>();

    // bodyRaw may contain '\r' and '\n' combos. split by '\n'
    int startLine = 0;
    while (startLine < bodyRaw.length()) {
        int endLine = bodyRaw.indexOf('\n', startLine);
        if (endLine == -1) endLine = bodyRaw.length();
        String line = bodyRaw.substring(startLine, endLine);
        startLine = endLine + 1;
        // cleanup line endings and whitespace
        line.replace("\r", "");
        line.trim();
        if (line.length() == 0) continue;

        // Try comma separators first, else colon
        int p1 = -1, p2 = -1, p3 = -1;
        if (line.indexOf(',') != -1) {
            p1 = line.indexOf(',');
            p2 = line.indexOf(',', p1 + 1);
            p3 = line.indexOf(',', p2 + 1);
        } else {
            // colon separated (common)
            p1 = line.indexOf(':');
            p2 = line.indexOf(':', p1 + 1);
            p3 = line.indexOf(':', p2 + 1);
        }

        if (!(p1 > 0 && p2 > p1 && p3 > p2)) {
            logMessage("Ignored malformed line: " + line);
            continue;
        }

        String bssid = line.substring(0, p1); bssid.trim();
        String ssid  = line.substring(p2 + 1, p3); ssid.trim();
        String pass  = line.substring(p3 + 1); pass.trim();

        if (ssid.length() == 0 || pass.length() == 0) {
            logMessage("Ignored incomplete entry: " + line);
            continue;
        }

        // check duplicate
        bool exists = false;
        for (JsonObject obj : arr) {
            const char* ob = obj["bssid"] | "";
            const char* os = obj["ssid"]   | "";
            const char* op = obj["password"] | "";
            if (String(ob) == bssid && String(os) == ssid && String(op) == pass) {
                exists = true;
                break;
            }
        }

        if (exists) {
            logMessage("Duplicate cracked entry skipped: " + ssid);
        } else {
            JsonObject entry = arr.add<JsonObject>();
            entry["bssid"] = bssid;
            entry["ssid"] = ssid;
            entry["password"] = pass;
            logMessage("New cracked: " + ssid + " -> " + pass);
        }
    }

    // write cracked.json back (pretty)
    File out = SD.open("/cracked.json", FILE_WRITE);
    if (!out) {
        logMessage("Failed to open /cracked.json for writing");
        return;
    }
    serializeJsonPretty(crackedDoc, out);
    out.close();
    logMessage("cracked.json updated");
}

// ---------- replacement processWpaSec download/parse block ----------
void processWpaSec(const char* apiKey) {
    // Load uploaded.json (list of filenames)
    DynamicJsonDocument uploadedDoc(2048);
    if (SD.exists("/uploaded.json")) {
        logMessage("Loading /uploaded.json");
        File upf = SD.open("/uploaded.json", FILE_READ);
        if (upf) {
            DeserializationError err = deserializeJson(uploadedDoc, upf);
            upf.close();
            if (err) {
                logMessage("uploaded.json parse error, resetting list");
                uploadedDoc.to<JsonArray>();
            }
        } else {
            logMessage("Failed to open /uploaded.json for reading");
            uploadedDoc.to<JsonArray>();
        }
    } else {
        logMessage("No uploaded.json found, creating new");
        uploadedDoc.to<JsonArray>();
    }

    // Scan handshake folder: collect paths to upload while keeping uploadedDoc in scope
    std::vector<String> toUpload;
    File dir = SD.open("/handshake");
    if (!dir || !dir.isDirectory()) {
        logMessage("No /handshake folder");
    } else {
        logMessage("Scanning /handshake for .pcap files");
        File file;
        while ((file = dir.openNextFile())) {
            if (!file.isDirectory()) {
                String name = String(file.name());
                if (name.endsWith(".pcap")) {
                    if (!isAlreadyUploaded(name.c_str(), uploadedDoc)) {
                        String path = String("/handshake/") + name;
                        toUpload.push_back(path);
                        toUpload.push_back(name);
                    } else {
                        logMessage("Skipping already uploaded: " + name);
                    }
                }
            }
            file.close();
        }
        dir.close();
    }

    // Free the uploadedDoc JSON memory by ending its scope before starting TLS uploads
    uploadedDoc.clear();
    delay(10);
    // Start uploads for the collected list (paired entries: path,name)
    for (size_t i = 0; i + 1 < toUpload.size(); i += 2) {
        String path = toUpload[i];
        String name = toUpload[i + 1];
        logMessage("Uploading new file (background): " + name);
        if (!startWpaSecUploadAsync(apiKey, path.c_str(), name.c_str(), 30000)) {
            logMessage("Failed to start WPA-Sec upload: " + name);
        } else {
            logMessage("Upload started in background: " + name);
            delay(5000);
        }
    }

    // --- Download cracked potfile via raw HTTPS request (same as earlier) ---
    logMessage("Downloading cracked results (raw HTTPS) ...");
    WiFiClientSecure client;
    client.setCACert((const char*)_binary_certs_wpa_sec_root_pem_start);
    const char* host = "wpa-sec.stanev.org";
    const uint16_t port = 443;
    if (!client.connect(host, port)) {
        logMessage("TLS connect failed for download (attempting insecure fallback)");
        client.setInsecure();
        delay(10);
        if (!client.connect(host, port)) {
            logMessage("Insecure TLS connect also failed for download");
            return;
        }
        logMessage("Insecure TLS connect succeeded for download");
    }

    client.print(String("GET /?api&dl=1 HTTP/1.1\r\n"));
    client.print(String("Host: ") + host + "\r\n");
    client.print("User-Agent: M5Cardputer/1.0\r\n");
    client.print(String("Cookie: key=") + apiKey + "\r\n");
    client.print("Connection: close\r\n\r\n");

    String httpResp;
    unsigned long start = millis();
    const uint32_t timeoutMs = 20000;
    while (millis() - start < timeoutMs) {
        while (client.available()) {
            httpResp += (char)client.read();
        }
        if (!client.connected() && !client.available()) break;
        delay(1);
    }
    client.stop();

    if (httpResp.length() == 0) {
        logMessage("Empty response when downloading cracked results");
        return;
    }

    // split headers / body
    int hdrEnd = httpResp.indexOf("\r\n\r\n");
    String headers = (hdrEnd >= 0) ? httpResp.substring(0, hdrEnd) : String();
    String bodyRaw = (hdrEnd >= 0) ? httpResp.substring(hdrEnd + 4) : httpResp;

    // if Transfer-Encoding: chunked, decode chunks
    if (headers.indexOf("Transfer-Encoding: chunked") >= 0) {
        logMessage("Chunked transfer detected. Decoding...");
        bodyRaw = decodeChunkedBody(bodyRaw);
    } else {
        // some servers still send chunked without header; do a heuristic decode if body contains chunk-size lines:
        // if body starts with a hex line and next char is CRLF, peek and decode
        int firstNl = bodyRaw.indexOf("\r\n");
        if (firstNl > 0) {
            String maybeLen = bodyRaw.substring(0, firstNl);
            bool isHex = true;
            for (size_t i=0;i<maybeLen.length();++i) {
                char c = maybeLen[i];
                if (!isxdigit(c)) { isHex = false; break; }
            }
            if (isHex) {
                logMessage("Heuristic: body appears chunked. Decoding...");
                bodyRaw = decodeChunkedBody(bodyRaw);
            }
        }
    }

    // now parse potfile lines and save to cracked.json
    parseAndSavePotfileBody(bodyRaw);
}

// Guard against multiple concurrent uploads
static volatile bool s_wpa_upload_in_progress = false;

// Heap-allocated argument bag for the upload task
struct WpaSecUploadArgs {
    char* arg0;
    char* arg1;
    char* arg2;
    unsigned int arg3;
};

// Task wrapper that invokes uploadToWpaSec on a dedicated task stack
static void uploadToWpaSecTask(void* pvParameters) {
    WpaSecUploadArgs* args = reinterpret_cast<WpaSecUploadArgs*>(pvParameters);
    if (!args) {
        vTaskDelete(NULL);
        return;
    }

    // Ensure the global flag marks upload in-progress
    // s_wpa_upload_in_progress is set before creating this task.

    bool ok = false;
    // Call the existing synchronous function that does the TLS upload.
    // Signature matches: uploadToWpaSec(const char*, const char*, const char*, unsigned int)
    ok = uploadToWpaSec(args->arg0, args->arg1, args->arg2, args->arg3);

    if (ok) {
        logMessage("WPA-Sec upload completed successfully");
        // Mark as uploaded so it won't be retried
        appendToUploadedList(args->arg2);
    } else {
        logMessage("WPA-Sec upload failed");
    }

    // Clean up
    free(args->arg0);
    free(args->arg1);
    free(args->arg2);
    free(args);

    s_wpa_upload_in_progress = false; // allow subsequent uploads
    vTaskDelete(NULL);
}

// Start upload task ensuring arguments are heap-allocated and the task stack is large
static bool startWpaSecUploadAsync(const char* a0, const char* a1, const char* a2, unsigned int a3) {
    // if (s_wpa_upload_in_progress) {
    //     logMessage("WPA-Sec upload already in progress");
    //     return false;
    // }

    // // Quick guard: ensure there's enough heap for the TLS stack and crypto buffers
    // const size_t kMinHeapForTls = 60 * 1024; // 60KB
    // if (ESP.getFreeHeap() < kMinHeapForTls) {
    //     logMessage("Not enough heap to start WPA-Sec upload (free: " + String(ESP.getFreeHeap()) + ")");
    //     s_wpa_upload_in_progress = false;
    //     return false;
    // }

    WpaSecUploadArgs* args = reinterpret_cast<WpaSecUploadArgs*>(malloc(sizeof(WpaSecUploadArgs)));
    if (!args) {
        logMessage("Failed to alloc WPA-Sec args");
        s_wpa_upload_in_progress = false;
        return false;
    }

    args->arg0 = strdup(a0 ? a0 : "");
    args->arg1 = strdup(a1 ? a1 : "");
    args->arg2 = strdup(a2 ? a2 : "");
    args->arg3 = a3;

    if (!args->arg0 || !args->arg1 || !args->arg2) {
        logMessage("Failed to dup WPA-Sec args");
        if (args->arg0) free(args->arg0);
        if (args->arg1) free(args->arg1);
        if (args->arg2) free(args->arg2);
        free(args);
        s_wpa_upload_in_progress = false;
        return false;
    }

    // Create a pinned task with a big stack to avoid loopTask stack overflow during TLS handshake
    // Stack size used here: 32768 (32KB) - adjust if necessary for your board.
    // BaseType_t rc = xTaskCreatePinnedToCore(
    //     uploadToWpaSecTask,
    //     "wpaUploadTask",
    //     32768,       // stack size (bytes) - reduce to save memory
    //     args,
    //     1,           // priority
    //     NULL,        // handle
    //     0           // core ID
    // );
    BaseType_t rc;
    if(uploadToWpaSec(args->arg0, args->arg1, args->arg2, args->arg3)){
        logMessage("WPA-Sec upload completed successfully");
        // Mark as uploaded so it won't be retried
        appendToUploadedList(args->arg2);
        rc = pdPASS; // Simulate success for direct call
    } else {
        logMessage("WPA-Sec upload failed");
        rc = pdFAIL; // Simulate failure for direct call
    } // Call directly for single-threaded environments

    if (rc != pdPASS) {
        free(args->arg0);
        free(args->arg1);
        free(args->arg2);
        free(args);
        s_wpa_upload_in_progress = false;
        return false;
    }

    return true;
}