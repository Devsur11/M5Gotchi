#include "api_client.h"
#include "crypto.h"
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <mbedtls/sha256.h>
#include "settings.h"
#include "ui.h"
#include "esp_heap_caps.h"

using namespace api_client;
using namespace pwngrid::crypto;

static const char *Endpoint = "https://api.pwnagotchi.ai/api/v1";
static String token = "";
static const char *tokenPath = "/pwngrid/token.json";
static String keysPathGlobal = "/pwngrid/keys";
extern const char pwngid_root_ca_pem_start[] asm("_binary_certs_pwngrid_root_ca_pem_start");
extern const char pwngid_root_ca_pem_end[] asm("_binary_certs_pwngrid_root_ca_pem_end");

#include <esp_sntp.h>

bool timeInitialized = false;
bool inited = false;

void api_client::initTime() {
    if (timeInitialized) return;   // stop f***ing reinitializing 

    timeInitialized = true;

    delay(150);
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_init();

    time_t now = 0;
    tm timeinfo = {0};
    while (now < 100000) {
        delay(200);
        time(&now);
        localtime_r(&now, &timeinfo);
    }
}

bool saveToken(const String &t) {
    JsonDocument doc;
    doc["token"] = t;
    String s;
    serializeJson(doc, s);
    File f = SD.open(tokenPath, "w");
    if (!f) return false;
    f.print(s);
    f.close();
    token = t;
    return true;
}

bool loadToken() {
    if (!SD.exists(tokenPath)) return false;
    File f = SD.open(tokenPath, "r");
    if (!f) return false;
    String s = f.readString(); f.close();
    JsonDocument doc;
    if (deserializeJson(doc, s)) return false;
    if (doc["token"].is<String>()) {
        token = String(doc["token"].as<const char*>());
        return true;
    }
    return false;
}

static TaskHandle_t initTaskHandle = nullptr;
static bool initResult = false;
static SemaphoreHandle_t initDone = nullptr;

void apiInitTask(void *arg) {
    String *path = (String *)arg;
    initResult = api_client::sub_init(*path);
    xSemaphoreGive(initDone);
    delete path;
    initTaskHandle = nullptr;
    vTaskDelete(nullptr);
}

bool api_client::sub_init(const String &keysPath) {
    if(inited){
        return enrollWithGrid();
    }
    initTime();
    keysPathGlobal = keysPath;
    if (!pwngrid::crypto::ensureKeys(keysPath)) {
        logMessage("crypto keys ensure failed");
        return false;
    }
    loadToken();
    if (!enrollWithGrid()) {
        logMessage("Enroll failed");
        return false;
    }
    inited = true;
    return true;
}

bool api_client::init(const String &keysPath) {
    initDone = xSemaphoreCreateBinary();
    if (!initDone) return false;

    // copy because passing String by pointer into tasks is cursed otherwise
    String *param = new String(keysPath);

    xTaskCreatePinnedToCore(
        apiInitTask,
        "apiInitTask",
        16384,   // increased stack: HTTPClient + mbedtls can require significantly more stack
        param,
        2,       // slightly higher priority to avoid preemption during heavy init
        &initTaskHandle,
        0
    );

    if (!initTaskHandle) {
        delete param;
        return false;
    }

    // wait for up to timeout
    if (xSemaphoreTake(initDone, pdMS_TO_TICKS(60000)) == pdTRUE) {
        // finished normally
        vSemaphoreDelete(initDone);
        initDone = nullptr;
        return initResult;
    }

    // timeout... time to commit a war crime
    vTaskDelete(initTaskHandle);
    initTaskHandle = nullptr;
    vSemaphoreDelete(initDone);
    initDone = nullptr;
    return false;
}


// helper: http POST json -> returns body string or empty on error
static String httpPostJson(const String &url, const String &json, bool auth) {
    size_t free_heap = esp_get_free_heap_size();
    if (free_heap < 40000) {
        fLogMessage("Not enough heap for SSL connect: %u\n", (unsigned)free_heap);
        return String();
    }
    WiFiClientSecure *client = new WiFiClientSecure();
    client->setCACert(pwngid_root_ca_pem_start);
    HTTPClient https;
    https.begin(*client, url);
    https.addHeader("Content-Type", "application/json");
    if (auth && token.length()) {
        https.addHeader("Authorization", "Bearer " + token);
    }
    logMessage("Log before http POST");
    uint16_t code = https.POST(json);
    logMessage("Log after http POST");
    String body = "";
    if (code > 0) {
        body = https.getString();
    } else {
        fLogMessage("HTTP POST failed: %d\n", code);
    }
    https.end(); delete client;
    return body;
}

static String httpGet(const String &url, bool auth) {
    size_t free_heap = esp_get_free_heap_size();
    if (free_heap < 40000) {
        fLogMessage("Not enough heap for SSL connect (GET): %u\n", (unsigned)free_heap);
        return String();
    }
    WiFiClientSecure *client = new WiFiClientSecure();
    client->setCACert(pwngid_root_ca_pem_start);
    HTTPClient https;
    https.begin(*client, url);
    if (auth && token.length()) https.addHeader("Authorization", "Bearer " + token);
    int code = https.GET();
    String body = "";
    if (code > 0) body = https.getString();
    else fLogMessage("HTTP GET failed: %d\n", code);
    https.end(); delete client;
    return body;
}

// build identity: hostname@SHA256(pubPEM)
static String sha256Hex(const String &s) {
    unsigned char out[32];
    mbedtls_sha256((const unsigned char*)s.c_str(), s.length(), out, 0);
    String hex = "";
    char buf[3];
    for (int i=0;i<32;i++) {
        sprintf(buf, "%02x", out[i]);
        hex += String(buf);
    }
    return hex;
}

#include "settings.h"

bool api_client::enrollWithGrid() {
    if(!((uint64_t)time(nullptr) > (lastTokenRefresh+(30*60)))){
        logMessage("Token refresh skipped, 30 minutes not passed." + String((uint64_t)time(nullptr)) + " > " + String((lastTokenRefresh+(30*60))));
        return true;
    }

    String pubPEM;
    if (!pwngrid::crypto::loadPublicPEM(pubPEM)) {
        logMessage("no public pem");
        return false;
    }

    // normalize (make sure header/footer and exactly one trailing newline for base64)
    String pubNorm = normalizePublicPEM(pubPEM);

    // identity must hash the exact bytes the server hashes: use trimmed PEM (python .strip())
    String pubTrim = trimString(pubNorm);
    String fingerprint = sha256Hex(pubTrim);
    String identity = hostname + "@" + fingerprint;

    // sign identity (raw bytes, no newline)
    std::vector<uint8_t> idBytes(identity.c_str(), identity.c_str() + identity.length());
    logMessage("Signing: " + identity);
    std::vector<uint8_t> signature;
    if (!pwngrid::crypto::signMessage(idBytes, signature)) {
        logMessage("sign failed");
        return false;
    }
    logMessage("Sign succesful, continuing...");

    // base64 everything consistently
    String signatureB64 = pwngrid::crypto::base64Encode(signature);

    // For public_key the Python client base64-encodes the PEM that ends with a single newline.
    std::vector<uint8_t> pubVec((const uint8_t*)pubNorm.c_str(), (const uint8_t*)pubNorm.c_str() + pubNorm.length());
    String pubPEMB64 = pwngrid::crypto::base64Encode(pubVec);

    // payload: identity + pub + sig + data (server expects 'data' to be an object)
    JsonDocument body;
    body["identity"] = identity;
    body["public_key"] = pubPEMB64;
    body["signature"] = signatureB64;
    JsonObject data = body["data"].to<JsonObject>();
    JsonObject session = body["session"].to<JsonObject>();
    session["epochs"] = 0;
    data["extra"] = "test";

    String out;
    serializeJsonPretty(body, out); // compact JSON like the script does

    // no auth header
    logMessage("Data for enrol created, sending...");
    String resp = httpPostJson(String(Endpoint) + "/unit/enroll", out, false);
    logMessage("Response got, proceeding to parse...");
    if (resp.isEmpty()) {
        logMessage("enroll: empty response");
        return false;
    }

    JsonDocument rdoc;
    auto err = deserializeJson(rdoc, resp);
    if (err) {
        logMessage("enroll: invalid json response");
        return false;
    }
    if (rdoc["token"].is<String>()) {
        String t = rdoc["token"].as<String>();
        saveToken(t);
        logMessage("enroll: got token");
        pwngrid_indentity = fingerprint;
        lastTokenRefresh = (uint64_t)time(nullptr);
        saveSettings(); // Save new fingerprint only if enroll sucess
        return true;
    }

    logMessage("enroll: no token in response");
    return false;
}

bool api_client::sendMessageTo(const String &recipientFingerprint, const String &cleartext) {
    enrollWithGrid();
    // fetch recipient unit
    String r = httpGet(String(Endpoint) + "/unit/" + recipientFingerprint, false);
    if (r.length() == 0) {
        logMessage("send: could not fetch unit");
        return false;
    }
    JsonDocument rd;
    if (deserializeJson(rd, r)) {
        logMessage("send: parse unit json failed");
        return false;
    }
    if (!rd["public_key"].is<String>()) {
        logMessage("send: recipient public_key missing");
        return false;
    }
    // recipient public_key is base64(pem)
    String pubB64 = pwngrid::crypto::deNormalizePublicPEM(String(rd["public_key"].as<const char*>()));
    logMessage("Recepients public key: " + pubB64);
    std::vector<uint8_t> pubPemVec = pwngrid::crypto::base64Decode(pubB64);
    String pubPem = String((const char*)pubPemVec.data(), pubPemVec.size());

    // encrypt
    std::vector<uint8_t> clearVec(cleartext.c_str(), cleartext.c_str() + cleartext.length());
    std::vector<uint8_t> encrypted;
    logMessage("Encrypting message to " + recipientFingerprint);
    if (!pwngrid::crypto::encryptFor(clearVec, pubB64, encrypted)) {
        logMessage("encryptFor failed");
        return false;
    }
    String encB64 = pwngrid::crypto::base64Encode(encrypted);

    // sign encrypted blob with our private key
    std::vector<uint8_t> signature;
    if (!pwngrid::crypto::signMessage(encrypted, signature)) {
        logMessage("sign failed");
        return false;
    }
    String sigB64 = pwngrid::crypto::base64Encode(signature);

    // build Message json
    JsonDocument body;
    body["data"] = encB64;
    body["signature"] = sigB64;
    String out; serializeJson(body, out);

    String resp = httpPostJson(String(Endpoint) + "/unit/" + recipientFingerprint + "/inbox", out, true);
    logMessage(resp);
    
    if (resp.length() == 0) {
        logMessage("send: empty response");
        return false;
    }
    logMessage("send: ok");
    return true;
}

String api_client::getNameFromFingerprint(String fingerprint){
    String r1 = httpGet(String(Endpoint) + "/unit/" + fingerprint, false);
    logMessage(r1);
    if (r1.length() == 0) {
        fLogMessage("poll: could not fetch fingerprint %s\n", fingerprint.c_str());
        return "";
    }
    JsonDocument ud;
    if(deserializeJson(ud, r1)){
        return "";
    }
    String senderFingerprint = pwngrid::crypto::deNormalizePublicPEM(ud["name"].as<String>());
    logMessage(senderFingerprint);
    return senderFingerprint;
}

// Converts "2019-10-06T22:56:06Z" -> unix timestamp (UTC)
uint32_t api_client::isoToUnix(const String &iso) {
    // Expected format: YYYY-MM-DDTHH:MM:SSZ
    if (iso.length() < 20) return 0;

    struct tm t;
    memset(&t, 0, sizeof(t));

    t.tm_year = iso.substring(0, 4).toInt() - 1900;
    t.tm_mon  = iso.substring(5, 7).toInt() - 1;
    t.tm_mday = iso.substring(8, 10).toInt();

    t.tm_hour = iso.substring(11, 13).toInt();
    t.tm_min  = iso.substring(14, 16).toInt();
    t.tm_sec  = iso.substring(17, 19).toInt();

    // This gives seconds since epoch **in UTC**
    time_t ts = timegm(&t);
    return (uint32_t)ts;
}

time_t api_client::timegm(struct tm* t) {
    const int daysBeforeMonth[] =
        {0,31,59,90,120,151,181,212,243,273,304,334};

    int year = t->tm_year + 1900;
    int month = t->tm_mon;
    int day = t->tm_mday;

    int y = year - 1970;

    // seconds from years
    time_t seconds = y * 31536000ULL;
    // leap days
    seconds += ((y + 1) / 4) * 86400ULL;
    seconds -= ((y + 69) / 100) * 86400ULL;
    seconds += ((y + 369) / 400) * 86400ULL;

    // add days in year
    seconds += daysBeforeMonth[month] * 86400ULL;
    // leap year correction for Jan/Feb
    if (month > 1 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)))
        seconds += 86400ULL;

    seconds += (day - 1) * 86400ULL;

    seconds += t->tm_hour * 3600ULL;
    seconds += t->tm_min * 60ULL;
    seconds += t->tm_sec;

    return seconds;
}

int8_t api_client::checkNewMessagesAmount(){
    logMessage("Polling inbox...");
    enrollWithGrid();
    String r = httpGet(String(Endpoint) + "/unit/inbox/?p=1", true);
    if (r.length() == 0) {
        logMessage("poll: empty response");
        return -1;
    }
    JsonDocument rd;
    if (deserializeJson(rd, r)) {
        logMessage("poll: parse failed");
        return -1;
    }
    // Expect "messages" array in response like server. Format may vary.
    logMessage(r);
    if (!rd["messages"].is<JsonArray>()) {
        logMessage("poll: no messages array");
        return -1;
    }
    JsonArray msgs = rd["messages"].as<JsonArray>();
    return msgs.size();
}

#include "src.h"

bool api_client::pollInbox() {
    logMessage("Polling inbox...");
    enrollWithGrid();
    String r = httpGet(String(Endpoint) + "/unit/inbox/?p=1", true);
    if (r.length() == 0) {
        logMessage("poll: empty response");
        return false;
    }
    JsonDocument rd;
    if (deserializeJson(rd, r)) {
        logMessage("poll: parse failed");
        return false;
    }
    // Expect "messages" array in response like server. Format may vary.
    if (!rd["messages"].is<JsonArray>()) {
        logMessage("poll: no messages array");
        return true;
    }
    JsonArray msgs = rd["messages"].as<JsonArray>();
    for (JsonObject m : msgs) {
        uint16_t msg_id = m["id"].as<uint16_t>();
        String sender = m["sender"].as<String>();
        String senderName = m["sender_name"].as<String>();
        String timestamp = m["created_at"].as<String>();
        uint32_t unix_timestamp = isoToUnix(timestamp);
        String seen_at = m["seen_at"].as<String>();
        if(seen_at != "null"){
            httpGet(String(Endpoint) + "/unit/inbox/" + msg_id + "/deleted", true);
            logMessage("Removed message from server. Msg: " + String(msg_id));
            continue;
        }

        r = httpGet(String(Endpoint) + "/unit/inbox/" + msg_id, true);
        if(r.length() < 20){
            logMessage("Error pulling message data!");
            continue;
        }
        
        JsonDocument data;
        if(deserializeJson(data, r)){
            logMessage("Could not fetch message data!");
            continue;
        }

        String dataB64 = data["data"].as<String>();
        if(dataB64.length() == 0){
            logMessage("Message empty, skipping.");
            continue;
        }
        String sigB64 = data["signature"].as<String>();

        auto encBytes = pwngrid::crypto::base64Decode(dataB64);
        auto sigBytes = pwngrid::crypto::base64Decode(sigB64);
        // get sender public key
        String r = httpGet(String(Endpoint) + "/unit/" + sender, false);
        if (r.length() == 0) {
            fLogMessage("poll: could not fetch sender %s\n", sender.c_str());
            continue;
        }
        JsonDocument ud;
        if (deserializeJson(ud, r)) continue;
        String senderPubB64 = pwngrid::crypto::deNormalizePublicPEM(ud["public_key"].as<String>());
        logMessage(senderPubB64);

        // verify signature
        if (!pwngrid::crypto::verifyMessageWithPubPEM(encBytes, sigBytes, senderPubB64)) {
            logMessage("poll: signature verify failed");
            continue;
        }
        // decrypt
        std::vector<uint8_t> clear;
        if (!pwngrid::crypto::decrypt(encBytes, clear)) {
            logMessage("poll: decrypt failed");
            continue;
        }
        String txt((const char*)clear.data(), clear.size());
        fLogMessage("msg from %s: %s\n", sender.c_str(), txt.c_str());
        message newMessage = {
            senderName,
            sender,
            msg_id,
            txt,
            unix_timestamp,
            false
        };
        r = httpGet(String(Endpoint) + "/unit/inbox/" + msg_id + "/seen", true);
        logMessage("Set message id as read, response: " + r);
        if (r == "{\"success\":true}") {
            logMessage("Message marked as read on server.");
            registerNewMessage(newMessage);
            if(pwnagotchi.sound_on_events){
                Sound(1200, 60, true);
                delay(60);
                Sound(1600, 60, true);
                delay(60);
                Sound(2000, 80, true);
                delay(80);
            }
        } else {
            logMessage("Failed to mark message as read on server.");
        }
    }
    return true;
}

// helper: ensures /pwngrid dir exists and returns cache file path
static String getPwngridCachePath() {
    const char *p = "/pwngrid";
    if (!SD.exists(p)) SD.mkdir(p);
    return String("/pwngrid/cracks.conf");
}

// Add an AP to the cache for later upload. Appends to a JSON array of objects {"essid":"..","bssid":".."}
bool api_client::queueAPForUpload(const String &essid, const String &bssid) {
    String path = getPwngridCachePath();

    JsonDocument doc;
    JsonArray arr = doc.to<JsonArray>();

    if (SD.exists(path)) {
        File f = SD.open(path, FILE_READ);
        if (f) {
            String s = f.readString();
            f.close();
            if (s.length() > 0) {
                DeserializationError err = deserializeJson(doc, s);
                if (!err && doc.is<JsonArray>()) {
                    arr = doc.as<JsonArray>();
                }
            }
        }
    }

    JsonObject item = arr.add<JsonObject>();
    item["essid"] = essid;
    item["bssid"] = bssid;

    // write back
    String out;
    serializeJson(arr, out);
    File wf = SD.open(path, FILE_WRITE);
    if (!wf) {
        logMessage("queueAP: could not open cache for writing");
        return false;
    }
    wf.print(out);
    wf.close();
    logMessage("queueAP: saved to cache: " + essid + " / " + bssid);
    return true;
}

// Upload cached APs to /unit/report/aps. On success, clears the cache file.
bool api_client::uploadCachedAPs() {
    enrollWithGrid();
    String path = getPwngridCachePath();
    if (!SD.exists(path)) {
        logMessage("uploadCachedAPs: nothing to upload");
        return true; // nothing to do
    }

    File f = SD.open(path, FILE_READ);
    if (!f) {
        logMessage("uploadCachedAPs: failed to open cache");
        return false;
    }
    String s = f.readString();
    f.close();
    if (s.length() == 0) {
        logMessage("uploadCachedAPs: cache empty");
        return true;
    }

    JsonDocument doc;
    DeserializationError err = deserializeJson(doc, s);
    if (err) {
        logMessage("uploadCachedAPs: invalid cache json, clearing");
        // clear corrupted file
        File wf = SD.open(path, FILE_WRITE);
        if (wf) { wf.print("[]"); wf.close(); }
        return false;
    }
    JsonArray arr = doc.as<JsonArray>();
    if (!doc.is<JsonArray>() || arr.size() == 0) {
        logMessage("uploadCachedAPs: no entries to upload");
        return true;
    }

    // Build request body as array of objects with essid and bssid
    String body;
    serializeJson(arr, body);

    String url = String(Endpoint) + "/unit/report/aps";
    logMessage("uploadCachedAPs: uploading " + String(arr.size()) + " APs");
    String resp = httpPostJson(url, body, true);
    logMessage("uploadCachedAPs: server response: " + resp);
    if (!(resp == "{\"success\":true}")) {
        logMessage("uploadCachedAPs: upload failed or empty response");
        return false;
    }
    

    // On success, clear cache file
    File wf = SD.open(path, FILE_WRITE);
    if (wf) {
        wf.print("[]");
        wf.close();
        logMessage("uploadCachedAPs: upload successful, cache cleared");
        return true;
    }

    logMessage("uploadCachedAPs: uploaded but failed to clear cache");
    return true;
}


