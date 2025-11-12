#include "api_client.h"
#include "crypto.h"
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <mbedtls/sha256.h>
#include "settings.h"

using namespace api_client;
using namespace pwngrid::crypto;

static const char *Endpoint = "https://api.pwnagotchi.ai/api/v1";
static String token = "";
static const char *tokenPath = "/token.json";
static String keysPathGlobal = "/keys";

bool saveToken(const String &t) {
    DynamicJsonDocument doc(512);
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
    DynamicJsonDocument doc(512);
    if (deserializeJson(doc, s)) return false;
    if (doc.containsKey("token")) {
        token = String(doc["token"].as<const char*>());
        return true;
    }
    return false;
}

bool api_client::init(const String &keysPath) {
    keysPathGlobal = keysPath;
    if (!SD.begin(true)) {
        logMessage("SD mount failed");
        return false;
    }
    if (!pwngrid::crypto::ensureKeys(keysPath)) {
        logMessage("crypto keys ensure failed");
        return false;
    }
    loadToken();
    return true;
}

// helper: http POST json -> returns body string or empty on error
static String httpPostJson(const String &url, const String &json, bool auth) {
    WiFiClientSecure *client = new WiFiClientSecure();
    client->setInsecure(); // TODO: replace with cert verification
    HTTPClient https;
    https.begin(*client, url);
    https.addHeader("Content-Type", "application/json");
    if (auth && token.length()) {
        https.addHeader("Authorization", "Bearer " + token);
    }
    int code = https.POST(json);
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
    WiFiClientSecure *client = new WiFiClientSecure();
    client->setInsecure();
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

    // base64 everything consistently
    String signatureB64 = pwngrid::crypto::base64Encode(signature);

    // For public_key the Python client base64-encodes the PEM that ends with a single newline.
    std::vector<uint8_t> pubVec((const uint8_t*)pubNorm.c_str(), (const uint8_t*)pubNorm.c_str() + pubNorm.length());
    String pubPEMB64 = pwngrid::crypto::base64Encode(pubVec);

    // payload: identity + pub + sig + data (server expects 'data' to be an object)
    StaticJsonDocument<512> body;
    body["identity"] = identity;
    body["public_key"] = pubPEMB64;
    body["signature"] = signatureB64;
    JsonObject data = body.createNestedObject("data");
    JsonObject session = data.createNestedObject("session");
    session["epochs"] = 0;
    data["extra"] = "test";

    String out;
    serializeJsonPretty(body, out); // compact JSON like the script does

    // no auth header
    String resp = httpPostJson(String(Endpoint) + "/unit/enroll", out, false);
    if (resp.isEmpty()) {
        logMessage("enroll: empty response");
        return false;
    }

    DynamicJsonDocument rdoc(512);
    auto err = deserializeJson(rdoc, resp);
    if (err) {
        logMessage("enroll: invalid json response");
        return false;
    }
    if (rdoc.containsKey("token")) {
        String t = rdoc["token"].as<String>();
        saveToken(t);
        logMessage("enroll: got token");
        pwngrid_indentity = fingerprint;
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
    if (!rd.containsKey("public_key")) {
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

bool api_client::pollInbox() {
    enrollWithGrid();
    String r = httpGet(String(Endpoint) + "/unit/inbox/?p=1", true);
    logMessage(r);
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
    if (!rd.containsKey("messages")) {
        logMessage("poll: no messages");
        return true;
    }
    JsonArray msgs = rd["messages"].as<JsonArray>();
    for (JsonObject m : msgs) {
        uint16_t msg_id = m["id"].as<uint16_t>();
        String sender = m["sender"].as<String>();

        String r2 = httpGet(String(Endpoint) + "/unit/inbox/" + msg_id, true);
        logMessage(r2);
        if(r2.length() < 20){
            logMessage("Error pulling message data!");
            continue;
        }
        
        JsonDocument data;
        if(deserializeJson(data, r2)){
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
        String r3 = httpGet(String(Endpoint) + "/unit/" + sender, false);
        logMessage(r3);
        if (r3.length() == 0) {
            fLogMessage("poll: could not fetch sender %s\n", sender.c_str());
            continue;
        }
        JsonDocument ud;
        if (deserializeJson(ud, r3)) continue;
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
    }
    return true;
}
