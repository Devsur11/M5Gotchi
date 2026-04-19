#include "achievements.h"
#include "settings.h"
#include "crypto.h"
#include "logger.h"
#include <time.h>

// Global achievements state
static std::vector<AchievementState> g_achievements(ACH_COUNT);
static bool g_achievements_loaded = false;

const AchievementData* achievements_get_data(AchievementID id) {
    if (id >= ACH_COUNT) return nullptr;
    return &ACHIEVEMENTS[id];
}

bool achievements_is_unlocked(AchievementID id) {
    if (id >= ACH_COUNT) return false;
    return g_achievements[id].unlocked;
}

uint32_t achievements_get_unlock_time(AchievementID id) {
    if (id >= ACH_COUNT) return 0;
    return g_achievements[id].unlock_time;
}

uint8_t achievements_get_unlocked_count() {
    uint8_t count = 0;
    for (const auto& ach : g_achievements) {
        if (ach.unlocked) count++;
    }
    return count;
}

const std::vector<AchievementState>& achievements_get_all_states() {
    return g_achievements;
}

bool achievements_load() {
    SD_LOCK();
    if (!FSYS.exists(ACHIEVEMENTS_CONFIG_FILE)) {
        SD_UNLOCK();
        logMessage("Achievements config doesn't exist, using defaults");
        return false;
    }

    File f = FSYS.open(ACHIEVEMENTS_CONFIG_FILE, FILE_READ);
    if (!f) {
        SD_UNLOCK();
        logMessage("Failed to open achievements config");
        return false;
    }

    String encrypted_content = f.readString();
    f.close();
    SD_UNLOCK();

    String device_mac = originalMacAddress;
    std::vector<uint8_t> decrypted;
    
    if (!pwngrid::crypto::decryptWithPassword(encrypted_content, device_mac, decrypted)) {
        logMessage("Failed to decrypt achievements");
        return false;
    }

    // Parse JSON
    String json_str((const char*)decrypted.data(), decrypted.size());
    
    StaticJsonDocument<2048> doc;
    DeserializationError err = deserializeJson(doc, json_str);
    
    if (err) {
        logMessage("Failed to parse achievements JSON: " + String(err.c_str()));
        return false;
    }

    JsonArray arr = doc.as<JsonArray>();
    for (uint8_t i = 0; i < ACH_COUNT && i < arr.size(); i++) {
        JsonObject obj = arr[i];
        g_achievements[i].unlocked = obj["unlocked"] | false;
        g_achievements[i].unlock_time = obj["time"] | 0;
    }

    logMessage("Achievements loaded: " + String(achievements_get_unlocked_count()) + "/" + String(ACH_COUNT));
    return true;
}

bool achievements_save() {
    StaticJsonDocument<2048> doc;
    JsonArray arr = doc.to<JsonArray>();

    for (uint8_t i = 0; i < ACH_COUNT; i++) {
        JsonObject obj = arr.createNestedObject();
        obj["id"] = i;
        obj["unlocked"] = g_achievements[i].unlocked;
        obj["time"] = g_achievements[i].unlock_time;
    }

    String json_str;
    serializeJson(doc, json_str);

    // Encrypt using device MAC as secret
    String device_mac = originalMacAddress;
    std::vector<uint8_t> json_bytes((const uint8_t*)json_str.c_str(), 
                                     (const uint8_t*)json_str.c_str() + json_str.length());
    String encrypted = pwngrid::crypto::encryptWithPassword(json_bytes, device_mac);

    SD_LOCK();
    File f = FSYS.open(ACHIEVEMENTS_CONFIG_FILE, FILE_WRITE);
    if (!f) {
        SD_UNLOCK();
        logMessage("Failed to open achievements config for writing");
        return false;
    }

    size_t written = f.print(encrypted);
    f.close();
    SD_UNLOCK();

    if (written == 0) {
        logMessage("Failed to write achievements config");
        return false;
    }

    logMessage("Achievements saved");
    return true;
}

bool achievements_register(AchievementID id) {
    if (id >= ACH_COUNT) return false;

    // Already unlocked?
    if (g_achievements[id].unlocked) return true;

    // Unlock it
    g_achievements[id].unlocked = true;
    g_achievements[id].unlock_time = (uint32_t)time(nullptr);

    logMessage("Achievement unlocked: " + String(id) + " - " + String(ACHIEVEMENTS[id].name));

    // Persist
    if (!achievements_save()) {
        logMessage("Warning: Failed to save achievement unlock");
        return false;
    }

    return true;
}

void achievements_init() {
    // Initialize all to unlocked=false
    for (uint8_t i = 0; i < ACH_COUNT; i++) {
        g_achievements[i].unlock_time = 0;
        g_achievements[i].unlocked = false;
    }

    // Try to load from storage
    achievements_load();
    g_achievements_loaded = true;
}