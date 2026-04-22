#include "achievementsUI.h"
#include "ui.h"
#include "logger.h"
#include "achievements.h"
#include "src.h"
#include "inputManager.h"

#define BUTTON_ONLY_INPUT

void drawAchievements() {
    debounceDelay();
    
    uint8_t total = ACH_COUNT;
    uint8_t unlocked = achievements_get_unlocked_count();
    uint8_t selected_idx = 0;
    const auto& states = achievements_get_all_states();

    while (true) {
        // Draw menu
        if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
        
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.setTextSize(2);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString("Achievements", canvas_center_x, 8);
        
        // Draw progress bar
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_center);
        canvas_main.drawString(String(unlocked) + "/" + String(total), canvas_center_x, 20);
        
        int bar_width = 200;
        int bar_height = 10;
        int bar_x = (display_w - bar_width) / 2;
        int bar_y = 28;
        
        canvas_main.drawRect(bar_x, bar_y, bar_width, bar_height, tx_color_rgb565);
        if (unlocked > 0) {
            int filled = (unlocked * bar_width) / total;
            canvas_main.fillRect(bar_x, bar_y, filled, bar_height, tx_color_rgb565);
        }
        
        // Draw achievement list
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(top_left);
        
        int start_y = 45;
        int item_height = 12;
        int visible_items = 4;
        
        // Calculate scroll
        int scroll_start = (selected_idx > visible_items - 1) ? selected_idx - visible_items + 1 : 0;
        
        for (int i = 0; i < visible_items && (scroll_start + i) < total; i++) {
            uint8_t idx = scroll_start + i;
            const AchievementData* data = achievements_get_data((AchievementID)idx);
            const AchievementState& state = states[idx];
            
            if (!data) continue;
            
            int y = start_y + (i * item_height);
            
            // Highlight selected
            if (idx == selected_idx) {
                canvas_main.fillRect(2, y - 1, 236, item_height, tx_color_rgb565);
                canvas_main.setTextColor(bg_color_rgb565);
            } else {
                canvas_main.setTextColor(tx_color_rgb565);
            }
            
            // Draw lock/unlock icon
            String icon = state.unlocked ? "[x]" : "[ ]";
            canvas_main.drawString(icon, 5, y);
            
            // Draw name - show ??? for secret achievements if not unlocked
            String display_name;
            if (data->is_secret && !state.unlocked) {
                display_name = "???";
            } else {
                display_name = String(data->name);
            }
            
            canvas_main.drawString(display_name, 30, y);
            
            // Restore text color for next item
            if (idx == selected_idx) {
                canvas_main.setTextColor(tx_color_rgb565);
            }
        }
        
        // Draw instructions
        canvas_main.setTextSize(1);
        canvas_main.setTextDatum(middle_center);
        canvas_main.setTextColor(tx_color_rgb565);
        #ifdef BUTTON_ONLY_INPUT
            canvas_main.drawString("A:info B:scroll B--:back", canvas_center_x, canvas_h - 10);
        #else
            canvas_main.drawString("[,][.] navigate [ENTER] info [`] back", canvas_center_x, canvas_h - 10);
        #endif
        
        if (displayMutex) xSemaphoreGive(displayMutex);
        pushAll();
        
        // Handle input
        M5.update();
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
        keyboard_changed = M5Cardputer.Keyboard.isChange();
        if(keyboard_changed){Sound(10000, 100, sound);}
        
        Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
        
        // Navigation
        for (auto k : status.word) {
            if (k == ';') {
                if (selected_idx > 0) selected_idx--;
                debounceDelay();
            }
            if (k == '.') {
                if (selected_idx < total - 1) selected_idx++;
                debounceDelay();
            }
            if (k == '`') {
                menuID = 1;  // Return to settings
                return;
            }
        }
        
        // Show details
        if (status.enter) {
#else
        inputManager::update();
        
        if (inputManager::isButtonBPressed()) {
            if (selected_idx < total - 1) selected_idx++;
            else{
                selected_idx = 0;
            }
            debounceDelay();
        }
        
        if (inputManager::isButtonBLongPressed()) {
            menuID = 6;  // Return to settings
            return;
        }
        
        if (inputManager::isButtonAPressed()) {
#endif
            // Show details dialog
            const AchievementData* data = achievements_get_data((AchievementID)selected_idx);
            const AchievementState& state = states[selected_idx];
            
            if (data) {
                debounceDelay();
                
                String title = data->is_secret && !state.unlocked ? "???" : String(data->name);
                String desc = String(data->description);
                String status_str = state.unlocked ? "UNLOCKED" : "LOCKED";
                
                if (state.unlocked && state.unlock_time > 0) {
                    // Format unlock time
                    time_t t = (time_t)state.unlock_time;
                    struct tm* timeinfo = localtime(&t);
                    char time_str[20];
                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M", timeinfo);
                    status_str += " @ " + String(time_str);
                }
                if(data->is_secret && !state.unlocked){
                    //do nothing - for secret advancments do not show details
                }
                else{
                    canvas_main.clear();
                    canvas_main.fillScreen(bg_color_rgb565);
                    canvas_main.setTextColor(tx_color_rgb565);
                    canvas_main.setTextSize(2);
                    canvas_main.setTextDatum(middle_center);
                    canvas_main.drawString(title, canvas_center_x, 50);
                    canvas_main.setCursor(0, 65);
                    canvas_main.setTextSize(1);
                    canvas_main.println(desc);
                    canvas_main.setTextDatum(top_left);
                    canvas_main.drawString(status_str, 190, 30);
                    if(!state.unlocked){
                        canvas_main.drawBitmap(190, 0, lock,LOCK_WIDTH, LOCK_HEIGHT, tx_color_rgb565);
                    }
                    else{
                        canvas_main.drawBitmap(190, 0, unlock, UNLOCK_WIDTH, UNLOCK_HEIGHT, tx_color_rgb565);
                    }
                    pushAll();
                    while(true){
                        #ifdef BUTTON_ONLY_INPUT
                        inputManager::update();
                        if (inputManager::isButtonAPressed() || inputManager::isButtonBPressed()) {
                            break;
                        }
                        #else
                        M5.update();
                        M5Cardputer.update();
                        if(M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER) || M5Cardputer.Keyboard.isKeyPressed('`')){
                            debounceDelay();
                            break;
                        }
                        #endif
                    }
                }
                debounceDelay();
            }
// #ifdef BUTTON_ONLY_INPUT
//         }
// #endif
        }
        
        delay(10);
    }
}

void drawNewAchUnlock(AchievementID id){
}
