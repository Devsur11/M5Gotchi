#pragma once

#include <Arduino.h>

namespace inputManager {
    // Button states
    enum ButtonState {
        BUTTON_IDLE,
        BUTTON_SHORT_PRESS,
        BUTTON_LONG_PRESS
    };

    // Initialize button handlers
    void init();
    
    // Update button states (call regularly)
    void update();
    
    // Get button A state
    ButtonState getButtonA();
    
    // Get button B state
    ButtonState getButtonB();
    
    // Check if button A was short pressed
    bool isButtonAPressed();
    
    // Check if button B was short pressed
    bool isButtonBPressed();
    
    // Check if button A was long pressed
    bool isButtonALongPressed();
    
    // Check if button B was long pressed
    bool isButtonBLongPressed();
    
    // Reset button states after reading
    void resetButtonStates();
    
    // Get help text for current mode
    String getHelpText();
}
