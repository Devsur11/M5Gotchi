#include "inputManager.h"
#include "M5Unified.h"
#include "logger.h"

namespace inputManager {
    
    // Button timing
    const uint32_t LONG_PRESS_THRESHOLD = 700; // 1 second for long press
    
    // Button state tracking
    struct ButtonTracker {
        bool isCurrentlyPressed = false;
        bool wasPressed = false;
        uint32_t pressStartTime = 0;
        bool longPressDetected = false;
    };
    
    static ButtonTracker buttonA;
    static ButtonTracker buttonB;

void init() {
    logMessage("Input Manager initialized for button-only mode");
}

void update() {
    M5.update();
    
    // Button A handling
    bool btnA_pressed = M5.BtnA.isPressed();
    if (btnA_pressed && !buttonA.isCurrentlyPressed) {
        // Button just pressed
        buttonA.isCurrentlyPressed = true;
        buttonA.pressStartTime = millis();
        buttonA.longPressDetected = false;
        buttonA.wasPressed = false;
        Serial.println("BtnA pressed");
    } else if (btnA_pressed && buttonA.isCurrentlyPressed) {
        // Button held - check for long press
        if (!buttonA.longPressDetected && (millis() - buttonA.pressStartTime >= LONG_PRESS_THRESHOLD)) {
            buttonA.longPressDetected = true;
            buttonA.wasPressed = true;
            Serial.println("BtnA long press detected");
        }
    } else if (!btnA_pressed && buttonA.isCurrentlyPressed) {
        // Button just released
        buttonA.isCurrentlyPressed = false;
        if (!buttonA.longPressDetected) {
            // It was a short press
            buttonA.wasPressed = true;
        }
        Serial.println("BtnA released");
    }
    
    // Button B handling
    bool btnB_pressed = M5.BtnB.isPressed();
    if (btnB_pressed && !buttonB.isCurrentlyPressed) {
        // Button just pressed
        buttonB.isCurrentlyPressed = true;
        buttonB.pressStartTime = millis();
        buttonB.longPressDetected = false;
        buttonB.wasPressed = false;
        Serial.println("BtnB pressed");
    } else if (btnB_pressed && buttonB.isCurrentlyPressed) {
        // Button held - check for long press
        if (!buttonB.longPressDetected && (millis() - buttonB.pressStartTime >= LONG_PRESS_THRESHOLD)) {
            buttonB.longPressDetected = true;
            buttonB.wasPressed = true;
            Serial.println("BtnB long press detected");
        }
    } else if (!btnB_pressed && buttonB.isCurrentlyPressed) {
        // Button just released
        buttonB.isCurrentlyPressed = false;
        if (!buttonB.longPressDetected) {
            // It was a short press
            buttonB.wasPressed = true;
        }
        Serial.println("BtnB released");
    }
}

ButtonState getButtonA() {
    // Deprecated - not used
    return BUTTON_IDLE;
}

ButtonState getButtonB() {
    // Deprecated - not used
    return BUTTON_IDLE;
}

bool isButtonAPressed() {
    if (buttonA.wasPressed && !buttonA.longPressDetected) {
        buttonA.wasPressed = false;
        Serial.println("isButtonAPressed() = true");
        return true;
    }
    return false;
}

bool isButtonBPressed() {
    if (buttonB.wasPressed && !buttonB.longPressDetected) {
        buttonB.wasPressed = false;
        Serial.println("isButtonBPressed() = true");
        return true;
    }
    return false;
}

bool isButtonALongPressed() {
    if (buttonA.wasPressed && buttonA.longPressDetected) {
        buttonA.wasPressed = false;
        Serial.println("isButtonALongPressed() = true");
        return true;
    }
    return false;
}

bool isButtonBLongPressed() {
    if (buttonB.wasPressed && buttonB.longPressDetected) {
        buttonB.wasPressed = false;
        Serial.println("isButtonBLongPressed() = true");
        return true;
    }
    return false;
}

void resetButtonStates() {
    // States are automatically managed

    // if (buttonB.state == BUTTON_IDLE) {
    //     buttonB.wasProcessed = false;
    // }
}

String getHelpText() {
    return "BtnA: Select/OK | BtnB: Back/Cancel | Long Press: Menu";
}

}
