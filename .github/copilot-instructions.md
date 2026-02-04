# ESPBlaster/M5Gotchi Copilot Instructions

## Project Overview

M5Gotchi is a Pwnagotchi implementation for M5Cardputer—a portable hacking device running Arduino-based firmware with a full keyboard UI. The project bridges manual Wi-Fi penetration testing with social networking features (PWNGrid). **Key constraint**: This is resource-constrained embedded C++ (ESP32-S3), not general software.

## Architecture

### Core Layers

1. **Hardware Abstraction** ([M5Cardputer lib](lib/M5Cardputer/), M5Unified)
   - Manages display (`M5Canvas`), keyboard input, speaker/buzzer, SD card, and device-specific GPIO
   - Use `M5.update()` and `M5Cardputer.update()` to poll input
   - Display operations must be protected by `displayMutex` semaphore to prevent race conditions

2. **UI System** ([src/ui.cpp](src/ui.cpp), [src/ui.h](src/ui.h))
   - **Canvas-based drawing**: All UI uses `canvas_main` (M5Canvas sprite) with `pushAll()` to flush to hardware
   - **Global state**: `menuID` controls which screen is active; `appID` drives app execution via `runApp()`
   - **Font handling**: Custom fonts loaded from SD (`/fonts/big.vlw`, `/fonts/small.vlw`) using `canvas_main.loadFont(FSYS, path)`. Critical: **Always unload fonts after use** with `canvas_main.unloadFont()` before loading another
   - **Input handling**: Keyboard (M5Cardputer) or button-only input (M5StickS3) via `#ifdef BUTTON_ONLY_INPUT`
   - **Dialog functions**: `drawInfoBox()`, `drawQuestionBox()`, `drawMultiChoice()` for blocking UX; `drawHintBox()` with bitfield tracking to show hints once

3. **Core Features**
   - **Pwnagotchi** ([src/pwnagothi.cpp](src/pwnagothi.cpp)): Wi-Fi scanning, handshake capture, mood system
   - **PWNGrid** ([src/pwngrid.cpp](src/pwngrid.cpp)): P2P mesh messaging with cryptographic identity; uses JSON messages
   - **Storage**: Unified via `FSYS` macro—either LittleFS (m5sticks3) or SD (Cardputer). See [src/settings.h](src/settings.h) for `#ifdef USE_LITTLEFS`
   - **Wardriving** ([src/wardrive.cpp](src/wardrive.cpp)): GPS integration for location-based Wi-Fi logging
   - **WPA-Sec** ([src/wpa_sec.cpp](src/wpa_sec.cpp)): Encrypted password database upload

### Critical Global Resources

- **`displayMutex`** ([src/ui.h](src/ui.h)): **Always take before any canvas drawing**. Use `if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);` and release with `xSemaphoreGive(displayMutex)`
- **`FSYS` macro** ([src/settings.h](src/settings.h)): Conditional SD/LittleFS abstraction—use this, not `SD` or `LittleFS` directly
- **`logMessage(String)`** ([src/logger.cpp](src/logger.cpp)): Thread-safe serial logging for debugging

## Build & Environments

**PlatformIO-based** with three target environments in [platformio.ini](platformio.ini):

- **Cardputer-dev / Cardputer-full**: M5Stack CardPuter (full keyboard, 8MB flash)
- **m5sticks3**: M5StickS3 (LittleFS only, minimal memory, button-only input)

### Build Commands

```bash
# Standard build (Cardputer-dev)
pio run

# Build all environments
pio run --environment Cardputer-dev && pio run --environment Cardputer-full && pio run --environment m5sticks3

# Upload to device
pio run --target upload --environment Cardputer-dev

# Monitor serial output
pio device monitor -b 115200

# With MQTT coredump logging (requires credentials)
./scripts/build_with_mqtt.sh Cardputer-dev
```

**Build flags** ([platformio.ini](platformio.ini)):
- `-DBYPASS_SD_CHECK`: Skip SD card requirement check
- `-DM5STICKS3_ENV`: Enable LittleFS and button-only input
- `-DENABLE_COREDUMP_LOGGING`: Add MQTT-based crash reporting (requires MQTT credentials via `build_with_mqtt.sh`)

## Key Development Patterns

### Input Handling (Dual-Mode)

Keyboard (M5Cardputer) and button (M5StickS3) are mutually exclusive:

```cpp
#ifndef BUTTON_ONLY_INPUT
  M5Cardputer.update();
  auto keysState = M5Cardputer.Keyboard.keysState();
  // keysState.word contains typed characters
#else
  inputManager::update();
  if (inputManager::isButtonAPressed()) { ... }
#endif
```

### Font Loading (Critical Pattern)

**Always unload before loading a new font**:

```cpp
if (FSYS.exists("/fonts/big.vlw")) {
    canvas_main.loadFont(FSYS, "/fonts/big.vlw");
    canvas_main.setTextSize(0.35);
    canvas_main.drawString(text, x, y);
    canvas_main.unloadFont();  // MUST DO THIS
    canvas_main.setFont(&fonts::Font0);  // Reset to default
}
```

### Canvas Drawing (Threadsafe Pattern)

**All canvas operations must be protected**:

```cpp
if (displayMutex) xSemaphoreTake(displayMutex, portMAX_DELAY);
canvas_main.fillScreen(bg_color_rgb565);
canvas_main.setTextColor(tx_color_rgb565);
canvas_main.drawString("text", x, y);
xSemaphoreGive(displayMutex);
pushAll();  // Flush to hardware
```

### Menu State Machine

UI is menu-driven with global `menuID`:

```cpp
void updateUi(bool show_toolbars, bool triggerPwnagothi, bool overrideDelay) {
  switch (menuID) {
    case 0: // main menu
    case 1: // submenu
    case 2: // app launcher
    ...
  }
}
```

Apps (`runApp(uint8_t appID)`) are modal overlays that modify `menuID` on exit.

### File I/O

- Always use `FSYS` (not `SD` or `LittleFS`)
- JSON: `ArduinoJson` library (v7.4.2)
- Paths: `/pwngrid/` for peer data, `/handshake/` for captures, `/fonts/` for assets
- Example:

```cpp
StaticJsonDocument<512> doc;
deserializeJson(doc, FSYS.open("/m5gothi.conf", FILE_READ));
String name = doc["name"];  // safe access
```

## Common Tasks

### Add a New Menu Item

1. Define `menuID` constant in [src/ui.cpp](src/ui.cpp)
2. Add `case` in `updateUi()`'s switch statement
3. Draw UI inside `if (displayMutex) { ... }` block, call `pushAll()`
4. Update `menuID` based on input to navigate

### Modify Wi-Fi Scanning

[src/pwnagothi.cpp](src/pwnagothi.cpp): `speedScan()` is the main loop. It populates `wifiSpeedScan` vector used by UI and [src/PMKIDGrabber.cpp](src/PMKIDGrabber.cpp).

### Handle PWNGrid Messages

[src/pwngrid.cpp](src/pwngrid.cpp): `pwngridAdvertise()` broadcasts mood; `pollInbox()` fetches encrypted messages. Messages stored as JSON in `/pwngrid/chats/`.

### Add Custom Mood/Personality

[src/mood.cpp](src/mood.cpp): Moods are arrays of phrases/faces. Load via [src/moodLoader.cpp](src/moodLoader.cpp). Personality config in [src/settings.cpp](src/settings.cpp).

## Memory & Performance Notes

- **PSRAM available** on Cardputer no but on StickS3 8mb large allocations
- **Mutex contention**: `displayMutex` serializes all UI; keep canvas ops short
- **File I/O blocks**: SD reads are slow (~10-100ms); prefer batch operations
- **Vector/String overhead**: Use references in hot loops; prefer static strings for error messages
- **Font loading**: VLW fonts are large; unload when switching sizes to free memory

## Testing & Debugging

- **Serial logs**: `logMessage("text")` prints to `/dev/ttyUSB0` at 115200 baud
- **Core dumps**: Enable via `build_with_mqtt.sh` to send crash reports to MQTT broker
- **Emulator**: No official emulator; physical device testing required
- **Syntax checks**: PlatformIO's compiler is strict; test both environments (Cardputer + m5sticks3)

## External Dependencies

- **M5Unified / M5GFX**: Custom forks in [lib/](lib/) (GitHub URLs in [platformio.ini](platformio.ini))
- **ESPAsyncWebServer**: Evil portal & firmware updater
- **ArduinoJson**: Configuration and PWNGrid message serialization
- **JPEGDEC**: Mood display (not currently used, possible future feature)
- **PubSubClient**: MQTT coredump reporting

## Conventions

- **Naming**: `camelCase` for functions/vars, `SNAKE_CASE` for defines
- **Headers**: Each `.cpp` has matching `.h` with function declarations
- **Comments**: Sparse; code is self-documenting. Mark TODOs with `//TODO: ...`
- **Error handling**: Log and return false/nullptr; no exceptions (embedded C++)
