![baner](https://github.com/user-attachments/assets/8daf0ad9-fb8c-4d7c-812c-39e26de5e7f4)


# M5Gothi

M5Gothi brings the powerful Pwnagotchi functions and interface to the M5Cardputer platform, providing both automatic and manual Wi-Fi control through an integrated keyboard interface, so you can finally go touch some grass and hack at the same time. Inspied by the original Pwnagotchi project. It doesn't have AI, but at least its working like it should.

---

> [!CAUTION]
> THIS FIRMWARE CAN BE USED IN WAYS THAT MAY VIOLATE LOCAL LAWS. YOU ARE RESPONSIBLE FOR YOUR OWN ACTIONS. DO NOT USE THIS FOR MALICIOUS PURPOSES.
> **THIS IS A RESEARCH TOOL DESIGNED FOR EDUCATIONAL AND LEGAL SECURITY TESTING PURPOSES ONLY.**
> This tool is intended **only for legal research and educational purposes**.
> Use of this firmware on unauthorized networks, or against devices without explicit permission, is **strictly prohibited** and **illegal in many countries**.
> The author takes **no responsibility** for any misuse, damage, or legal consequences resulting from use of this software. Always comply with local laws and regulations.

---

# Main screen data

<p align=center>
  <img src="https://github.com/user-attachments/assets/63eb92f1-4194-431e-8f74-3df0472611a7" width="300">
</p>

---

## Features

- Full Pwnagothi functionality adapted for M5Cardputer
- Manual Wi-Fi control via integrated keyboard UI making it first fully UI-controlled pwnagotchi
- Automatic handshake capture using  Auto Mode
- **Update firmware directly from GitHub, SD card, or built-in Web UI**
- Advanced personality, for better control over pwnagotchi functions
- pwngrid connection for interaction with other pwnagotchis
- GPS support for wardriving or getting location info from pwned networks
- integration with wigle for wardriving data upload
- full file manager with build-in file editor

---
> [!IMPORTANT]
> An SD card is **required** for the firmware to function properly.

### SD Card File Structure

- Configuration file: m5gotchi.conf will be created at first boot and then used to store informations. **Don't mess with it at your own - use device UI to change these values!
- personality will be saved in file called personality.conf.
- Wpa-sec needed files: uploaded.json, cracked.json. Do not edit those files, and if you're running lite mode and need to view them on pc - use text editor of your choice.
- Captured handshakes will be stored inside a folder called:

  ```
  /handshake
  ```
  
---

## Supported Devices

| Device         | Status         | Notes                          |
|----------------|----------------|--------------------------------|
| M5Cardputer    | ✅ Supported   | Main target device             |
| M5Cardputer adv| ✅ Supported   | Tested And Work Fine           |
| M5Stack Core2  | ⏳ Planned     | Requires GPIO adaptation       |
| M5StickC       | ⏳ Planned     | Requires GPIO adaptation       |
| M5Paper        | ⏳ Planned     | E-ink rendering testing needed |
| LILIGO t-embed | ⏳ Planned     | Requires GPIO adaptation       |

>[!NOTE]
>For devices that I planned: I do not own any of this devices, support for them will be only made with help from testers. Feel free to join me with testing on discord.

---

## TODO / Planned Features

| Feature                 | Status     |
|-------------------------|------------|
| Pwnagothi Auto Mode     | ✅ Done    |
| GitHub Update Support   | ✅ Done    |
| SD Card Update          | ✅ Done    |
| Web UI Update           | ✅ Done    |
| Handshake upload to web | ✅ Done    |
| PWNGrid support         | ✅ Done    |
| Custom UI plugins       | Planned    |


>[!NOTE]
>If you want to see some of your features, submit ideas with an pull request.

---

## Requirements

- [PlatformIO](https://platformio.org/) — for building and flashing the firmware
- Git — for cloning the repository
- All other dependencies are automatically handled by PlatformIO

### Installing PlatformIO

You can install PlatformIO using either:

- **Visual Studio Code extension**
  - Install VS Code
  - Open Extensions → Search for "PlatformIO IDE"
  - Install and reload

- **Command-line (CLI)**
  Follow instructions here: [https://platformio.org/install/cli](https://platformio.org/install/cli)

---

## Build and Flash Instructions

1. Clone this repository:

   ```bash
   git clone https://github.com/Devsur11/M5Gotchi/
   cd M5gothi
   ```

2. Build and upload via PlatformIO:

   ```bash
   pio run
   pio run --target upload
   ```

|Esp pin|Sd pin|
|-------|------|
|G12|CS|
|G14|MOSI|
|G40|CLK|
|G39|MISO|

---

## Usage Instructions

>[!IMPORTANT]
>To use any of the functions, pwnagothi mode must be set to MANU, otherwise nothing will work!

- **UI** is fully controlled via the **built-in keyboard**
- Use  `G0` button to turn screen off or change the mode - customize this is settings
- Press `ESC` to open the main menu
- Use **arrow keys** to navigate
- Exit apps using `Fn + ESC`
- On first boot there will be created m5gotchi.conf file - use it to change setting on **lite mode** compilations
- Customize name to your likings via settings
- customize theme to your liking via settings
- Use ENTER to confirm or `y` or `n` when asked to do so
- use `c` to clone wifi when in wifi details menu
- handshakes are stored in `/handshake/` folder with filemanes containing SSID and BSSID of network that was pwned

## Update Methods

| Method        | Status    | Description                                     |
|---------------|-----------|-------------------------------------------------|
| GitHub        | ✅ Done   | Update via GitHub Pages through UI              |
| SD Card       | ✅ Done   | Place update.bin file and trigger update        |
| Web UI        | ✅ Done   | Upload update through browser interface         |

---

## Example screenshots of menus

<p align="center">
  <img src="https://github.com/user-attachments/assets/ba45d464-f09b-4d81-b8b9-d0ca3074e64e" width="300">
  <img src="https://github.com/user-attachments/assets/1d4dfe88-0109-47bb-a71e-f5fe25f6150f" width="300">
  <img src="https://github.com/user-attachments/assets/52b26e04-b6e9-41c0-bf25-89069a821e64" width="300">
</p>

---

## Core dump reporter (MQTT) 🔧

When built with `ENABLE_COREDUMP_LOGGING` the firmware will publish core dump uploads over MQTT to the configured broker. The flow is:

- `device/coredump/meta` — JSON metadata published first. Contains fields:
  - `upload_id` (string)
  - `mac` (string)
  - `board` (numeric board id)
  - `version` (firmware version / build tag)
  - `build_time` (compile timestamp)
  - `reset_reason` (boot reason)
  - `idf` (ESP-IDF version)
  - `chip_model`, `chip_cores`, `chip_rev`
  - `size`, `chunks`, `addr`, `freeHeap`
  - `gps_tx`, `gps_rx` (GPS TX/RX pins configured)
  - `advertise_pwngrid`, `toggle_pwnagothi_with_gpio0`, `cardputer_adv`, `limitFeatures` (boolean flags reported as 0/1)

- `device/coredump/chunk` — messages with a small header JSON (upload_id, seq, len, checksum, total) followed by `\n` and base64-encoded chunk payload.

- `device/coredump/end` — final JSON with `upload_id`, `status`, `sent_chunks`, `checksum` (combined checksum of all bytes).

- `device/coredump/ack/<upload_id>` (or `device/coredump/ack/#`) — the collector should send an acknowledgement JSON with `upload_id`, `status` (`ok` or `complete`), `received_chunks`, and `checksum` when the uploaded file is verified; the device will only erase the core dump after receiving a matching verification ack.

---

## License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

# CREDIT

<https://github.com/evilsocket/pwnagotchi> - For the original pwnagothi project
<br>
<https://github.com/viniciusbo/m5-palnagotchi> - For inspiration and pwngrid support for cardputer

---

## Contributing

Contributions, issue reports, and pull requests are welcome!
To help out, fork this repo, before opening a PR run pre_commit.sh (don't worry its safe) and finally open a PR.

---

## Contact

Join our Discord community for support, discussion, and sneak peeks at upcoming features.

<https://discord.gg/2TZFcndkhB>

---
