# Moods on SD Card

This project now supports loading faces and text messages from the SD card. Files are stored under `/moods` on the SD card.

Files created/loaded:

- `/moods/faces.txt` — face strings organized in INI-like sections. Example:

  [sleeping]
  (⇀‿‿↼)
  (≖‿‿≖)

  [mainFaces]
  (⇀‿‿↼)
  (◕‿‿◕)

- `/moods/texts.txt` — text messages organized in INI-like sections. Example:

  [startup]
  Hi, I'm Pwnagotchi! Starting ...

  [mainFaces]
  (⇀‿‿↼)|Zzzz....
  (◕‿‿◕)|Let's go for a walk! Pwning will do us good!

Notes:
- When the device boots, it will ensure `/moods/faces.txt` and `/moods/texts.txt` exist (creating them with default content if missing) and then load them.
- The `mainFaces` section in `texts.txt` stores `face|phrase` pairs and is used to populate the runtime splash list.
- If parsing fails or sections are missing, the firmware falls back to built-in defaults.
- To reload updated files at runtime, call `reloadMoodFiles()` (exposed in `src/mood.h`).