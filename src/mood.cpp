#include "mood.h"
#include "settings.h"
#include "pwngrid.h"
#include "logger.h"
#include <SD.h>
#include <map>
#include <vector>

// ASCII equivalent
struct splash {
    String face;
    String splash;
};

const char* sleeping[] = {
  "(⇀‿‿↼)",
  "(≖‿‿≖)"
};

const char* looking[] = {
  "( ⚆_⚆)",
  "(☉_☉ )",
  "( ◕‿◕)",
  "(◕‿◕ )",
  "(◕‿‿◕)"
};

const char* happy[] = {
  "(•‿‿•)",
  "(^‿‿^)",
  "(ᵔ◡◡ᵔ)",
  "(☼‿‿☼)"
};

const char* sad[] = {
  "(╥☁╥ )",
  "(ب__ب)",
  "(☓‿‿☓)",
  "(-__-)",
  "(≖__≖)",
  "(-_-')"
};

const char* excited[] = {
  "(⌐■_■)",
  "(°▃▃°)",
  "(✜‿‿✜)",
  "(♥‿‿♥)",
  "(ᵔ◡◡ᵔ)"
};

const char* time_def[] = {
  "minutes",
  "seconds",
  "hour",
  "minute",
  "second"
};

const char* deauthing[] = {
  "Deauthenticating %s",
  "Kickbanning %s!",
  "Saying goodbye to %s",
  "Sending %s away",
  "Telling %s to leave",
  "Asking %s to disconnect",
  "Making %s go offline"
};

const char* peer_nearby[] = {
  "Unit %s is nearby!",
  "Found a new friend: %s",
  "Hello %s, wanna be friends?",
  "Hey %s, I see you!"
};

const char* system_def[] = {
  "You have %s new message%s!",
  "Generating keys, do not turn off ...",
  "Hey, channel %s is free! Your AP will say thanks.",
  "Looking around (%s s)"
};

const char* attack_failed[] = {
  "Uhm ... goodbye %s",
  "%s is gone ...",
  "Whoops ... %s is gone.",
  "%s missed!",
  "Missed!"
};

const char* new_handshake[] = {
  "Cool, we got %s new handshake!",
  "Yay! %s new handshake captured!",
  "Another one! %s new handshake!",
  "Pwned! %s new handshake!",
  "Sweet! %s new handshake added to the collection!",
  "Got %s new handshake, nice!"
};

const char* ap_selected[] = {
  "Hello %s! Nice to meet you.",
  "Yo %s! Sup?",
  "Hey %s how are you doing?",
  "Hey %s let's be friends!",
  "Yo %s!",
  "Just decided that %s needs no WiFi!"
};

const char* text_sad[] = {
  "Shitty day :/",
  "I'm extremely bored ...",
  "I'm very sad ...",
  "I'm sad",
  "Leave me alone ...",
  "I'm mad at you!",
  "I'm bored ...",
  "Nobody wants to play with me ...",
  "I feel so alone ...",
  "Where's everybody?!"
};

const char* text_happy[] = {
  "Let's go for a walk!",
  "This is the best day of my life!",
  "I'm living the life!",
  "So many networks!!!",
  "I'm having so much fun!",
  "Good friends are a blessing!",
  "I love my friends!"
};

const char* startup[] = {
  "Hi, I'm M5Gotchi! Starting ...",
  "New day, new hunt, new pwns! Starting ...",
  "I pwn therefore I am. Starting ...",
  "My crime is that of curiosity ...",
  "Hack the Planet! Starting ..."
};

// Default splash/face pairs (used to create defaults and fallback)
splash defaultMainFaces[] = {
  {"(⇀‿‿↼)", "Zzzz...."},
  {"(≖‿‿≖)", "..."},
  {"(◕‿‿◕)", "Let's go for a walk! Pwning will do us good!"},
  {"(╥☁╥ )", "Anyone?! Please?!"},
  {"(ب__ب)", "Why did you left me?"},
  {"(☓‿‿☓)", "Why my life sucks?!"},
  {"(ب__ب)", "Why did you left me?"},
  {"(✜‿‿✜)", "Working... Please hold..."},
  {"(#__#)", "file pwnagothi.cpp has stopped working"},
  {"(°▃▃°)", "Too much 0s and 1s to understand"},
  {"(ᵔ◡◡ᵔ)", "I PWN! Suck my balz!"},
  {"(#__#)", "WTF! I didn't even touch it!"},
  {"( ◕‿◕)", "I see you :) What password are you hiding?"},
  {"(◕‿◕ )", "Oh, hello, don't hide! I'm just curious!"},
  {"(•‿‿•)", "Let's see what you got for me!"},
  {"(◕‿‿◕)", "Don't mind me, I'm just looking around"},
  {"(☼‿‿☼)", "Hello there, wanna show me something hidden?"},
  {"(♥‿‿♥)", "Wanna meet? I've got some packets to share!"},
  {"(⌐■_■)", "So much to PWN!"},
  {"(^‿‿^)", "I LOVE PWNAGOTCHI!"},
  {"(⌐■_■)", "Hell yeah!"},
  {"(°▃▃°)", "I'm hungry for handshakes!"},
  {"(ᵔ◡◡ᵔ)", "So many possibilities to pwn!!"},
  {"(☼‿‿☼)", "Ready for action!"},
  {"(°▃▃°)", "It's snapshot day my dudes"},
  {"(^‿‿^)", "Welcome to another day of using my system!"},
  {"(☓‿‿☓)", "It works on my end. On your it don't need to :)"},
};

// Runtime main faces (populated from SD or fallback to defaults)
std::vector<splash> mainFaces;

uint8_t current_mood = 0;
String current_phrase = "";
String part2 = "";
String current_face = "";
bool current_broken = false;

String getCurrentMoodFace() { return current_face; }
String getCurrentMoodPhrase() { return current_phrase; }

// Runtime containers for faces and text categories
static std::map<String, std::vector<String>> facesMap;
static std::map<String, std::vector<String>> textsMap;

// Helper: write a file with given content
static bool writeTextFile(const String &path, const String &content) {
  File f = SD.open(path.c_str(), FILE_WRITE);
  if (!f) {
    logMessage("Failed to open " + path + " for writing");
    return false;
  }
  f.print(content);
  f.close();
  return true;
}

// Create default faces.txt and texts.txt under /moods
bool createDefaultMoodFiles() {
  if (!SD.exists("/moods")) {
    SD.mkdir("/moods");
  }

  // Faces
  String facesContent = "";
  auto addSection = [&](const char* name, const char** arr, size_t count){
    facesContent += "[" + String(name) + "]\n";
    for (size_t i=0;i<count;i++) {
      facesContent += String(arr[i]) + "\n";
    }
    facesContent += "\n";
  };

  addSection("sleeping", sleeping, sizeof(sleeping)/sizeof(sleeping[0]));
  addSection("looking", looking, sizeof(looking)/sizeof(looking[0]));
  addSection("happy", happy, sizeof(happy)/sizeof(happy[0]));
  addSection("sad", sad, sizeof(sad)/sizeof(sad[0]));
  addSection("excited", excited, sizeof(excited)/sizeof(excited[0]));

  // Also include faces used in main splash list
  facesContent += "[mainFaces]\n";
  for (auto &s : defaultMainFaces) {
    facesContent += s.face + "\n";
  }
  facesContent += "\n";

  bool ok1 = writeTextFile("/moods/faces.txt", facesContent);

  // Texts
  String textsContent = "";
  auto addSectionTxt = [&](const char* name, const char** arr, size_t count){
    textsContent += "[" + String(name) + "]\n";
    for (size_t i=0;i<count;i++) {
      textsContent += String(arr[i]) + "\n";
    }
    textsContent += "\n";
  };

  addSectionTxt("time_def", time_def, sizeof(time_def)/sizeof(time_def[0]));
  addSectionTxt("deauthing", deauthing, sizeof(deauthing)/sizeof(deauthing[0]));
  addSectionTxt("peer_nearby", peer_nearby, sizeof(peer_nearby)/sizeof(peer_nearby[0]));
  addSectionTxt("system_def", system_def, sizeof(system_def)/sizeof(system_def[0]));
  addSectionTxt("attack_failed", attack_failed, sizeof(attack_failed)/sizeof(attack_failed[0]));
  addSectionTxt("new_handshake", new_handshake, sizeof(new_handshake)/sizeof(new_handshake[0]));
  addSectionTxt("ap_selected", ap_selected, sizeof(ap_selected)/sizeof(ap_selected[0]));
  addSectionTxt("sad", text_sad, sizeof(text_sad)/sizeof(text_sad[0]));
  addSectionTxt("happy", text_happy, sizeof(text_happy)/sizeof(text_happy[0]));
  addSectionTxt("startup", startup, sizeof(startup)/sizeof(startup[0]));

  // // mainFaces: face|phrase
  // textsContent += "[mainFaces]\n";
  // for (auto &s : defaultMainFaces) {
  //   textsContent += s.face + "|" + s.splash + "\n";
  // }
  textsContent += "\n";

  bool ok2 = writeTextFile("/moods/texts.txt", textsContent);

  logMessage(String("Default mood files created: faces.txt=") + (ok1?"ok":"fail") + ", texts.txt=" + (ok2?"ok":"fail"));
  return ok1 && ok2;
}

// Parse simple INI-like file with [section] and lines
static bool parseSectionedFile(const String &path, std::map<String, std::vector<String>> &out) {
  File f = SD.open(path.c_str(), FILE_READ);
  if (!f) return false;
  String section = "";
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;
    if (line.startsWith("#")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.substring(1, line.length()-1);
      out[section] = std::vector<String>();
      continue;
    }
    if (section == "") continue; // ignore lines before first section
    out[section].push_back(line);
  }
  f.close();
  return true;
}

// Load mood files into runtime structures
bool reloadMoodFiles() {
  facesMap.clear();
  textsMap.clear();

  bool okFaces = parseSectionedFile("/moods/faces.txt", facesMap);
  bool okTexts = parseSectionedFile("/moods/texts.txt", textsMap);

  // Populate mainFaces vector from texts mainFaces section if present, otherwise fallback
  mainFaces.clear();
  if (okTexts && textsMap.count("mainFaces")) {
    for (auto &line : textsMap["mainFaces"]) {
      int sep = line.indexOf('|');
      if (sep > 0) {
        String face = line.substring(0, sep);
        String phrase = line.substring(sep+1);
        mainFaces.push_back({face, phrase});
      }
    }
  }

  if (mainFaces.empty()) {
    // fallback to defaults
    for (auto &s : defaultMainFaces) mainFaces.push_back(s);
  }

  String details = "";
  details += "faces sections=" + String(facesMap.size());
  details += ", texts sections=" + String(textsMap.size());
  details += ", main faces=" + String(mainFaces.size());
  logMessage(String("Mood files loaded: faces=") + (okFaces?"ok":"fail") + ", texts=" + (okTexts?"ok":"fail") + "; " + details);
  return okFaces && okTexts;
}

bool initMoodsFromSD() {
  // ensure files exist
  if (!SD.exists("/moods/faces.txt") || !SD.exists("/moods/texts.txt")) {
    createDefaultMoodFiles();
  }

  return reloadMoodFiles();
}

void setMood(uint8_t mood, String face, String phrase, bool broken) {
  current_mood = mood;
  current_broken = broken;

  if (face != "") {
    current_face = face;
  } else {
    // guard against out of range
    if (mainFaces.size() > current_mood) current_face = mainFaces[current_mood].face;
    else current_face = defaultMainFaces[current_mood % (sizeof(defaultMainFaces)/sizeof(defaultMainFaces[0]))].face;
  }

  if (phrase != "") {
    current_phrase = phrase;
  } else {
    if (mainFaces.size() > current_mood) current_phrase = mainFaces[current_mood].splash;
    else current_phrase = defaultMainFaces[current_mood % (sizeof(defaultMainFaces)/sizeof(defaultMainFaces[0]))].splash;
  }
}

void setMoodToStatus(){
  char* out;
  asprintf(&out, "I've been pwning for %d and kicked %d clients! I've also met %d new peers and ate %d handshake!", millis()/1000, sessionDeauths, getPwngridTotalPeers(), sessionCaptures);
  setMood(2, happy[random(0, sizeof(happy)/sizeof(happy[0]))], String(out), false);
  free(out);
}

void setMoodToNewHandshake(uint8_t handshakes){
  char* out;
  asprintf(&out, new_handshake[random(0, sizeof(new_handshake)/sizeof(new_handshake[0]))], String(handshakes).c_str());
  setMood(4, excited[random(0, sizeof(excited)/sizeof(excited[0]))], String(out), false);
  free(out);
}

void setMoodToDeauth(const String& ssid){
  char* out;
  asprintf(&out, deauthing[random(0, sizeof(deauthing)/sizeof(deauthing[0]))], ssid.c_str());
  setMood(3, sad[random(0, sizeof(sad)/sizeof(sad[0]))], String(out), false);
  free(out);
}

void setMoodToPeerNearby(const String& peerName){
  char* out;
  asprintf(&out, peer_nearby[random(0, sizeof(peer_nearby)/sizeof(peer_nearby[0]))], peerName.c_str());
  setMood(2, happy[random(0, sizeof(happy)/sizeof(happy[0]))], String(out), false);
  free(out);
}

void setMoodToAttackFailed(const String& targetName){
  char* out;
  asprintf(&out, attack_failed[random(0, sizeof(attack_failed)/sizeof(attack_failed[0]))], targetName.c_str());
  setMood(3, sad[random(0, sizeof(sad)/sizeof(sad[0]))], String(out), false);
  free(out);
}

void setMoodToStartup(){
  String phrase = startup[random(0, sizeof(startup)/sizeof(startup[0]))];
  setMood(1, looking[random(0, sizeof(looking)/sizeof(looking[0]))], phrase, false);
}

void setMoodSad(){
  setMood(3, sad[random(0, sizeof(sad)/sizeof(sad[0]))], text_sad[random(0, sizeof(text_sad)/sizeof(text_sad[0]))], false);
}

void setMoodHappy(){
  setMood(2, happy[random(0, sizeof(happy)/sizeof(happy[0]))], text_happy[random(0, sizeof(text_happy)/sizeof(text_happy[0]))], false);
}

void setMoodBroken(){
  setMood(MOOD_BROKEN, "(#__#)", "System broken! Rebooting might help.", true);
}

void setMoodSleeping(){
  setMood(0, sleeping[random(0, sizeof(sleeping)/sizeof(sleeping[0]))], "Zzzz....", false);
}

void setMoodLooking(uint8_t durationSeconds){
  char* out;
  asprintf(&out, system_def[3], durationSeconds);
  setMood(1, looking[random(0, sizeof(looking)/sizeof(looking[0]))], String(out), false);
  free(out);
}

void setMoodExcited(){
  setMood(4, excited[random(0, sizeof(excited)/sizeof(excited[0]))], "So much to pwn!", false);
}

void setMoodApSelected(const String& ssid){
  char* out;
  asprintf(&out, ap_selected[random(0, sizeof(ap_selected)/sizeof(ap_selected[0]))], ssid.c_str());
  setMood(2, happy[random(0, sizeof(happy)/sizeof(happy[0]))], String(out), false);
  free(out);
}

void setNewMessageMood(uint8_t messages){
  char* out;
  asprintf(&out, system_def[0], String(messages).c_str(), messages == 1 ? "" : "s");
  setMood(2, happy[random(0, sizeof(happy)/sizeof(happy[0]))], String(out), false);
  free(out);
}

void setGeneratingKeysMood(){
  setMood(4, excited[random(0, sizeof(excited)/sizeof(excited[0]))], "Generating keys, do not turn off ...", false);
}

void setChannelFreeMood(uint8_t channel){
  char* out;
  asprintf(&out, system_def[2], String(channel).c_str());
  setMood(4, excited[random(0, sizeof(excited)/sizeof(excited[0]))], String(out), false);
  free(out);
}
