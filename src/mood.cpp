#include "mood.h"
#include "settings.h"
#include "pwngrid.h"
#include "logger.h"
#include <SD.h>
#include <map>
#include <vector>
#include <cstdarg>

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
  "Hi, I'm M5Gotchi! \nStarting ...",
  "New day, new hunt, new pwns! \nStarting ...",
  "I pwn therefore I am. \nStarting ...",
  "My crime is that of curiosity ... \nStarting ...",
  "Hack the Planet! \nStarting ..."
};

uint8_t current_mood = 0;
String current_phrase = "";
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

  String details = "";
  details += "faces sections=" + String(facesMap.size());
  details += ", texts sections=" + String(textsMap.size());
  logMessage(String("Mood files loaded: faces=") + (okFaces?"ok":"fail") + ", texts=" + (okTexts?"ok":"fail") + "; " + details);
  return okFaces && okTexts;
}

bool initedMoods = false;

static String vformat(const char* fmt, ...) {
  char buf[128];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  return String(buf);
}

static String pickFace(const char* section, const char** fallback, size_t fallbackCount) {
  if (initedMoods) {
    auto it = facesMap.find(String(section));
    if (it != facesMap.end() && !it->second.empty()) {
      auto &v = it->second;
      return v[random(0, v.size())];
    }
  }
  return String(fallback[random(0, fallbackCount)]);
}

static String pickText(const char* section, const char** fallback, size_t fallbackCount) {
  if (initedMoods) {
    auto it = textsMap.find(String(section));
    if (it != textsMap.end() && !it->second.empty()) {
      auto &v = it->second;
      return v[random(0, v.size())];
    }
  }
  return String(fallback[random(0, fallbackCount)]);
}

static const char* getTextOrDefault(const char* section, size_t index, const char** fallback, size_t fallbackCount) {
  if (initedMoods) {
    auto it = textsMap.find(String(section));
    if (it != textsMap.end() && it->second.size() > index) {
      return it->second[index].c_str();
    }
  }
  return (index < fallbackCount) ? fallback[index] : "";
}

void debugPrintMoods() {
  logMessage("Faces Map:");
  for (auto &pair : facesMap) {
    String line = " [" + pair.first + "]: ";
    for (auto &val : pair.second) {
      line += "\"" + val + "\", ";
    }
    logMessage(line);
  }

  logMessage("Texts Map:");
  for (auto &pair : textsMap) {
    String line = " [" + pair.first + "]: ";
    for (auto &val : pair.second) {
      line += "\"" + val + "\", ";
    }
    logMessage(line);
  }
}

bool initMoodsFromSD() {
  // ensure files exist
  if (!SD.exists("/moods/faces.txt") || !SD.exists("/moods/texts.txt")) {
    createDefaultMoodFiles();
  }
  initedMoods = true;
  return reloadMoodFiles();
}

void setMood(uint8_t mood, String face, String phrase, bool broken) {
  current_mood = mood;
  current_broken = broken;

  if (face != "") {
    current_face = face;
  } 

  if (phrase != "") {
    current_phrase = phrase;
  }
}

void setMoodToStatus(){
  uint16_t sessionTimeMinutes = (lastSessionTime) / 60000;
  String out = vformat("I've been pwning for %d minutes and kicked %d clients! I've also met %d new peers and ate %d handshakes", sessionTimeMinutes, lastSessionDeauths, lastSessionPeers, lastSessionCaptures);
  setMood(0, pickFace("happy", happy, sizeof(happy)/sizeof(happy[0])), out, false);
} 

void setMoodToNewHandshake(uint8_t handshakes){
  String fmt = pickText("new_handshake", new_handshake, sizeof(new_handshake)/sizeof(new_handshake[0]));
  String out = vformat(fmt.c_str(), String(handshakes).c_str());
  setMood(4, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), out, false);
} 

void setMoodToDeauth(const String& ssid){
  String fmt = pickText("deauthing", deauthing, sizeof(deauthing)/sizeof(deauthing[0]));
  String out = vformat(fmt.c_str(), ssid.c_str());
  setMood(3, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), out, false);
} 

void setMoodToPeerNearby(const String& peerName){
  String fmt = pickText("peer_nearby", peer_nearby, sizeof(peer_nearby)/sizeof(peer_nearby[0]));
  String out = vformat(fmt.c_str(), peerName.c_str());
  setMood(0, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), out, false);
} 

void setMoodToAttackFailed(const String& targetName){
  String fmt = pickText("attack_failed", attack_failed, sizeof(attack_failed)/sizeof(attack_failed[0]));
  String out = vformat(fmt.c_str(), targetName.c_str());
  setMood(0, pickFace("sad", sad, sizeof(sad)/sizeof(sad[0])), out, false);
} 

void setMoodToStartup(){
  String fmt = pickText("startup", startup, sizeof(startup)/sizeof(startup[0]));
  String out = vformat(fmt.c_str());
  setMood(0, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), out, false);  
} 

void setMoodSad(){
  setMood(0, pickFace("sad", sad, sizeof(sad)/sizeof(sad[0])),
          pickText("sad", text_sad, sizeof(text_sad)/sizeof(text_sad[0])), false);
}

void setMoodHappy(){
  setMood(0, pickFace("happy", happy, sizeof(happy)/sizeof(happy[0])),
          pickText("happy", text_happy, sizeof(text_happy)/sizeof(text_happy[0])), false);
}

void setMoodBroken(){
  setMood(MOOD_BROKEN, "(#__#)", "System broken! Rebooting might help.", true);
}

void setMoodSleeping(){
  setMood(0, pickFace("sleeping", sleeping, sizeof(sleeping)/sizeof(sleeping[0])),
          "Zzzzz...", false);
}

void setMoodLooking(uint8_t durationSeconds){
  if(durationSeconds == 0){
    setMood(1, pickFace("looking", looking, sizeof(looking)/sizeof(looking[0])), String("Looking around..."), false);
    return;
  }
  if(durationSeconds < 60){
    const char* unit = getTextOrDefault("time_def", 1, time_def, sizeof(time_def)/sizeof(time_def[0]));
    String out = vformat("Looking around (%d %s)", durationSeconds, unit);
    setMood(1, pickFace("looking", looking, sizeof(looking)/sizeof(looking[0])), out, false);
    return;
  }
  int minutes = durationSeconds / 60;
  const char* unit = getTextOrDefault("time_def", 0, time_def, sizeof(time_def)/sizeof(time_def[0]));
  String out = vformat("Looking around (%d %s)", minutes, unit);
  setMood(1, pickFace("looking", looking, sizeof(looking)/sizeof(looking[0])), out, false);
} 

void setMoodApSelected(const String& ssid){
  String fmt = pickText("ap_selected", ap_selected, sizeof(ap_selected)/sizeof(ap_selected[0]));
  String out = vformat(fmt.c_str(), ssid.c_str());
  setMood(2, pickFace("happy", happy, sizeof(happy)/sizeof(happy[0])), out, false);
} 

void setNewMessageMood(uint8_t messages){
  String fmt;
  if (initedMoods) {
    auto it = textsMap.find("system_def");
    if (it != textsMap.end() && !it->second.empty()) fmt = it->second[0];
    else fmt = String(system_def[0]);
  } else {
    fmt = String(system_def[0]);
  }
  String out = vformat(fmt.c_str(), String(messages).c_str(), (messages==1?"":"s"));
  setMood(0, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), out, false);
} 

void setGeneratingKeysMood(){
  String txt;
  if (initedMoods) {
    auto it = textsMap.find("system_def");
    if (it != textsMap.end() && it->second.size() > 1) txt = it->second[1];
    else txt = String("Generating keys, do not turn off ...");
  } else {
    txt = String("Generating keys, do not turn off ...");
  }
  setMood(0, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])), txt, false);
} 

void setChannelFreeMood(uint8_t channel){
  String fmt;
  if (initedMoods) {
    auto it = textsMap.find("system_def");
    if (it != textsMap.end() && it->second.size() > 2) fmt = it->second[2];
    else fmt = String(system_def[2]);
  } else {
    fmt = String(system_def[2]);
  }
  String out = vformat(fmt.c_str(), String(channel).c_str());
  setMood(2, pickFace("happy", happy, sizeof(happy)/sizeof(happy[0])), out, false);
} 

void setIDLEMood(){
  int16_t balance = tot_happy_epochs - tot_sad_epochs;
  if(balance >= 5 && balance < 15){
    setMood(0, pickFace("happy", happy, sizeof(happy)/sizeof(happy[0])),
            "...", false);
  }
  else if(balance <= -5){
    setMood(0, pickFace("sad", sad, sizeof(sad)/sizeof(sad[0])),
            "...", false);
  }
  else if(balance >= 15){
    setMood(0, pickFace("excited", excited, sizeof(excited)/sizeof(excited[0])),
            "...", false);
  }
  else{
    setMood(0, pickFace("looking", looking, sizeof(looking)/sizeof(looking[0])),
            "...", false);
  }
}