#include "mood.h"

// ASCII equivalent
struct splash {
  String face;
  String splash;
};

splash mainFaces[] = {
  {"(v__v)", "Zzzz...          "},
  {"(=__=)", "...              "},
  {"(O__O)", "Ready for action!"},
  {"( O_O)", "Hello there!     "},
  {"(O_O )", "I see you :)     "},
  {"( 0_0)", "Wanna meet?      "},
  {"(0_0 )", "Oh, hello        "},
  {"(+__+)", "Working...       "},
  {"(-@_@)", "I am so cool!    "},
  {"(0__0)", "I like this      "},
  {"(^__^)", "I LOVE PWNAGOTCHI"},
  {"(a__a)", "So much to explore"},
  {"(+__+)", "Hacking NASA...  "},
  {"(*__*)", "LETS BE FRIENDS! "},
  {"(@__@)", "IT RUNS!         "},
  {"(>__<)", "Why my life sucks?"},
  {"(-__-)", "Let's go for a walk!"},
  {"(T_T )", "Get your hands off me"},
  {"(;__;)", "I am so lonely..."},
  {"(X__X)", "It works with me."},
  {"(#__#)", "I didn't touch it"},
};

uint8_t current_mood = 0;
String current_phrase = "";
String current_face = "";
bool current_broken = false;

uint8_t getCurrentMoodId() { return current_mood; }
String getCurrentMoodFace() { return current_face; }
String getCurrentMoodPhrase() { return current_phrase; }
bool isCurrentMoodBroken() { return current_broken; }

void setMood(uint8_t mood, String face, String phrase, bool broken) {
  current_mood = mood;
  current_broken = broken;

  if (face != "") {
    current_face = face;
  } else {
    current_face = mainFaces[current_mood].face;
  }

  if (phrase != "") {
    current_phrase = phrase;
  } else {
    current_phrase = mainFaces[current_mood].splash;
  }
}
/* rewrite this whole section

add "activity" variable for activity level & displaying moods
merge mood and phrase to 1 wariable with struct() 
rewrite enterelly :
uint8_t getCurrentMoodId() { return current_mood; }
String getCurrentMoodFace() { return current_face; }
String getCurrentMoodPhrase() { return current_phrase; }
bool isCurrentMoodBroken() { return current_broken; }
amen */