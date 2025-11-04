#include "mood.h"

// ASCII equivalent
struct splash {
    String face;
    String splash;
};


splash mainFaces[] = {
  {"(v__v)", "Zzzz...."},
  {"(=__=)", "..."},
  {"(-__-)", "Let's go for a walk! Pwning will do us good!"},
  {"(T_T )", "Anyone?! Please?!"},
  {"(;__;)", "Why did you left me?"},
  {"(>__<)", "Why my life sucks?!"},
  {"(.__.)", "Why did you left me?"},
  {"(+__+)", "Working... Please hold..."},
  {"(@__@)", "file pwnagothi.cpp has stopped working"},
  {"(@__@)", "Too much 0s and 1s to understand"},
  {"(@__@)", "I PWN! Suck my balz!"},
  {"(#__#)", "WTF! I didn't even touch it!"},
  {"(O_O )", "I see you :) What password are you hiding?"},
  {"(0_0 )", "Oh, hello, don't hide! I'm just curious!"},
  {"(o__o)", "Let's see what you got for me!"},
  {"(o__o)", "Don't mind me, I'm just looking around"},
  {"( O_O)", "Hello there, wanna show me something hidden?"},
  {"( 0_0)", "Wanna meet? I've got some packets to share!"},
  {"(a__a)", "So much to PWN!"},
  {"(^__^)", "I LOVE PWNAGOTCHI!"},
  {"(*__*)", "Hell yeah!"},
  {"(0__0)", "I'm hungry for handshakes!"},
  {"(-@_@)", "So many possibilities to pwn!!"},
  {"(O__O)", "Ready for action!"},
  {"(O__O)", "It's snapshot day my dudes"},
  {"(O__O)", "Welcome to another day of using my system!"},
  {"(X__X)", "It works on my end. On your it don't need to :)"},
};

uint8_t current_mood = 0;
String current_phrase = "";
String part2 = "";
String current_face = "";
bool current_broken = false;

String getCurrentMoodFace() { return current_face; }
String getCurrentMoodPhrase() { return current_phrase; }

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
