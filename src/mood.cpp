#include "mood.h"

// ASCII equivalent
struct splash {
    String face;
    String splash;
};

struct pwnagothiMood {
  String Face;
  String spashPart1;
  String splashPart2;
};

splash mainFaces[] = {
  {"(v__v)", "Zzzz.... Just debugging my dreams!"},
  {"(=__=)", "..."},
  {"(-__-)", "Let's go for a walk! Fresh air will do us good!"},
  {"(T_T )", "Anyone?! Please?! I'm feeling a bit lonely here..."},
  {"(;__;)","Lonely, I am so lonely... Can someone keep me company?"},
  {"(>__<)", "Why my life sucks? Let's turn that frown upside down!"},
  {"(.__.)", "Why did you left me?"},
  {"(+__+)", "Working... Please hold while I conjure some magic!"},
  {"(@__@)", "file pwnagothi.cpp has stopped working"},
  {"(@__@)", "Too much 0s and 1s to understand"},
  {"(@__@)", "IT RUNS! Suck my balz! Just kidding, let's celebrate!"},
  {"(#__#)", "WTF! I didn't even touch it! What just happened?"},
  {"(O_O )", "I see you :) What secrets are you hiding?"},
  {"(0_0 )", "Oh, hello, don't hide! I'm just curious!"},
  {"(o__o)", "Let's see what you got for me!"},
  {"(o__o)", "Don't mind me, I'm just lurking around"},
  {"( O_O)", "Hello there, wanna explore? I promise it'll be fun!"},
  {"( 0_0)", "Wanna meet? I've got some interesting things to share!"},
  {"(a__a)", "So much to explore! Where should we start?"},
  {"(^__^)", "I LOVE PWNAGOTCHI! Let's make some memories!"},
  {"(*__*)", "Hell yeah! This is going to be epic!"},
  {"(0__0)", "Give me more of that! I'm hungry for knowledge!"},
  {"(-@_@)", "So many possibilities!! What should we tackle first?"},
  {"(O__O)", "Ready for action! Let's dive into the adventure!"},
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
    //part2 = mainFaces[current_mood].part2;
  }
}
