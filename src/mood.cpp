#include "mood.h"

// ASCII equivalent
struct splash {
    String face;
    String splash;
};

splash mainFaces[] = {
  {"(v__v)", "Zzzz.... Just debugging my dreams!"},
  {"(O__O)", "Ready for action! Let's dive into the adventure!"},
  {"( O_O)", "Hello there, wanna explore? I promise it'll be fun!"},
  {"(O_O )", "I see you :) What secrets are you hiding?"},
  {"( 0_0)", "Wanna meet? I've got some interesting things to share!"},
  {"(0_0 )", "Oh, hello, don't hide! I'm just curious!"},
  {"(=__=)", "..."},
  {"(+__+)", "Working... Please hold while I conjure some magic!"},
  {"(-@_@)", "So many possibilities!! What should we tackle first?"},
  {"(0__0)", "Give me more of that! I'm hungry for knowledge!"},
  {"(^__^)", "I LOVE PWNAGOTCHI! Let's make some memories!"},
  {"(a__a)", "So much to explore! Where should we start?"},
  {"(*__*)", "Hell yeah! This is going to be epic!"},
  {"(@__@)", "IT RUNS! Suck my balz! Just kidding, let's celebrate!"},
  {"(>__<)", "Why my life sucks? Let's turn that frown upside down!"},
  {"(-__-)", "Let's go for a walk! Fresh air will do us good!"},
  {"(T_T )", "Anyone???! Please?! I'm feeling a bit lonely here..."},
  {"(;__;)","Lonely, I am so lonely... Can someone keep me company?"},
  {"(X__X)", "It works on my end. On your it don't need to :)"},
  {"(#__#)", "WTF! I didn't even touch it! What just happened?"},
  {"(o__o)", "Agent 007 ready for action!"},
  {"(o__o)", "Don't mind me, I'm just lurking around"},
  {"(.__.)", "Why did you left me?"},
  {"(@__@)", "file mood.cpp has stopped working"},
  {"(✞__✞)", "Blue Screen of Death incoming..."},
  {"(@__@)", "Too much 0s and 1s to understand"},
  {"(O__O)", "It's snapshot day my dudes"},
  {"(O__O)", "Welcome to another day of using my system!"},
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
