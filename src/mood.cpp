#include "mood.h"

// ASCII equivalent

splash mainFaces[] = {
  {"(v__v)", "Zzzz...." },
  {"(=__=)", "..." },
  {"(O__O)", "Ready for action!" },
  {"( O_O)", "Hello there, wanna explore?" },
  {"(O_O )", "I see you :)" },
  {"( 0_0)", "Wanna meet?" },
  {"(0_0 )", "Oh, hello, don't hide!" },
  {"(+__+)", "Working..." },
  {"(-@_@)", "So many posibilities!!" },
  {"(0__0)", "Give me more of that!" },
  {"(^__^)", "I LOVE PWNAGOTCHI" },
  {"(a__a)", "So much to explore" },
  {"(+__+)", "Fixing bugs..." },
  {"(*__*)", "Hell yeah" },
  {"(@__@)", "IT RUNS! Suck my balz!" },
  {"(>__<)", "Why my life sucks?" },
  {"(-__-)", "Let's go for a walk!"},
  {"(T_T )", "Anyone???! Please?!"},
  {"(;__;)", "Lonely, I am so lonely..."},
  {"(X__X)", "It works on my end. On your it don't need to :)."},
  {"(#__#)", "WTF! I didn't even touch it!"},
  {"(σ__σ)", "Agent 007 ready for action!"}
  {"(0__0)", "Watching your every move" },
  {"(^__^)", "Lights out and away we go!" },
  {"(>__<)", "Give me your attention!" },
  {"(ಠ__ಠ)", "Get back to work!" },
  {"(o__o)", "Don't mind me, I'm just lurking around" },
  {"(.__.)", "Why did you left me?" }
  {"(@__@)", "file mood.cpp has stopped working" }
  {"(✞__✞)", "Blue Screen of Death incoming..." }
  {"(@__@)", "Too much 0s and 1s to understand" } //(˶˃⤙˂˶)(｡>﹏<)
  {"(≧ヮ≦)", "I'm so happy to see you!" }
  {"(˶˃⤙˂˶)", "It's taking you so long!" }
  {"(O__O)", "It's snapshot day my dudes" }
  {"(O__O)", "Welcome to another day of using my system!" } //(⸝⸝ᵕᴗᵕ⸝⸝)
  {"(⸝⸝ᵕᴗᵕ⸝⸝)", "Such a nice day for having fun!" }
};

uint8_t current_mood = 0;
String current_phrase = "";
String part2 = "";
String current_face = "";
bool current_broken = false;

uint8_t getCurrentMoodId() { return current_mood; }
String getCurrentMoodFace() { return current_face; }
String getCurrentMoodPhrase() { return current_phrase; }
//String getCurrentMoodPart2() {return part2;}
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
    //part2 = mainFaces[current_mood].part2;
  }
}
