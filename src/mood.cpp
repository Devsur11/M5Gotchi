#include "mood.h"

// ASCII equivalent
const String palnagotchi_moods[] = {
    "(v__v)",  // 0 - sleeping
    "(=__=)",  // 1 - awakening
    "(O__O)",  // 2 - awake
    "( O_O)",  // 3 - observing (neutral) right
    "(O_O )",  // 4 - observig (neutral) left
    "( 0_0)",  // 5 - observing (happy) right
    "(0_0 )",  // 6 - observing (happy) left
    "(+__+)",  // 7 - intense
    "(-@_@)",  // 8 - cool
    "(0__0)",  // 9 - happy
    "(^__^)",  // 10 - grateful
    "(a__a)",  // 11 - excited
    "(+__+)",  // 12 - smart
    "(*__*)",  // 13 - friendly
    "(@__@)",  // 14 - motivated
    "(>__<)",  // 15 - demotivated
    "(-__-)",  // 16 - bored
    "(T_T )",  // 17 - sad
    "(;__;)",  // 18 - lonely
    "(X__X)",  // 19 - broken
    "(#__#)",  // 20 - debugging,
    "9====9",  // 21 - ultra random easter egg
};

const String palnagotchi_moods_desc[] = {
    "Zzzz...          ",                     // 0 - sleeping
    "...              ",                     // 1 - awakening
    "Ready for action!",                     // 2 - awake
    "Hello there!     ",                     // 3 - observing (neutral) right
    "I see you :)     ",                     // 4 - observig (neutral) left
    "Wanna meet?      ",                     // 5 - observing (happy) right
    "Oh, hello        ",                     // 6 - observing (happy) left
    "Working...       ",                     // 7 - intense
    "I am so cool!    ",                     // 8 - cool
    "I like this      ",                     // 9 - happy
    "I LOVE PWNAGOTCHI",                     // 10 - grateful
    "So much to explore",                    // 11 - excited
    "3.1415926535897932",                    // 12 - smart
    "HEY YOU! LETS BE FRIENDS!",             // 13 - friendly
    "IT RUNS!          ",                    // 14 - motivated
    "Why my life sucks?",                    // 15 - demotivated
    "Let's go for a walk!",                  // 16 - bored
    "Get your hands off me",                 // 17 - sad
    "Lonely, I am so lonely",                // 18 - lonely
    "It works on my end.",                   // 19 - broken
    "I didn't even touch it...",             // 20 - debugging,
    "What?",                                 // 21 - ultra random easter egg
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
    current_face = palnagotchi_moods[current_mood];
  }

  if (phrase != "") {
    current_phrase = phrase;
  } else {
    current_phrase = palnagotchi_moods_desc[current_mood];
  }
}
