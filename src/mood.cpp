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
  {"(o__o)", "Agent 007 ready for action!"},
  {"(0__0)", "Watching your every move" },
  {"(^__^)", "Lights out and away we go!" },
  {"(>__<)", "Give me your attention!" },
  {"(ಠ__ಠ)", "Get back to work!" },//broken
  {"(o__o)", "Don't mind me, I'm just lurking around" },
  {"(.__.)", "Why did you left me?" },
  {"(@__@)", "file mood.cpp has stopped working" },
  {"(✞__✞)", "Blue Screen of Death incoming..." },//broken
  {"(@__@)", "Too much 0s and 1s to understand" }, //(˶˃⤙˂˶)(｡>﹏<)
  {"(≧ヮ≦)", "I'm so happy to see you!" },//broken
  {"(˶˃⤙˂˶)", "It's taking you so long!" },//broken
  {"(O__O)", "It's snapshot day my dudes" },
  {"(O__O)", "Welcome to another day of using my system!" }, //(⸝⸝ᵕᴗᵕ⸝⸝)
  {"(⸝⸝ᵕᴗᵕ⸝⸝)", "Such a nice day for having fun!" }, //ᕙ(⇀‸↼‶)ᕗ //broken , uncentered
  {"(⇀‸↼‶)", "You dare waking me up mortal?" }, //(｡•́︿•̀｡)(╥﹏╥) //broken
  {"(╥﹏╥)", "Come back to me! Please!" }, //♡✧( •⌄• ), //broken
  {"( •⌄• )", "I just don't know what went wrong!" } ,//broken
  {"( ・ω・)", "Hey! You dropped this: ';' You can thank me later" }, //broken
  {"(⌒▽⌒)", "Don't mind me, just swapping your semicolon with greek question mark" }, //broken
  {"(◉__◉)", "Incoming task: touch grass" },//broken
  {"(►__◄)", "YOU FORGOT YOUR SEMICOLON YOU IDIOT" },//broken
  {"(≧ヮ≦)", "meow" },//broken
  {"╯‵Д′)╯彡┻━┻", "Jokes on you, your table have been flipped" } ,//broken, uncentered
  {"(v__v)", "Zzzz.... I'm just taking a quick nap, but I'll be back soon!" },
  {"(=__=)", "..." },
  {"(O__O)", "Ready for action! Let's dive into the adventure!" },
  {"( O_O)", "Hello there, wanna explore? I promise it'll be fun!" },
  {"(O_O )", "I see you :) What secrets are you hiding?" },
  {"( 0_0)", "Wanna meet? I've got some interesting things to share!" },
  {"(0_0 )", "Oh, hello, don't hide! I'm just curious!" },
  {"(+__+)", "Working... Please hold while I conjure some magic!" },
  {"(-@_@)", "So many possibilities!! What should we tackle first?" },
  {"(0__0)", "Give me more of that! I'm hungry for knowledge!" },
  {"(^__^)", "I LOVE PWNAGOTCHI! Let's make some memories!" },
  {"(a__a)", "So much to explore! Where should we start?" },
  {"(+__+)", "Fixing bugs... Just a moment while I work my magic!" },
  {"(*__*)", "Hell yeah! This is going to be epic!" },
  {"(@__@)", "IT RUNS! Suck my balz! Just kidding, let's celebrate!" },
  {"(>__<)", "Why my life sucks? Let's turn that frown upside down!" },
  {"(-__-)", "Let's go for a walk! Fresh air will do us good!" },
  {"(T_T )", "Anyone???! Please?! I'm feeling a bit lonely here..." },
  {"(;__;)", "Lonely, I am so lonely... Can someone keep me company?" },
  {"(X__X)", "It works on my end. On your it don't need to :). Let's troubleshoot!" },
  {"(#__#)", "WTF! I didn't even touch it! What just happened?" },
  {"(✧__✧)", "Wow! Look at all the possibilities!" },//broken
  {"(≧◡≦)", "Yay! I'm so excited to be here!" },//broken
  {"(•̀ᴗ•́)", "Ready to tackle the day! Let's do this!" },//broken
  {"(⊙_☉)", "What just happened? I'm intrigued!" },//broken
  {"(￣▽￣)", "Just chilling, waiting for some action!" },//broken
  {"(╯°□°）╯︵ ┻━┻", "Oops! I flipped the table again!" },//broken uncentered
  {"(✿◠‿◠)", "Hello, friend! Let's spread some positivity!" },//broken
  {"(¬‿¬)", "I see what you're up to... Care to share?" },//broken
  {"(✧ω✧)", "Adventure time! Where are we headed?" },//broken
  {"(╥ω╥)", "Feeling a bit down... Can someone cheer me up?" },//broken
  {"(≧▽≦)", "Let's celebrate! Good vibes only!" },//broken
  {"(￣︿￣)", "Hmm... Something feels off today." },//broken
  {"(✧ω✧)", "I'm all ears! What do you want to talk about?" },//broken
  {"(⊙_☉)", "Surprise! I didn't see that coming!" },//broken
  {"(╯✧▽✧)╯", "Let's flip the script and have some fun!" },//broken
  {"(•̀ᴗ•́)", "Onward and upward! Let's make progress!" },//broken
  {"(✿´‿`)", "Just here to spread some love and joy!" },//broken
  {"(╯°□°）╯︵ ┻━┻", "Table flipping mode activated! Just kidding!" },//broken uncentered
  {"(≧◡≦)", "I'm ready to rock! What's the plan?" },//broken
  {"(•̀ᴗ•́)", "Let's get this party started!" },//broken
  {"(✧ω✧)", "I'm buzzing with excitement! What's next?" },//broken
  {"(⊙_☉)", "Did you see that? I need to know more!" },//broken
  {"(￣▽￣)", "Just another day in paradise!" },//broken
  {"(╥ω╥)", "Feeling a bit lost... Can you help me find my way?" },//broken
  {"(≧▽≦)", "Let's make some magic happen!" },//broken
  {"(✿◠‿◠)", "So happy to see you! What's on your mind?" },//broken
  {"(¬‿¬)", "I have a feeling something interesting is about to happen!" },//broken
  {"(✧ω✧)", "Adventure awaits! Let's dive in!" },//broken
  {"(⊙_☉)", "What's going on? I'm all ears!" },//broken
  {"(•̀ᴗ•́)", "Let's tackle this challenge together!" },//broken
  {"(≧◡≦)", "I'm here and ready to shine!" },//broken
  {"(✿´‿`)", "Let's spread some kindness today!" },//broken
  {"(v__v)", "Zzzz.... Just debugging my dreams!" },
  {"(=__=)", "Compiling... Please wait." },
  {"(O_O )", "I see you debugging! Need a hand?" },
  {"(0_0 )", "Oh, hello, don't hide! I promise I won't break your code!" },
  {"(+__+)", "Working... Just fixing some bugs in the matrix!" },
  {"(-@_@)", "So many possibilities!! Which algorithm should we use?" }
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
