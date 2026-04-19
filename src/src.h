void Sound(int frequency, int duration, bool sound);
void setup();
void loop();
void fontSetup();
extern bool setupDone;
#ifdef ENABLE_COREDUMP_LOGGING
void connectMQTT();
bool sendCoredump();
#endif