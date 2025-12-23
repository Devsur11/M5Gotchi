void Sound(int frequency, int duration, bool sound);
void setup();
void loop();
void fontSetup();
#ifdef ENABLE_COREDUMP_LOGGING
void connectMQTT();
void sendCoredump();
#endif