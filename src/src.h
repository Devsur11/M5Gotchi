void Sound(int frequency, int duration, bool sound);
void updateActivity(bool reward);
void setup();
void loop();
#ifdef ENABLE_COREDUMP_LOGGING
void connectMQTT();
void sendCoredump();
#endif