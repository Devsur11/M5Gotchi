namespace n_pwnagotchi{
    bool begin();
    bool end();
}
void attackTask(void* parameter);
void task(void* parameter);

// File write queue management for SD operations
struct FileWriteRequest;
extern QueueHandle_t fileWriteQueue;
void handleFileWrite(FileWriteRequest* req);
struct wifiRTResults{
    String ssid;
    int rssi;
    int channel;
    bool secure;
    uint8_t bssid[6];
    long lastSeen;
};
extern std::vector<wifiRTResults> g_wifiRTResults;
extern wifiRTResults ap; //network being currently attacked
extern TaskHandle_t pwnagotchiTaskHandle;