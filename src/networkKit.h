#include "WiFi.h"

// External ESP32 Wi-Fi related C functions for channel and transmission
extern "C" {
#include "esp_wifi.h"
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
}

// Function declaration for broadcasting fake SSIDs
void broadcastFakeSSIDs(String ssidList[], int ssidCount, bool sound);
