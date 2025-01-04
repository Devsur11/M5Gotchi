#pragma once

struct MacEntry {
    uint8_t source[6];
    uint8_t destination[6];
};

// External ESP32 Wi-Fi related C functions for channel and transmission
extern "C" {
#include "esp_wifi.h"
  esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
  esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);
};

// Function declaration for broadcasting fake SSIDs
void broadcastFakeSSIDs(String ssidList[], int ssidCount, bool sound);
bool send_deauth_packets(String &client_mac, int count);
void deauth_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type);
bool is_client_known(uint8_t *mac);
void initClientSniffing();
void add_client(uint8_t *mac);
void get_clients_list(String client_list[], int &count);
void setMac(uint8_t new_mac[6]);
bool set_mac_address(uint8_t new_mac[6]);
bool convert_mac_string_to_bytes(const String &mac_str, uint8_t *mac_bytes);
void clearClients();
void set_target_channel(const char* target_ssid);
void client_sniff_promiscuous_rx_cb(void* buf, wifi_promiscuous_pkt_type_t type);
void add_mac_to_table(uint8_t *src, uint8_t *dest);
bool is_mac_in_table(uint8_t *src, uint8_t *dest);
void resetMacTable();
MacEntry* get_mac_table(int &count);