#include "ArduinoJson.h"
#include "M5Cardputer.h"
#include "M5Unified.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "logger.h"
#include "settings.h"

#ifndef PWNGRID_H
#define PWNGRID_H
typedef struct {
  int epoch;
  String face;
  String grid_version;
  String identity;
  String name;
  int pwnd_run;
  int pwnd_tot;
  String session_id;
  int timestamp;
  int uptime;
  String version;
  signed int rssi;
  int last_ping;
  bool gone;
} pwngrid_peer;

void initPwngrid();
esp_err_t pwngridAdvertise(uint8_t channel, String face);
pwngrid_peer* getPwngridPeers();
uint8_t getPwngridTotalPeers();
String getPwngridLastFriendName();
void checkPwngridGoneFriends();
String getLastPeerFace();
uint16_t getPwngridLastPwnedAmount();
uint16_t getPwngridLastSessionPwnedAmount();
#endif