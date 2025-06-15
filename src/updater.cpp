#include "updater.h"
#include "ui.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>
#include <ESPAsyncWebServer.h>
#include <Update.h>

AsyncWebServer updateServer(80);

// Strona HTML do przesyłania pliku
const char* upload_form = R"(
  <html>
    <body>
      <center><h1>M5Blaster WIFI update</h1>
      <form method='POST' action='/update' enctype='multipart/form-data'>
        <input type='file' name='firmware'>
        <input type='submit' value='Update! '>
      </form>
    </body>
  </html>
)";

// Funkcja obsługująca stronę główną (formularz)
void handleRoot(AsyncWebServerRequest *request) {
  request->send(200, "text/html", upload_form);
}

// Funkcja obsługująca przesyłanie pliku
void handleUpdate(AsyncWebServerRequest *request, 
                  const String& filename, 
                  size_t index, 
                  uint8_t *data, 
                  size_t len, 
                  bool final) {
  if (index == 0) {
    drawInfoBox("Uploading...", "Please wait...", "", false, false);
    if (!Update.begin()) {  // Inicjalizacja aktualizacji OTA
      drawInfoBox("Init error", "Error with initialization", "Please contact developer.", true, false);
      request->send(500, "text/plain", "Init error");
      return;
    }
  }

  // Zapis przesyłanych danych do pamięci
  if (Update.write(data, len) != len) {
    drawInfoBox("Write error", "Error writing file", "to device", true, false);
    request->send(500, "text/plain", "Write error");
    return;
  }

  if (final) {
    if (Update.end(true)) {  // Zakończenie aktualizacji
      drawInfoBox("All done!", "Please reboot device", "", false, false);
      request->send(200, "text/html", "<center>Update successful, please reboot device");
      while (true) {} // Czekanie na restart
    } else {
      drawInfoBox("Update failed", "Unknown error", "", true, false);
      request->send(500, "text/html", "<center>Update failed...");
    }
  }
}

// Funkcja obsługująca nieprawidłowe żądania
void handleNotFound(AsyncWebServerRequest *request) {
  request->send(404, "text/plain", "<center>404 Not Found.");
}

void updateFromHTML() {
  if (WiFi.status() == WL_CONNECTED) {
    updateServer.on("/", HTTP_GET, handleRoot);  // Strona główna

    // Funkcja obsługująca aktualizację
    updateServer.on(
      "/update", HTTP_POST, [](AsyncWebServerRequest *request) {}, 
      [](AsyncWebServerRequest *request, const String& filename, size_t index, uint8_t *data, size_t len, bool final) {
        handleUpdate(request, filename, index, data, len, final);
      }
    );

    updateServer.onNotFound(handleNotFound);  // Obsługa nieznanych stron

    // Uruchomienie serwera
    updateServer.begin();

    while (true) {
      drawInfoBox("Ready", "Please send update to", WiFi.localIP().toString(), false, true);
      delay(1000);  // Zamiast handleClient(), robimy delay w pętli (serwer działa asynchronicznie)
    }
  } else {
    drawInfoBox("Error", "No WIFI connected", "Please connect to it first", true, false);
  }
}

SPIClass sd1SPI(FSPI);  // FSPI bus is typically used on ESP32-S3

void updateFromSd(){
  uint8_t cardType;
  // You can uncomment this and build again
  // logMessage("Update successfull");
  sd1SPI.begin(SD_SCK, SD_MISO, SD_MOSI, SD_CS);
  //first init and check SD card
  if (!SD.begin(SD_CS, sd1SPI, 1000000)) {
     drawInfoBox("ERROR", "SD card not found","",  true, true);
     return;
     //rebootEspWithReason("Card Mount Failed");
  }
  cardType = SD.cardType();
  if (cardType == CARD_NONE) {
     rebootEspWithReason("No SD_MMC card attached");
  }
  else{
    if(drawQuestionBox("Are you sure?", "Are want to update?", "This can not be undone!")){
      updateFromFS(SD);
      }
    else{return;}
  }
}
void performUpdate(Stream &updateSource, size_t updateSize) {
   if (Update.begin(updateSize)) {      
      size_t written = Update.writeStream(updateSource);
      if (written == updateSize) {
         logMessage("Written : " + String(written) + " successfully");
      }
      else {
         logMessage("Written only : " + String(written) + "/" + String(updateSize) + ". Retry?");
      }
      if (Update.end()) {
         logMessage("OTA done!");
         if (Update.isFinished()) {
            logMessage("Update successfully completed. Rebooting.");
            
            drawInfoBox("Info", "Update succesful, ","please reset device", false, false);
            while(true){}

         }
         else {
            logMessage("Update not finished? Something went wrong!");
            drawInfoBox("Error!", "Update failed. ", "system may be corrupt", false, true);
         }
      }
      else {
         drawInfoBox("Error", " Error #: " + String(Update.getError()), "" , false, true);
      }

   }
   else
   {
      logMessage("Not enough space to begin OTA");
   }
}

// check given FS for valid update.bin and perform update if available
void updateFromFS(fs::FS &fs) {
   File updateBin = fs.open("/update.bin");
   if (updateBin) {
      if(updateBin.isDirectory()){
         logMessage("Error, update.bin is not a file");
	      drawInfoBox("Error!", "update.bin is a", "directory", true, false);
         updateBin.close();
         return;
      }

      size_t updateSize = updateBin.size();

      if (updateSize > 0) {
	drawInfoBox("Updating..." , "", "", false, false);
         logMessage("Try to start update");
         performUpdate(updateBin, updateSize);
      }
      else {
	drawInfoBox("Error", "File is empty" , "", true , false);
         logMessage("Error, file is empty");
      }

      updateBin.close();
      // whe finished remove the binary from sd card to indicate end of the process
      // fs.remove("/update.bin");
   }
   else {
      logMessage("Could not load update.bin from sd root");
      drawInfoBox("ERROR", "update.bin not found", "", true, false);
   }
}

void rebootEspWithReason(String reason){
    logMessage(reason);
    delay(1000);
    ESP.restart();
}