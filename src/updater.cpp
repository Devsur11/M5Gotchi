#include "updater.h"
#include "ui.h"
#include <Update.h>
#include <FS.h>
#include <SD.h>


void updateFromSd(){
  uint8_t cardType;

   // You can uncomment this and build again
   // Serial.println("Update successfull");

   //first init and check SD card
   if (!SD.begin()) {
      drawInfoBox("ERROR", "SD card not found","",  true, true);
      return;
      //rebootEspWithReason("Card Mount Failed");
   }

   cardType = SD.cardType();

   if (cardType == CARD_NONE) {
      rebootEspWithReason("No SD_MMC card attached");
   }else{
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
         Serial.println("Written : " + String(written) + " successfully");
      }
      else {
         Serial.println("Written only : " + String(written) + "/" + String(updateSize) + ". Retry?");
      }
      if (Update.end()) {
         Serial.println("OTA done!");
         if (Update.isFinished()) {
            Serial.println("Update successfully completed. Rebooting.");
            
            drawInfoBox("Info", "Update succesful, ","please reset device", false, false);

         }
         else {
            Serial.println("Update not finished? Something went wrong!");
            drawInfoBox("Error!", "Update failed. ", "system may be corrupt", false, true);
         }
      }
      else {
         drawInfoBox("Error", " Error #: " + String(Update.getError()), "" , false, true);
      }

   }
   else
   {
      Serial.println("Not enough space to begin OTA");
   }
}

// check given FS for valid update.bin and perform update if available
void updateFromFS(fs::FS &fs) {
   File updateBin = fs.open("/update.bin");
   if (updateBin) {
      if(updateBin.isDirectory()){
         Serial.println("Error, update.bin is not a file");
	      drawInfoBox("Error!", "update.bin is a", "directory", true, false);
         updateBin.close();
         return;
      }

      size_t updateSize = updateBin.size();

      if (updateSize > 0) {
	drawInfoBox("Updating..." , "", "", false, false);
         Serial.println("Try to start update");
         performUpdate(updateBin, updateSize);
      }
      else {
	drawInfoBox("Error", "File is empty" , "", true , false);
         Serial.println("Error, file is empty");
      }

      updateBin.close();
      // whe finished remove the binary from sd card to indicate end of the process
      // fs.remove("/update.bin");
   }
   else {
      Serial.println("Could not load update.bin from sd root");
      drawInfoBox("ERROR", "update.bin not found", "", true, false);
   }
}

void rebootEspWithReason(String reason){
    Serial.println(reason);
    delay(1000);
    ESP.restart();
}
