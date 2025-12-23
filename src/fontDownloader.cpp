#include <WiFi.h>
#include <HTTPClient.h>
#include <SD.h>
#include <FS.h>
#include "fontDownloader.h"
#include "M5GFX.h"
#include "M5Cardputer.h"

const char* GITHUB_URL1 = "https://devsur11.github.io/M5Gotchi/fonts/big.vlw";
const char* GITHUB_URL2 = "https://devsur11.github.io/M5Gotchi/fonts/small.vlw";
const char* FONTS_FOLDER = "/fonts";
const char* VLW_EXTENSION = ".vlw";
extern const char github_root_cert_pem_start[] asm("_binary_certs_github_root_cert_pem_start");

bool fileExists(const char* path) {
    File file = SD.open(path);
    bool exists = file;
    if (file) file.close();
    return exists;
}

bool downloadFile(const char* url, const char* localPath) {
    if (fileExists(localPath)) {
        fLogMessage("File already exists: %s\n", localPath);
        return true;
    }

    HTTPClient http;
    http.begin(url, github_root_cert_pem_start);
    int httpCode = http.GET();

    if (httpCode != HTTP_CODE_OK) {
        fLogMessage("Failed to download from %s (code: %d)\n", url, httpCode);
        http.end();
        return false;
    }

    File file = SD.open(localPath, FILE_WRITE);
    if (!file) {
        fLogMessage("Failed to create file: %s\n", localPath);
        http.end();
        return false;
    }

    WiFiClient* stream = http.getStreamPtr();
    uint8_t buf[1024];
    size_t total = 0;
    size_t contentLength = http.getSize();

    while (http.connected() && (contentLength <= 0 || total < contentLength)) {
        size_t available = stream->available();
        if (available) {
            int readBytes = stream->readBytes(buf, min(available, sizeof(buf)));
            file.write(buf, readBytes);
            total += readBytes;
            
            // Display progress overlay
            if (contentLength > 0) {
                int progress = (total * 100) / contentLength;
                M5.Display.fillRect(0, 0, M5.Display.width(), 40, TFT_BLACK);
                M5.Display.setTextColor(TFT_WHITE);
                M5.Display.drawString("Downloading...", 10, 10);
                M5.Display.drawString(String(progress) + "%", M5.Display.width() - 50, 10);
                M5.Display.fillRect(10, 25, (M5.Display.width() - 20) * progress / 100, 10, TFT_GREEN);
            }
        }
        delay(1);
    }
    file.close();
    http.end();

    fLogMessage("Downloaded: %s (%u bytes)\n", localPath, total);
    return true;
}

void downloadFonts() {
    if (!SD.begin()) {
        logMessage("SD card initialization failed");
        return;
    }

    if (!SD.exists(FONTS_FOLDER)) {
        SD.mkdir(FONTS_FOLDER);
        logMessage("Created fonts folder");
    }

    downloadFile(GITHUB_URL1, (String(FONTS_FOLDER) + String("/big") + VLW_EXTENSION).c_str());
    downloadFile(GITHUB_URL2, (String(FONTS_FOLDER) + "/small" + VLW_EXTENSION).c_str());

    logMessage("Font download complete");
}