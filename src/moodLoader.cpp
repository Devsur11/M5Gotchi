#include "settings.h"
#include "moodLoader.h"
#include <JPEGDEC.h>
#include "SD.h"
#include <map>
#include "logger.h"


// image size: 240/40 px otherwise it will be oerrided!!!

std::map<String, MoodImage> moods;
int imgW = 0;
int imgH = 0;
int rowBytes = 0;
uint8_t *packed = nullptr;
static File jpegFile;

static String lastPath;

void *jpegOpenFile(const char *filename, int32_t *size) {
    logMessage("jpegOpenFile called for: " + lastPath);
    jpegFile = FSYS.open(lastPath.c_str(), FILE_READ);
    if (!jpegFile) {
        logMessage("jpegOpenFile: FAILED to open " + lastPath);
        return nullptr;
    }
    *size = jpegFile.size();
    logMessage("jpegOpenFile: success, size=" + String(*size));
    return &jpegFile;
}


void jpegCloseFile(void *handle) {
    if (jpegFile) jpegFile.close();
}

int32_t jpegReadFile(JPEGFILE *handle, uint8_t *buffer, int32_t length) {
    return jpegFile.read(buffer, length);
}

int32_t jpegSeekFile(JPEGFILE *handle, int32_t position) {
    return jpegFile.seek(position);
}

// --- Render callback ---
int jpegRenderCallback(JPEGDRAW *pDraw) {
    uint16_t *pixels = pDraw->pPixels;
    for (int y = 0; y < pDraw->iHeight; y++) {
        int imgY = pDraw->y + y;
        for (int x = 0; x < pDraw->iWidth; x++) {
            int imgX = pDraw->x + x;
            if (imgX >= imgW || imgY >= imgH) continue;

            uint16_t px = pixels[y * pDraw->iWidth + x];
            uint8_t r = ((px >> 11) & 0x1F) * 255 / 31;
            uint8_t g = ((px >> 5) & 0x3F) * 255 / 63;
            uint8_t b = (px & 0x1F) * 255 / 31;
            float y_lum = 0.299f*r + 0.587f*g + 0.114f*b;
            if (y_lum < 128) {
                packed[imgY * rowBytes + imgX/8] |= (1 << (7-(imgX % 8)));
            }
        }
    }
    return 1;
}

// --- Preload moods ---
void preloadMoods() {
    File dir = FSYS.open("/moods");
    if (!dir) {
        logMessage("Failed to open /moods directory");
        return;
    }

    while (File f = dir.openNextFile()) {
        if (f.isDirectory() || !String(f.name()).endsWith(".jpg")) {
            f.close();
            continue;
        }

        String filePath = String("/moods/") + String(f.name());
        String fileName = String(f.name());
        f.close();

        logMessage("Parsing mood file: " + filePath);

        lastPath = filePath; // store the correct, absolute path
        JPEGDEC jpeg; // local decoder instance to free RAM when not decoding
        if (jpeg.open(filePath.c_str(),
                      jpegOpenFile,
                      jpegCloseFile,
                      jpegReadFile,
                      jpegSeekFile,
                      jpegRenderCallback) != JPEG_SUCCESS) {
            logMessage("Failed to open JPEG: " + filePath);
            logMessage(String(jpeg.getLastError()));
            //continue; // dont you dare to continue, because for some reason it works like this
        }


        imgW = jpeg.getWidth();
        imgH = jpeg.getHeight();
        rowBytes = (imgW + 7) / 8;

        packed = new uint8_t[rowBytes * imgH];
        if (!packed) {
            logMessage("Alloc fail: " + fileName);
            jpeg.close();
            continue;
        }
        memset(packed, 0, rowBytes * imgH);

        if (jpeg.decode(0, 0, 0) != JPEG_SUCCESS) {////////////////////FUCK EVERTHING THAT THIS SHIT DOES I DONT FUCKING UNDERSTAND THIS BUT FUCKING SOMEHOW THIS SHIT WORKS JUST HOW THE FUCK I AM CRASHING OUT!!!!!!!!!!!!!!!!!!
            // logMessage("Decode failed: " + fileName);
            // delete[] packed;
            // jpeg.close();
            // continue;
        }

        jpeg.close();
        moods[fileName] = { (uint16_t)imgW, (uint16_t)imgH, packed };
        logMessage("Mood loaded successfully: " + fileName);
    }

    dir.close();
}
