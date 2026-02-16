#include "settings.h"
#include "ui.h"
#include <FS.h>
#include "fontDownloader.h"

const char* FONTS_FOLDER = "/fonts";

// Embedded font files from platformio.ini board_build.embed_files
extern const uint8_t big_vlw_start[] asm("_binary_fonts_big_vlw_start");
extern const uint8_t big_vlw_end[] asm("_binary_fonts_big_vlw_end");
extern const uint8_t small_vlw_start[] asm("_binary_fonts_small_vlw_start");
extern const uint8_t small_vlw_end[] asm("_binary_fonts_small_vlw_end");

bool fileExists(const char* path) {
    File file = FSYS.open(path);
    bool exists = file;
    if (file) file.close();
    return exists;
}

bool copyEmbeddedFont(const uint8_t* fontStart, const uint8_t* fontEnd, const char* fontName) {
    String fontPath = String(FONTS_FOLDER) + "/" + String(fontName);
    
    if (fileExists(fontPath.c_str())) {
        fLogMessage("Font already exists: %s\n", fontPath.c_str());
        return true;
    }

    File file = FSYS.open(fontPath.c_str(), FILE_WRITE);
    if (!file) {
        fLogMessage("Failed to create font file: %s\n", fontPath.c_str());
        return false;
    }

    size_t fontSize = fontEnd - fontStart;
    size_t written = file.write(fontStart, fontSize);
    file.close();

    if (written != fontSize) {
        fLogMessage("Failed to write complete font file: %s (wrote %u of %u bytes)\n", 
                    fontPath.c_str(), written, fontSize);
        FSYS.remove(fontPath.c_str());
        return false;
    }

    fLogMessage("Copied font: %s (%u bytes)\n", fontPath.c_str(), fontSize);
    return true;
}

void downloadFonts() {
    if (!FSYS.begin()) {
        logMessage("SD card initialization failed");
        return;
    }

    if (!FSYS.exists(FONTS_FOLDER)) {
        FSYS.mkdir(FONTS_FOLDER);
        logMessage("Created fonts folder");
    }

    // Copy embedded fonts to SD card
    copyEmbeddedFont(big_vlw_start, big_vlw_end, "big.vlw");
    copyEmbeddedFont(small_vlw_start, small_vlw_end, "small.vlw");

    logMessage("Font transfer complete");
}