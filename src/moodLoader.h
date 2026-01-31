#pragma once
#include <M5Unified.h>
#include <map>
#include "SD.h"
#include <JPEGDEC.h>

struct MoodImage {
    uint16_t width;
    uint16_t height;
    uint8_t *bitmap; // packed: 8 pixels per byte
};

extern std::map<String, MoodImage> moods;

void preloadMoods();
void *jpegOpenFile(const char *filename, int32_t *size);
void jpegCloseFile(void *handle);
int32_t jpegReadFile(JPEGFILE *handle, uint8_t *buffer, int32_t length);
int32_t jpegSeekFile(JPEGFILE *handle, int32_t position);