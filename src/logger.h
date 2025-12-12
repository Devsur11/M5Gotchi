#include <string>
#include <vector>
#include "Arduino.h"
void logMessage(String message);
void fLogMessage(const char *format, ...);
// Overlay helpers
void loggerSetOverlayEnabled(bool enabled);
bool loggerIsOverlayEnabled();
void loggerGetLines(std::vector<String> &out, int maxLines);