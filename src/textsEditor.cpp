#include "settings.h"
#include "textsEditor.h"
#include "ui.h"
#include <map>
#include <vector>
#include "logger.h"
#include <algorithm>
#include "mood.h"
#include "inputManager.h"
#ifndef BUTTON_ONLY_INPUT
#include "M5Cardputer.h"
#endif

extern M5Canvas canvas_main;
extern uint16_t bg_color_rgb565;
extern uint16_t tx_color_rgb565;

// Simple INI-like parser for sectioned texts file
static bool parseSectionedFileLocal(const String &path, std::map<String, std::vector<String>> &out, std::vector<String> &order) {
  out.clear();
  order.clear();
  File f = FSYS.open(path.c_str(), FILE_READ);
  if (!f) return false;
  String section = "";
  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;
    if (line.startsWith("#")) continue;
    if (line.startsWith("[") && line.endsWith("]")) {
      section = line.substring(1, line.length()-1);
      out[section] = std::vector<String>();
      order.push_back(section);
      continue;
    }
    if (section == "") continue;
    out[section].push_back(line);
  }
  f.close();
  return true;
}

static bool saveSectionedFileLocal(const String &path, const std::map<String, std::vector<String>> &mapIn, const std::vector<String> &order) {
  if (!FSYS.remove(path.c_str())) {
    // ignore remove failure
  }
  File f = FSYS.open(path.c_str(), FILE_WRITE);
  if (!f) return false;
  for (size_t i = 0; i < order.size(); ++i) {
    String section = order[i];
    f.print("["); f.print(section); f.print("]\n");
    auto it = mapIn.find(section);
    if (it != mapIn.end()) {
      for (const String &line : it->second) {
        f.print(line);
        f.print('\n');
      }
    }
    f.print('\n');
  }
  f.flush();
  f.close();
  return true;
}

// Helper function to draw a scrollbar
static void drawScrollbar(int x, int y, int height, int totalItems, int currentPage, int itemsPerPage) {
    int visibleItems = min(itemsPerPage, totalItems);
    if (totalItems <= visibleItems || totalItems <= 0) return; // No scrollbar needed
    
    int barHeight = max(3, (height * visibleItems + totalItems - 1) / totalItems);
    int barY = y + (height * currentPage * itemsPerPage + totalItems - 1) / totalItems;
    
    //canvas_main.drawRect(x, y, 2, height, tx_color_rgb565);
    canvas_main.fillRect(x, barY, 2, barHeight, tx_color_rgb565);
}

// Simple text input without userInput function
static String simpleTextInput(const String &prompt, const String &initial, int maxLen) {
    //TODO: retire this function and use userInput directly
    return userInput(prompt, "", maxLen, initial);
}

// Draw a simple list and return when user exits
void runTextsEditor() {
    const String path = "/moods/texts.txt";
    std::map<String, std::vector<String>> texts;
    std::vector<String> order;
    if (!parseSectionedFileLocal(path, texts, order)) {
        drawInfoBox("ERROR", "Cannot open /moods/texts.txt", "Make sure SD is available", true, false);
        return;
    }

    const int LINES_PER_PAGE = 5;
    int selSection = 0;
    int selLine = 0;
    int pageSection = 0;
    int pageLine = 0;
    bool viewingLines = false;
    int marqueePos = 0;
    unsigned long lastMarqueeUpdate = 0;

    while (true) {
        drawTopCanvas();
        drawBottomCanvas();
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextSize(1);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.setTextDatum(top_left);

        // Update marquee
        unsigned long now = millis();
        if (now - lastMarqueeUpdate > 200) {
            marqueePos = (marqueePos + 1) % 50;
            lastMarqueeUpdate = now;
        }

        if (!viewingLines) {
            // draw sections with pagination
            canvas_main.drawString("Texts editor - Sections:", 6, 6);
            int maxPages = (order.size() + LINES_PER_PAGE - 1) / LINES_PER_PAGE;
            pageSection = min(pageSection, max(0, maxPages - 1));
            int startIdx = pageSection * LINES_PER_PAGE;
            int endIdx = min(startIdx + LINES_PER_PAGE, (int)order.size());
            
            int y = 28;
            for (int i = startIdx; i < endIdx; ++i) {
                String name = order[i];
                if (i == selSection) {
                    canvas_main.fillRect(4, y-2, canvas_main.width()-12, 12, tx_color_rgb565);
                    canvas_main.setTextColor(bg_color_rgb565);
                    canvas_main.drawString(name, 8, y);
                    canvas_main.setTextColor(tx_color_rgb565);
                } else {
                    canvas_main.drawString(name, 8, y);
                }
                y += 14;
            }
            
            // Draw scrollbar
            drawScrollbar(canvas_main.width()-4, 28, LINES_PER_PAGE*14, order.size(), pageSection, LINES_PER_PAGE);
            
            // Show hints based on input mode
#ifdef BUTTON_ONLY_INPUT
            canvas_main.drawString("A:select  B:nav  Long B:menu", 6, canvas_main.height()-12);
#else
            String hints = "i/ENTER:open  a:add  d:del  s:save  `:exit";
            if (hints.length() > 40) {
                String marqueeTxt = hints + "  |  " + hints;
                canvas_main.drawString(marqueeTxt.substring(marqueePos, marqueePos + 40), 6, canvas_main.height()-12);
            } else {
                canvas_main.drawString(hints, 6, canvas_main.height()-12);
            }
#endif
        } else {
            // draw lines of selected section with pagination
            String sec = order[selSection];
            canvas_main.drawString("Section: " + sec, 6, 6);
            auto &lines = texts[sec];
            int maxPages = (lines.size() + LINES_PER_PAGE - 1) / LINES_PER_PAGE;
            pageLine = min(pageLine, max(0, maxPages - 1));
            int startIdx = pageLine * LINES_PER_PAGE;
            int endIdx = min(startIdx + LINES_PER_PAGE, (int)lines.size());
            
            int y = 28;
            for (int i = startIdx; i < endIdx; ++i) {
                String ln = lines[i];
                if (i == selLine) {
                    canvas_main.fillRect(4, y-2, canvas_main.width()-12, 14, tx_color_rgb565);
                    canvas_main.setTextColor(bg_color_rgb565);
                    canvas_main.drawString(String(i+1)+": " + ln, 8, y);
                    canvas_main.setTextColor(tx_color_rgb565);
                } else {
                    canvas_main.drawString(String(i+1)+": " + ln, 8, y);
                }
                y += 14;
            }
            
            // Draw scrollbar
            drawScrollbar(canvas_main.width()-4, 28, LINES_PER_PAGE*14, (int)lines.size(), pageLine, LINES_PER_PAGE);
            
            // Show hints based on input mode
#ifdef BUTTON_ONLY_INPUT
            canvas_main.drawString("A:select  B:nav  Long B:menu", 6, canvas_main.height()-12);
#else
            String hints = "i/ENTER:edit  a:add  d:del  b/`:back  s:save";
            if (hints.length() > 40) {
                String marqueeTxt = hints + "  |  " + hints;
                canvas_main.drawString(marqueeTxt.substring(marqueePos, marqueePos + 40), 6, canvas_main.height()-12);
            } else {
                canvas_main.drawString(hints, 6, canvas_main.height()-12);
            }
#endif
        }

        pushAll();
        M5.update();
#ifndef BUTTON_ONLY_INPUT
        M5Cardputer.update();
#endif

        // navigation
        if (!viewingLines) {
#ifdef BUTTON_ONLY_INPUT
            inputManager::update();
            if (inputManager::isButtonBPressed()) {
                debounceDelay();
                selSection = (selSection + 1) % (order.size() ? order.size() : 1);
                pageSection = selSection / LINES_PER_PAGE;
            }
            if (inputManager::isButtonBLongPressed()) {
                debounceDelay();
                // Show action menu
                String actions[] = {"Open", "Add", "Delete", "Save", "Exit", "Close menu"};
                int choice = drawMultiChoice("Sections Menu:", actions, 6, 0, 0);
                if(choice == 5) {
                    // Close menu
                } else
                if (choice == 0) {
                    // Open
                    viewingLines = true;
                    selLine = 0;
                    pageLine = 0;
                } else if (choice == 1) {
                    // Add
                    String name = simpleTextInput("New section", "", 24);
                    if (name.length() > 0 && texts.count(name) == 0) {
                        texts[name] = std::vector<String>();
                        order.push_back(name);
                        selSection = order.size()-1;
                        pageSection = selSection / LINES_PER_PAGE;
                    }
                } else if (choice == 2) {
                    // Delete
                    if (order.size() > 0) {
                        if (drawQuestionBox("Delete?", "Delete section:", order[selSection])) {
                            String sect = order[selSection];
                            texts.erase(sect);
                            order.erase(order.begin() + selSection);
                            if (selSection >= (int)order.size()) selSection = max(0, (int)order.size()-1);
                            pageSection = selSection / LINES_PER_PAGE;
                        }
                    }
                } else if (choice == 3) {
                    // Save
                    saveSectionedFileLocal(path, texts, order);
                    reloadMoodFiles();
                    drawInfoBox("Saved", "Changes written", "", true, false);
                } else if (choice == 4) {
                    // Exit
                    debounceDelay();
                    return;
                }
            }
            if (inputManager::isButtonAPressed()) {
                debounceDelay();
                if (order.size() > 0) {
                    viewingLines = true;
                    selLine = 0;
                    pageLine = 0;
                }
            }
#else
            if (M5Cardputer.Keyboard.isKeyPressed('j') || M5Cardputer.Keyboard.isKeyPressed('.')) {
                selSection = min((int)order.size()-1, selSection+1);
                pageSection = selSection / LINES_PER_PAGE;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('k') || M5Cardputer.Keyboard.isKeyPressed(';')) {
                selSection = max(0, selSection-1);
                pageSection = selSection / LINES_PER_PAGE;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('i') || M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
                viewingLines = true;
                selLine = 0;
                pageLine = 0;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('a')) {
                String name = simpleTextInput("New section", "", 24);
                if (name.length() > 0 && texts.count(name) == 0) {
                    texts[name] = std::vector<String>();
                    order.push_back(name);
                    selSection = order.size()-1;
                    pageSection = selSection / LINES_PER_PAGE;
                }
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('d')) {
                if (order.size() > 0) {
                    String sect = order[selSection];
                    texts.erase(sect);
                    order.erase(order.begin() + selSection);
                    if (selSection >= (int)order.size()) selSection = max(0, (int)order.size()-1);
                    pageSection = selSection / LINES_PER_PAGE;
                }
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('s')) {
                saveSectionedFileLocal(path, texts, order);
                reloadMoodFiles();
                drawInfoBox("Saved", "Changes written", "", true, false);
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('`')) {
                debounceDelay();
                return;
            }
#endif
        } else {
            String sec = order[selSection];
            auto &lines = texts[sec];
#ifdef BUTTON_ONLY_INPUT
            inputManager::update();
            if (inputManager::isButtonBPressed()) {
                debounceDelay();
                selLine = (selLine + 1) % (lines.size() ? lines.size() : 1);
                pageLine = selLine / LINES_PER_PAGE;
            }
            if (inputManager::isButtonBLongPressed()) {
                debounceDelay();
                // Show action menu
                String actions[] = {"Edit", "Add", "Delete", "Save", "Back", "Close menu"};
                int choice = drawMultiChoice("Line Menu:", actions, 6, 0, 0);
                if(choice == 5) {
                    // Close menu
                } else
                if (choice == 0) {
                    // Edit
                    if (lines.size() > 0) {
                        String newv = simpleTextInput("Edit line", lines[selLine], 120);
                        if (newv.length() > 0) lines[selLine] = newv;
                    }
                } else if (choice == 1) {
                    // Add
                    String newv = simpleTextInput("Add line", "", 120);
                    if (newv.length() > 0) lines.insert(lines.begin() + selLine + 1, newv);
                } else if (choice == 2) {
                    // Delete
                    if (lines.size() > 0) {
                        if (drawQuestionBox("Delete?", "Delete line:", lines[selLine])) {
                            lines.erase(lines.begin() + selLine);
                            if (selLine >= (int)lines.size()) selLine = max(0, (int)lines.size()-1);
                            pageLine = selLine / LINES_PER_PAGE;
                        }
                    }
                } else if (choice == 3) {
                    // Save
                    saveSectionedFileLocal(path, texts, order);
                    reloadMoodFiles();
                    drawInfoBox("Saved", "Changes written", "", true, false);
                } else if (choice == 4) {
                    // Back
                    viewingLines = false;
                }
            }
            if (inputManager::isButtonAPressed()) {
                debounceDelay();
                if (lines.size() > 0) {
                    String newv = simpleTextInput("Edit line", lines[selLine], 120);
                    if (newv.length() > 0) lines[selLine] = newv;
                }
            }
#else
            if (M5Cardputer.Keyboard.isKeyPressed('j') || M5Cardputer.Keyboard.isKeyPressed('.')) {
                selLine = min((int)lines.size()-1, selLine+1);
                pageLine = selLine / LINES_PER_PAGE;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('k') || M5Cardputer.Keyboard.isKeyPressed(';')) {
                selLine = max(0, selLine-1);
                pageLine = selLine / LINES_PER_PAGE;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('i') || M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
                String newv = simpleTextInput("Edit line", lines[selLine], 120);
                if (newv.length() > 0) lines[selLine] = newv;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('a')) {
                String newv = simpleTextInput("Add line", "", 120);
                if (newv.length() > 0) lines.insert(lines.begin() + selLine + 1, newv);
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('d')) {
                if (lines.size() > 0) {
                    lines.erase(lines.begin() + selLine);
                    if (selLine >= (int)lines.size()) selLine = max(0, (int)lines.size()-1);
                    pageLine = selLine / LINES_PER_PAGE;
                }
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('b') || M5Cardputer.Keyboard.isKeyPressed('`')) {
                viewingLines = false;
                debounceDelay();
            }
            if (M5Cardputer.Keyboard.isKeyPressed('s')) {
                saveSectionedFileLocal(path, texts, order);
                reloadMoodFiles();
                drawInfoBox("Saved", "Changes written", "", true, false);
                debounceDelay();
            }
#endif
        }
    }
}
