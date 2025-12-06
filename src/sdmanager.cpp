#include "sdmanager.h"
#include "M5Cardputer.h"
#include <FS.h>
#include <SD.h>
#include <vector>
#include "ui.h"
#include "logger.h"

extern M5Canvas canvas_main;
extern int canvas_top_h;
extern uint16_t bg_color_rgb565;
extern uint16_t tx_color_rgb565;
extern uint8_t menuID;

struct Entry {
  String name;
  bool isDir;
};

static void listDirectory(const String &path, std::vector<Entry> &out) {
  out.clear();
  File dir = SD.open(path.c_str());
  if (!dir) return;
  File file = dir.openNextFile();
  while (file) {
    Entry e;
    e.name = String(file.name());
    e.isDir = file.isDirectory();
    out.push_back(e);
    file.close();
    file = dir.openNextFile();
  }
  dir.close();
}

// Read file into vector of lines
static void readFileLines(const String &fullpath, std::vector<String> &lines) {
  lines.clear();
  File f = SD.open(fullpath.c_str(), FILE_READ);
  if (!f) return;
  String cur = "";
  while (f.available()) {
    char c = (char)f.read();
    if (c == '\r') continue;
    if (c == '\n') {
      lines.push_back(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  if (cur.length() > 0) lines.push_back(cur);
  f.close();
}

// Write vector of lines to file (overwrite)
static bool writeFileLines(const String &fullpath, const std::vector<String> &lines) {
  if (!SD.remove(fullpath.c_str())) {
    // ignore remove failure
  }
  File f = SD.open(fullpath.c_str(), FILE_WRITE);
  if (!f) return false;
  for (size_t i = 0; i < lines.size(); ++i) {
    f.print(lines[i]);
    if (i + 1 < lines.size()) f.print('\n');
  }
  f.flush();
  f.close();
  return true;
}

// Recursive delete for directories and files
static bool recursiveDelete(const String &path) {
  File f = SD.open(path.c_str());
  if (!f) return false;
  if (!f.isDirectory()) {
    f.close();
    return SD.remove(path.c_str());
  }
  // directory: iterate children
  File child = f.openNextFile();
  while (child) {
    String name = String(child.name());
    child.close();
    String childPath = path;
    if (!childPath.endsWith("/")) childPath += "/";
    childPath += name;
    // if child is directory, recurse
    File probe = SD.open(childPath.c_str());
    if (probe && probe.isDirectory()) {
      probe.close();
      recursiveDelete(childPath);
    } else {
      if (probe) probe.close();
      SD.remove(childPath.c_str());
    }
    child = f.openNextFile();
  }
  f.close();
  // remove the now-empty directory
  return SD.rmdir(path.c_str());
}

static void drawEntries(const String &path, const std::vector<Entry> &entries, int cur, int scroll) {
  drawTopCanvas();
  drawBottomCanvas();
  canvas_main.fillSprite(bg_color_rgb565);
  canvas_main.setTextSize(1.2);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.setTextDatum(top_left);
  canvas_main.drawString("SD: " + path, 3, 3);

  int y = 20;
  int perPage = 5;
  for (int i = 0; i < perPage; ++i) {
    int idx = i + scroll;
    if (idx >= (int)entries.size()) break;
    const Entry &e = entries[idx];
    if (idx == cur) {
      // highlight
      canvas_main.fillRect(2, y - 2, canvas_main.width() - 4, 14, tx_color_rgb565);
      canvas_main.setTextColor(bg_color_rgb565);
    } else {
      canvas_main.setTextColor(tx_color_rgb565);
    }
    String prefix = e.isDir ? "[D] " : "    ";
    String name = e.name;
    // trim leading path parts if any
    int slash = name.lastIndexOf('/');
    if (slash >= 0) name = name.substring(slash + 1);
    canvas_main.drawString(prefix + name, 6, y);
    y += 14;
  }

  // draw hints
  canvas_main.setTextSize(1);
  canvas_main.setTextColor(tx_color_rgb565);
  canvas_main.drawString("Enter: open/view  e:edit  c:new  d:del  `:back/exit", 3, canvas_main.height() - 12);

  // Scrollbar
  int total = entries.size();
  int visible = perPage;
  int trackX = canvas_main.width() - 8;
  int trackY = 18;
  int trackH = perPage * 14;
  if (trackH <= 0) trackH = canvas_main.height() - 40;
  // draw track background
  canvas_main.fillRect(trackX, trackY, 6, trackH, bg_color_rgb565);
  if (total > visible && visible > 0) {
    float ratio = (float)visible / (float)total;
    int thumbH = (int)(trackH * ratio);
    if (thumbH < 6) thumbH = 6;
    int maxScroll = total - visible;
    float posRatio = (maxScroll > 0) ? ((float)scroll / (float)maxScroll) : 0.0f;
    int thumbY = trackY + (int)((trackH - thumbH) * posRatio);
    canvas_main.fillRect(trackX, thumbY, 6, thumbH, tx_color_rgb565);
  } else {
    // full thumb
    canvas_main.fillRect(trackX, trackY, 6, trackH, tx_color_rgb565);
  }

  // push all canvases together to avoid leaving stale UI
  pushAll();
}

static void viewFile(const String &fullpath) {
  File f = SD.open(fullpath.c_str(), FILE_READ);
  if (!f) {
    drawInfoBox("ERROR", "Cannot open file", fullpath, true, true);
    return;
  }
  String content = "";
  while (f.available()) {
    content += (char)f.read();
    if (content.length() > 4000) break; // limit preview
  }
  f.close();

  int page = 0;
  const int linesPerPage = 6;
  std::vector<String> lines;
  int start = 0;
  while (start < (int)content.length()) {
    int nl = content.indexOf('\n', start);
    if (nl < 0) nl = content.length();
    lines.push_back(content.substring(start, nl));
    start = nl + 1;
  }

  while (true) {
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    int y = 10;
    int from = page * linesPerPage;
    for (int i = 0; i < linesPerPage; ++i) {
      int idx = from + i;
      if (idx >= (int)lines.size()) break;
      // reserve space for scrollbar on the right
      canvas_main.drawString(lines[idx], 6, y);
      y += 12;
    }
    // draw page indicator on left bottom
    canvas_main.setTextSize(1);
    canvas_main.drawString(String("Page ") + String(page + 1) + "/" + String((lines.size() + linesPerPage - 1) / linesPerPage), 6, canvas_main.height() - 20);

    // Draw vertical scrollbar on right
    int total = lines.size();
    int visible = linesPerPage;
    int trackX = canvas_main.width() - 8;
    int trackY = 8;
    int trackH = linesPerPage * 12;
    if (trackH <= 0) trackH = canvas_main.height() - 36;
    canvas_main.fillRect(trackX, trackY, 6, trackH, bg_color_rgb565);
    if (total > visible && visible > 0) {
      float ratio = (float)visible / (float)total;
      int thumbH = (int)(trackH * ratio);
      if (thumbH < 6) thumbH = 6;
      int maxScroll = total - visible;
      float posRatio = (maxScroll > 0) ? ((float)(page * visible) / (float)maxScroll) : 0.0f;
      int thumbY = trackY + (int)((trackH - thumbH) * posRatio);
      canvas_main.fillRect(trackX, thumbY, 6, thumbH, tx_color_rgb565);
    } else {
      canvas_main.fillRect(trackX, trackY, 6, trackH, tx_color_rgb565);
    }

    // scrolling hints marquee for long hint text
    static unsigned long hintTick = 0;
    static int hintOffset = 0;
    String hint = "ENTER: exit  .:next page  ;:prev page";
    int hintW = canvas_main.textWidth(hint);
    int availW = canvas_main.width()- 12; // leave space for scrollbar
    if (hintW > availW) {
      unsigned long now = millis();
      if (now - hintTick > 1) { hintTick = now; hintOffset++; }
      int maxOffset = hintW - availW + 8;
      if (hintOffset > maxOffset) hintOffset = 0;
      // draw substring by clipping with textWidth increments
      int startChar = 0;
      while (startChar < (int)hint.length() && canvas_main.textWidth(hint.substring(0, startChar)) < hintOffset) startChar++;
      String toDraw = hint.substring(startChar);
      // clamp to available width
      int endChar = toDraw.length();
      while (endChar > 0 && canvas_main.textWidth(toDraw.substring(0, endChar)) > availW) endChar--;
      toDraw = toDraw.substring(0, endChar);
      canvas_main.drawString(toDraw, 6, canvas_main.height() - 10);
    } else {
      canvas_main.drawString(hint, 6, canvas_main.height() - 10);
    }

    pushAll();

    M5.update();
    M5Cardputer.update();
    if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
      debounceDelay();
      break;
    }
    if (M5Cardputer.Keyboard.isKeyPressed('.')) {
      debounceDelay();
      if ((page + 1) * linesPerPage < (int)lines.size()) page++;
    }
    if (M5Cardputer.Keyboard.isKeyPressed(';')) {
      debounceDelay();
      if (page > 0) page--;
    }
  }
}

// Vim-like modal editor: normal mode (navigation) and insert mode (editing) with cursor display
static void editFile(const String &fullpath) {
  std::vector<String> lines;
  readFileLines(fullpath, lines);
  if (lines.size() == 0) lines.push_back("");

  int curLine = 0;
  int curCol = 0;
  int scrollLine = 0;
  bool insertMode = false;
  const int linesPerPage = 7;
  const int maxLineLen = 200;

  while (true) {
    drawTopCanvas();
    drawBottomCanvas();
    canvas_main.fillSprite(bg_color_rgb565);
    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    int y = 5;
    int start = scrollLine;
    
    //switch to next line if current line wrap overrides hints area
    

    // draw lines with cursor on current line
    for (int i = 0; i < linesPerPage; ++i) {
      int idx = start + i;
      if (idx >= (int)lines.size()) break;

      String prefix = String(idx + 1) + ": ";
      int prefixW = canvas_main.textWidth(prefix);
      int availW = canvas_main.width() - 18; // reserve space for scrollbar
      int wrapPx = availW;
      // enforce a sensible wrap width
      if (wrapPx > 230) wrapPx = 230;

      // build wrapped segments for this logical line
      String fullLine = lines[idx];
      std::vector<String> segments;
      // first segment includes space for prefix
      int taken = 0;
      // first segment: include prefix width in limit
      int maxFirstPx = wrapPx - prefixW;
      if (maxFirstPx < 8) maxFirstPx = wrapPx; // fallback
      int endChar = fullLine.length();
      // determine endChar for first segment
      while (endChar > taken && canvas_main.textWidth(fullLine.substring(0, endChar)) > maxFirstPx) endChar--;
      if (endChar < 0) endChar = 0;
      segments.push_back(fullLine.substring(0, endChar));
      taken = endChar;
      // subsequent segments: no prefix, use wrapPx
      while (taken < (int)fullLine.length()) {
        int remain = fullLine.length() - taken;
        int e = taken + remain;
        while (e > taken && canvas_main.textWidth(fullLine.substring(taken, e)) > wrapPx) e--;
        if (e <= taken) break; // can't fit any more
        segments.push_back(fullLine.substring(taken, e));
        taken = e;
      }

      // draw background highlight if current line
      if (idx == curLine) {
        int height = 14 * (int)segments.size();
        canvas_main.fillRect(4, y - 2, canvas_main.width() - 14, height, tx_color_rgb565);
        if(height + y > canvas_main.height() - 24){
          //scroll down to fit hints area
          scrollLine++;
          if(scrollLine > curLine) scrollLine = curLine;
          break; //redraw
        }
        canvas_main.setTextColor(bg_color_rgb565);
        // draw segments: first with prefix, others indented after prefix
        for (size_t si = 0; si < segments.size(); ++si) {
          if (si == 0) canvas_main.drawString(prefix + segments[si], 6, y);
          else canvas_main.drawString(segments[si], 6 + prefixW, y);

          // draw cursor if it falls in this segment
          int charsBefore = 0;
          for (size_t k = 0; k < si; ++k) charsBefore += segments[k].length();
          int segLen = segments[si].length();
          if ((insertMode && idx == curLine) || (!insertMode && idx == curLine)) {
            if (curCol >= charsBefore && curCol <= charsBefore + segLen) {
              int offsetInSeg = curCol - charsBefore;
              int cursorX = 6 + prefixW + canvas_main.textWidth(segments[si].substring(0, offsetInSeg));
              if (cursorX < canvas_main.width() - 18) canvas_main.fillRect(cursorX, y, 2, 12, bg_color_rgb565);
            }
            // special case: cursor at end (append)
            if (curCol > (int)fullLine.length()) {
              int cursorX = 6 + prefixW + canvas_main.textWidth(fullLine);
              if (cursorX < canvas_main.width() - 18) canvas_main.fillRect(cursorX, y, 2, 12, bg_color_rgb565);
            }
          }
          y += 12;
        }
      } else {
        canvas_main.setTextColor(tx_color_rgb565);
        // draw segments: first with prefix, others indented after prefix
        for (size_t si = 0; si < segments.size(); ++si) {
          if (si == 0) canvas_main.drawString(prefix + segments[si], 6, y);
          else canvas_main.drawString(segments[si], 6 + prefixW, y);
          y += 12;
        }
      }
    }


    canvas_main.setTextSize(1);
    canvas_main.setTextColor(tx_color_rgb565);
    String mode = insertMode ? "[INSERT]" : "[NORMAL]";
    String hints = mode + " .:down ;:up h:left l:right i:insert a:append o:newline x:del s:save q:quit";
    // marquee for hints if too long (leave space for scrollbar)
    int hintW = canvas_main.textWidth(hints);
    int hintAvailW = canvas_main.width() - 18;
    static unsigned long editHintTick = 0;
    static int editHintOffset = 0;
    if (hintW > hintAvailW) {
      unsigned long now = millis();
      if (now - editHintTick > 1) { editHintTick = now; editHintOffset++; }
      int maxOffset = hintW - hintAvailW + 8;
      if (editHintOffset > maxOffset) editHintOffset = 0;
      int startChar = 0;
      while (startChar < (int)hints.length() && canvas_main.textWidth(hints.substring(0, startChar)) < editHintOffset) startChar++;
      String toDraw = hints.substring(startChar);
      int endChar = toDraw.length();
      while (endChar > 0 && canvas_main.textWidth(toDraw.substring(0, endChar)) > hintAvailW) endChar--;
      toDraw = toDraw.substring(0, endChar);
      canvas_main.drawString(toDraw, 3, canvas_main.height() - 12);
    } else {
      canvas_main.drawString(hints, 3, canvas_main.height() - 12);
    }

    // Draw vertical scrollbar on right for editor
    int total = lines.size();
    int visible = linesPerPage;
    int trackX = canvas_main.width() - 8;
    int trackY = 5;
    int trackH = linesPerPage * 12;
    if (trackH <= 0) trackH = canvas_main.height() - 36;
    canvas_main.fillRect(trackX, trackY, 6, trackH, bg_color_rgb565);
    if (total > visible && visible > 0) {
      float ratio = (float)visible / (float)total;
      int thumbH = (int)(trackH * ratio);
      if (thumbH < 6) thumbH = 6;
      int maxScroll = total - visible;
      float posRatio = (maxScroll > 0) ? ((float)scrollLine / (float)maxScroll) : 0.0f;
      int thumbY = trackY + (int)((trackH - thumbH) * posRatio);
      canvas_main.fillRect(trackX, thumbY, 6, thumbH, tx_color_rgb565);
    } else {
      canvas_main.fillRect(trackX, trackY, 6, trackH, tx_color_rgb565);
    }

    pushAll();

    M5.update();
    M5Cardputer.update();

    if (insertMode) {

      // backtick to exit insert mode
      if (M5Cardputer.Keyboard.isKeyPressed('`')) {
        debounceDelay();
        insertMode = false;
        continue;
      }
      // Insert mode: type characters
      Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();
      for (auto c : status.word) {
        if (curCol > maxLineLen) continue;
        // Always insert: splice character at cursor position
        lines[curLine] = lines[curLine].substring(0, curCol) + String(c) + lines[curLine].substring(curCol);
        curCol++;
        debounceDelay();
      }
      // Handle backspace
      if (M5Cardputer.Keyboard.isKeyPressed(KEY_BACKSPACE)) {
        debounceDelay();
        if (curCol > 0) {
          lines[curLine] = lines[curLine].substring(0, curCol - 1) + lines[curLine].substring(curCol);
          curCol--;
        }
      }
      
    } else {
      // Normal mode: navigation and commands
      if (M5Cardputer.Keyboard.isKeyPressed('.') || M5Cardputer.Keyboard.isKeyPressed('j')) {
        debounceDelay();
        if (curLine + 1 < (int)lines.size()) {
          curLine++;
          if (curLine >= scrollLine + linesPerPage) scrollLine++;
          if (curCol > (int)lines[curLine].length()) curCol = lines[curLine].length();
        }
      }
      if (M5Cardputer.Keyboard.isKeyPressed(';') || M5Cardputer.Keyboard.isKeyPressed('k')) {
        debounceDelay();
        if (curLine > 0) {
          curLine--;
          if (curLine < scrollLine) scrollLine--;
          if (curCol > (int)lines[curLine].length()) curCol = lines[curLine].length();
        }
      }
      if (M5Cardputer.Keyboard.isKeyPressed('h')) {
        debounceDelay();
        if (curCol > 0) curCol--;
      }
      if (M5Cardputer.Keyboard.isKeyPressed('l')) {
        debounceDelay();
        if (curCol < (int)lines[curLine].length()) curCol++;
      }
      
      if (M5Cardputer.Keyboard.isKeyPressed('i')) {
        debounceDelay();
        insertMode = true;
      }
      if (M5Cardputer.Keyboard.isKeyPressed('a')) {
        debounceDelay();
        curCol = lines[curLine].length();
        insertMode = true;
      }
      if (M5Cardputer.Keyboard.isKeyPressed('o')) {
        debounceDelay();
        lines.insert(lines.begin() + curLine + 1, String(""));
        curLine++;
        curCol = 0;
        if (curLine >= scrollLine + linesPerPage) scrollLine++;
        insertMode = true;
      }
      if (M5Cardputer.Keyboard.isKeyPressed('x')) {
        debounceDelay();
        if (curCol < (int)lines[curLine].length()) {
          lines[curLine] = lines[curLine].substring(0, curCol) + lines[curLine].substring(curCol + 1);
        }
      }
      if (M5Cardputer.Keyboard.isKeyPressed('s')) {
        debounceDelay();
        if (writeFileLines(fullpath, lines)) {
          drawInfoBox("Saved", fullpath, "", true, false);
        } else {
          drawInfoBox("ERROR", "Cannot save file", fullpath, true, true);
        }
      }
      if (M5Cardputer.Keyboard.isKeyPressed('q')) {
        debounceDelay();
        if (drawQuestionBox("Save?", "Save changes to file:", fullpath)) {
          writeFileLines(fullpath, lines);
        }
        break;
      }
    }
    
    delay(80);
  }
}

void sdmanager::runFileManager() {
  String curPath = "/";
  std::vector<Entry> entries;
  int cur = 0;
  int scroll = 0;

  if (!SD.begin()) {
    drawInfoBox("ERROR", "SD not mounted", "Insert SD card", true, true);
    return;
  }

  listDirectory(curPath, entries);

  while (true) {
    if (cur >= (int)entries.size()) cur = entries.size() - 1;
    if (cur < 0) cur = 0;
    if (scroll > cur) scroll = cur;
    if (cur >= scroll + 5) scroll = cur - 4;

    drawEntries(curPath, entries, cur, scroll);

    M5.update();
    M5Cardputer.update();

    if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) {
      debounceDelay();
      if (entries.empty()) continue;
      String name = entries[cur].name;
      String full = curPath;
      if (!full.endsWith("/")) full += "/";
      full += name;
      if (entries[cur].isDir) {
        // enter dir
        curPath = full;
        listDirectory(curPath, entries);
        cur = 0; scroll = 0;
      } else {
        // file: show submenu: view/edit/delete
        drawTopCanvas(); drawBottomCanvas();
        canvas_main.fillSprite(bg_color_rgb565);
        canvas_main.setTextSize(1.5);
        canvas_main.setTextColor(tx_color_rgb565);
        canvas_main.drawString(name, 6, 20);
        canvas_main.setTextSize(1);
        canvas_main.drawString("v:view  e:edit  m:move/rename  d:delete  ENTER:back", 6, 60);
        pushAll();
        while (true) {
          M5.update();
          M5Cardputer.update();
          if (M5Cardputer.Keyboard.isKeyPressed('v')) { debounceDelay(); viewFile(full); break; }
          if (M5Cardputer.Keyboard.isKeyPressed('e')) { debounceDelay(); editFile(full); break; }
          if (M5Cardputer.Keyboard.isKeyPressed('m')) {
            debounceDelay();
            String newname = userInput("Move/rename to:", name, 128);
            if (newname.length()) {
              String target = newname;
              // if target is relative (no leading /), put in same directory
              if (!target.startsWith("/")) {
                String base = curPath;
                if (!base.endsWith("/")) base += "/";
                target = base + target;
              }
              if (SD.rename(full.c_str(), target.c_str())) {
                drawInfoBox("OK", "Moved/renamed", target, true, false);
                listDirectory(curPath, entries);
              } else {
                drawInfoBox("ERROR", "Move/rename failed", target, true, true);
              }
            }
            break;
          }
          if (M5Cardputer.Keyboard.isKeyPressed('d')) {
            debounceDelay();
            if (drawQuestionBox("Delete?", "Delete file:", name)) {
              // if it's a directory, ask for recursive delete
              File probe = SD.open(full.c_str());
              if (probe && probe.isDirectory()) {
                probe.close();
                if (drawQuestionBox("Recursive?", "Delete directory and all contents?", name)) {
                  if (recursiveDelete(full)) {
                    drawInfoBox("Deleted", name, "", true, false);
                    listDirectory(curPath, entries);
                  } else {
                    drawInfoBox("ERROR", "Recursive delete failed", name, true, true);
                  }
                }
              } else {
                if (probe) probe.close();
                SD.remove(full);
                listDirectory(curPath, entries);
                cur = 0; scroll = 0;
              }
            }
            break;
          }
          if (M5Cardputer.Keyboard.isKeyPressed(KEY_ENTER)) { debounceDelay(); break; }
        }
      }
    }

    if (M5Cardputer.Keyboard.isKeyPressed('.')) { debounceDelay(); cur = (cur + 1) % ( (entries.empty()) ? 1 : entries.size() ); }
    if (M5Cardputer.Keyboard.isKeyPressed(';')) { debounceDelay(); if (!entries.empty()) cur = (cur + entries.size() - 1) % entries.size(); }

    if (M5Cardputer.Keyboard.isKeyPressed('`')) {
      debounceDelay();
      // go up or exit
      if (curPath == "/") {
        // exit manager
        menuID = 0;
        return;
      }
      int lastSlash = curPath.lastIndexOf('/');
      if (lastSlash == 0) curPath = "/"; else curPath = curPath.substring(0, lastSlash);
      listDirectory(curPath, entries);
      cur = 0; scroll = 0;
    }

    if (M5Cardputer.Keyboard.isKeyPressed('c')) {
      debounceDelay();
      // create new file or dir
      String createOpts[2]; createOpts[0] = "File"; createOpts[1] = "Directory";
      int choice = drawMultiChoice("Create: ", createOpts, 2, 0, 0);
      if (choice == 0) {
        String name = userInput("New file name:", "", 64);
        if (name.length()) {
          String full = curPath;
          if (!full.endsWith("/")) full += "/";
          full += name;
          File f = SD.open(full.c_str(), FILE_WRITE);
          if (f) { f.print(""); f.close(); listDirectory(curPath, entries); }
          else drawInfoBox("ERROR", "Cannot create file", full, true, true);
        }
      } else if (choice == 1) {
        String name = userInput("New dir name:", "", 64);
        if (name.length()) {
          String full = curPath;
          if (!full.endsWith("/")) full += "/";
          full += name;
          if (!SD.mkdir(full.c_str())) drawInfoBox("ERROR", "Cannot create dir", full, true, true);
          listDirectory(curPath, entries);
        }
      }
    }

    if (M5Cardputer.Keyboard.isKeyPressed('d')) {
      debounceDelay();
      if (entries.empty()) continue;
      String name = entries[cur].name;
      String full = curPath;
      if (!full.endsWith("/")) full += "/";
      full += name;
      if (drawQuestionBox("Delete?", "Confirm delete", name)) {
        if (entries[cur].isDir) {
          // check if empty
          File dd = SD.open(full.c_str());
          if (dd) {
            bool empty = (dd.openNextFile() == 0);
            dd.close();
            if (empty) {
              SD.rmdir(full.c_str());
              listDirectory(curPath, entries);
            } else {
              // ask for recursive delete
              if (drawQuestionBox("Recursive?", "Delete directory and all contents?", name)) {
                if (recursiveDelete(full)) {
                  drawInfoBox("Deleted", name, "", true, false);
                  listDirectory(curPath, entries);
                } else {
                  drawInfoBox("ERROR", "Recursive delete failed", name, true, true);
                }
              }
            }
          } else {
            drawInfoBox("ERROR", "Directory cannot be opened", name, true, true);
          }
        } else {
          SD.remove(full.c_str());
          listDirectory(curPath, entries);
        }
      }
    }

    delay(80);
  }
}
