#include "settings.h"
#include "logger.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "githubUpdater.h"
#include <FS.h>
#include <ArduinoJson.h>
#include <SD.h>
#include <M5GFX.h>
#include "M5Cardputer.h"

static int ota_progress = 0;
static int ota_total = 0;


extern const char github_root_cert_pem_start[] asm("_binary_certs_github_root_cert_pem_start");
extern const char github_root_cert_pem_end[] asm("_binary_certs_github_root_cert_pem_end");

void draw_progress_bar(int percent) {
  const int x = 0;
  const int y = 0;
  const int w = M5.Display.width();
  const int h = 16;

  M5.Display.fillRect(x, y, w, M5.Display.height(), TFT_BLACK);
  M5.Display.drawRect(x, y, w, h, TFT_WHITE);
  int fill = (w - 2) * percent / 100;
  M5.Display.fillRect(x + 1, y + 1, fill, h - 2, TFT_WHITE);

  M5.Display.setCursor(x, y + 20);
  M5.Display.setTextColor(TFT_WHITE, TFT_BLACK);
  M5.Display.printf("Updating... %d%%   \n", percent);
  M5.Display.println("M5Gotchi Updater v2.0");
  M5.Display.println("\nDON'T TURN OFF THE DEVICE!, otherwise it may brick!");
}

esp_err_t ota_http_event_handler(esp_http_client_event_t *evt) {
  switch (evt->event_id) {
    case HTTP_EVENT_ON_HEADER:
      if (strcasecmp(evt->header_key, "Content-Length") == 0) {
        ota_total = atoi(evt->header_value);
      }
      break;

    case HTTP_EVENT_ON_DATA:
      if (ota_total > 0) {
        ota_progress += evt->data_len;
        int percent = (ota_progress * 100) / ota_total;
        draw_progress_bar(percent);
      }
      break;

    default:
      break;
  }
  return ESP_OK;
}


static bool ensure_temp_dir() {
  if (!SD.exists(TEMP_DIR)) {
    if (!SD.mkdir(TEMP_DIR)) {
      logMessage("Failed to create temp directory on SD card");
      return false;
    }
  }
  return true;
}

static bool download_file(const char* url, const char* dest_path) {
  esp_http_client_config_t config = {
    .url = url,
    .cert_pem = github_root_cert_pem_start,
  };
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    logMessage("Failed to initialise HTTP client");
    return false;
  }
  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    logMessage((String("Failed to open HTTP connection: ") + esp_err_to_name(err)).c_str());
    esp_http_client_cleanup(client);
    return false;
  }
  int status = esp_http_client_fetch_headers(client);
  logMessage(String("HTTP status: ") + esp_http_client_get_status_code(client));
  File f = SD.open(dest_path, FILE_WRITE, true);
  if (!f) {
    logMessage("Failed to open file for writing");
    esp_http_client_cleanup(client);
    return false;
  }
  int contentLength = esp_http_client_get_content_length(client);
  char buffer[512];
  int read_len;
  size_t total = 0;
  while ((read_len = esp_http_client_read(client, buffer, sizeof(buffer))) > 0) {
    f.write((const uint8_t*)buffer, read_len);
    total += read_len;
    if (read_len > 0) {
        int progress = (total * 100) / contentLength;
        M5.Display.fillRect(0, 0, M5.Display.width(), 40, TFT_BLACK);
        M5.Display.setTextColor(TFT_WHITE);
        M5.Display.drawString("Downloading...", 10, 10);
        M5.Display.drawString(String(progress) + "%", M5.Display.width() - 50, 10);
        M5.Display.fillRect(10, 25, (M5.Display.width() - 20) * progress / 100, 10, TFT_GREEN);
    }
  }
  f.flush();
  f.close();
  logMessage(String("Downloaded ") + total + " bytes to " + dest_path);
  logMessage(String("Actual file size on disk: ") + String(SD.open(dest_path).size()));
  logMessage(String("Downloaded ") + total + " bytes to " + dest_path);
  esp_http_client_cleanup(client);
  return true;
}

static bool parse_json_version_and_file(const char* json_path, char* out_version, size_t version_len, char* out_file, size_t file_len) {
  File f = SD.open(json_path, FILE_READ);
  if (!f) {
    logMessage("Failed to open JSON file for parsing");
    return false;
  }
  size_t size = f.size();
  if (size == 0) {
    logMessage("JSON file is empty" + String(json_path));
    f.close();
    return false;
  }
  std::unique_ptr<char[]> buf(new char[size + 1]);
  f.readBytes(buf.get(), size);
  buf[size] = 0;
  f.close();

  JsonDocument doc;
  DeserializationError error = deserializeJson(doc, buf.get());
  if (error) {
    logMessage("Failed to parse JSON");
    return false;
  }
  const char* version = doc["version"];
  const char* file = doc["file"];
  if (!version || !file) {
    logMessage("JSON missing required fields");
    return false;
  }
  strncpy(out_version, version, version_len - 1);
  out_version[version_len - 1] = 0;
  strncpy(out_file, file, file_len - 1);
  out_file[file_len - 1] = 0;
  return true;
}

bool check_for_new_firmware_version(bool lite) {
  if (!SD.begin(SD_CS, sdSPI, 1000000)) {
    logMessage("Failed to mount SD card");
    return false;
  }
  if (!ensure_temp_dir()) return false;

  const char* json_url = lite ? LITE_JSON_URL : NORMAL_JSON_URL;
  logMessage(String("Downloading JSON: ") + json_url);
  if (!download_file(json_url, TEMP_JSON_PATH)) {
    logMessage("Failed to download JSON file");
    return false;
  }

  char remote_version[32] = {0};
  char bin_url[256] = {0};
  if (!parse_json_version_and_file(TEMP_JSON_PATH, remote_version, sizeof(remote_version), bin_url, sizeof(bin_url))) {
    SD.remove(TEMP_JSON_PATH);
    return false;
  }

  logMessage(String("Remote version: ") + remote_version + ", Current: " + CURRENT_VERSION);

  bool update_needed = strcmp(CURRENT_VERSION, remote_version) < 0;
  SD.remove(TEMP_JSON_PATH);
  return update_needed;
}

bool ota_update_from_url(bool lite) {
  if (!ensure_temp_dir()) return false;

  const char* json_url = lite ? LITE_JSON_URL : NORMAL_JSON_URL;
  logMessage(String("Downloading JSON: ") + json_url);
  if (!download_file(json_url, TEMP_JSON_PATH)) {
    logMessage("Failed to download JSON file");
    return false;
  }

  char remote_version[32] = {0};
  char bin_url[256] = {0};
  if (!parse_json_version_and_file(TEMP_JSON_PATH, remote_version, sizeof(remote_version), bin_url, sizeof(bin_url))) {
    SD.remove(TEMP_JSON_PATH);
    return false;
  }

  if (strcmp(CURRENT_VERSION, remote_version) >= 0) {
    logMessage("No update needed");
    SD.remove(TEMP_JSON_PATH);
    return false;
  }

  logMessage(String("Downloading firmware bin: ") + bin_url);
  if (!download_file(bin_url, TEMP_BIN_PATH)) {
    logMessage("Failed to download firmware bin");
    SD.remove(TEMP_JSON_PATH);
    return false;
  }
  SD.remove(TEMP_JSON_PATH);

  esp_http_client_config_t config = {
    .url = bin_url,
    .cert_pem = github_root_cert_pem_start,
    .event_handler = ota_http_event_handler,
  };


  // Use esp_https_ota with file
  ota_progress = 0;
  ota_total = 0;
  draw_progress_bar(0);

  esp_err_t ret = esp_https_ota(&config);
  SD.remove(TEMP_BIN_PATH);

  if (ret == ESP_OK) {
    logMessage("OTA update successful, restarting...");
    esp_restart();
    return true;
  } else {
    logMessage(String("OTA failed: ") + esp_err_to_name(ret));
    return false;
  }
}
