#include "usbMassStorage.h"
#include "logger.h"
#include <ESPAsyncWebServer.h>
#include <ArduinoJson.h>
#include "settings.h"

namespace USBMassStorage {
  static AsyncWebServer* web_server = nullptr;
  static bool is_active = false;
  static const int WEB_SERVER_PORT = 8080;
  static const size_t JSON_BUFFER_SIZE = 4096;

  // HTML/CSS/JS for the web interface
  static const char* getIndexHTML() {
    return R"rawliteral(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: var(--bg-gradient);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: var(--bg-gradient);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .content { 
            padding: 30px;
        }
        .toolbar {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-bottom: 20px;
            align-items: center;
        }
        .breadcrumb {
            flex: 1;
            background: #f5f5f5;
            padding: 10px 15px;
            border-radius: 6px;
            font-size: 0.9em;
            word-break: break-all;
        }
        .btn {
            padding: 10px 15px;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 500;
            transition: all 0.3s ease;
        }
        .btn-primary {
            background: #667eea;
            color: white;
        }
        .btn-primary:hover { background: #5568d3; }
        .btn-danger {
            background: #f56565;
            color: white;
        }
        .btn-danger:hover { background: #e53e3e; }
        .btn-success {
            background: #48bb78;
            color: white;
        }
        .btn-success:hover { background: #38a169; }
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
        input[type="file"], input[type="text"] {
            padding: 10px 15px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 0.9em;
        }
        .file-list {
            border: 1px solid #ddd;
            border-radius: 6px;
            overflow: hidden;
        }
        .file-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: background 0.2s;
        }
        .file-item:hover { background: #f9f9f9; }
        .file-item:last-child { border-bottom: none; }
        .file-info {
            flex: 1;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .file-icon {
            font-size: 1.5em;
            width: 30px;
            text-align: center;
        }
        .file-details {
            flex: 1;
        }
        .file-name {
            font-weight: 500;
            word-break: break-all;
        }
        .file-meta {
            font-size: 0.8em;
            color: #999;
            margin-top: 4px;
        }
        .file-actions {
            display: flex;
            gap: 5px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }
        .btn-small {
            padding: 6px 10px;
            font-size: 0.8em;
        }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal.active { display: flex; }
        .modal-content {
            background: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
        }
        #editModal .modal-content {
            max-width: 95vw;
            width: 95vw;
            height: 90vh;
            padding: 20px;
            display: flex;
            flex-direction: column;
            border-radius: 8px;
        }
        .modal-header { font-size: 1.3em; font-weight: 600; margin-bottom: 20px; }
        .modal-body { margin-bottom: 20px; }
        #editModal .modal-body {
            flex: 1;
            display: flex;
            flex-direction: column;
            margin-bottom: 10px;
            overflow: hidden;
        }
        .modal-body input {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            margin-bottom: 15px;
        }
        .modal-footer {
            display: flex;
            gap: 10px;
            justify-content: flex-end;
        }
        .textarea-editor {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 0.9em;
            resize: vertical;
            min-height: 400px;
        }
        #editModal .textarea-editor {
            flex: 1;
            min-height: unset;
            height: 100%;
            resize: none;
        }
        .storage-info {
            background: rgba(102, 126, 234, 0.1);
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.9em;
        }
        .progress-bar {
            background: rgba(102, 126, 234, 0.2);
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        .progress-fill {
            height: 100%;
            background: var(--bg-gradient);
            transition: width 0.3s;
        }
        .toast {
            position: fixed;
            bottom: 20px;
            right: 20px;
            padding: 15px 20px;
            background: #333;
            color: white;
            border-radius: 6px;
            z-index: 2000;
            animation: slideIn 0.3s ease-out;
        }
        @keyframes slideIn {
            from { transform: translateX(400px); }
            to { transform: translateX(0); }
        }
        .toast.success { background: #48bb78; }
        .toast.error { background: #f56565; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📁 File Manager</h1>
            <p>Browse, upload, download, edit and manage your files</p>
        </div>
        <div class="content">
            <div class="storage-info">
                <div>Storage: <span id="storageUsed">0</span> / <span id="storageTotal">0</span> KB (<span id="storagePercent">0</span>%)</div>
                <div class="progress-bar">
                    <div class="progress-fill" id="progressBar" style="width: 0%"></div>
                </div>
            </div>
            
            <div class="toolbar">
                <button class="btn btn-primary btn-small" onclick="goUp()">⬆ Up</button>
                <div class="breadcrumb" id="breadcrumb">/</div>
                <button class="btn btn-primary btn-small" onclick="createFolder()">+ Folder</button>
                <button class="btn btn-primary btn-small" onclick="document.getElementById('fileInput').click()">⬆ Upload</button>
                <input type="file" id="fileInput" style="display:none" onchange="uploadFile()">
                <button class="btn btn-danger btn-small" onclick="shutdownServer()">⚠ Shutdown Server</button>
            </div>

            <div class="file-list" id="fileList">
                <div class="file-item"><div class="file-info">Loading...</div></div>
            </div>
        </div>
    </div>

    <!-- Create Folder Modal -->
    <div class="modal" id="folderModal">
        <div class="modal-content">
            <div class="modal-header">Create New Folder</div>
            <div class="modal-body">
                <input type="text" id="folderName" placeholder="Folder name">
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeFolderModal()">Cancel</button>
                <button class="btn btn-primary" onclick="confirmCreateFolder()">Create</button>
            </div>
        </div>
    </div>

    <!-- Edit File Modal -->
    <div class="modal" id="editModal">
        <div class="modal-content">
            <div class="modal-header" id="editTitle">Edit File</div>
            <div class="modal-body">
                <textarea class="textarea-editor" id="fileContent"></textarea>
            </div>
            <div class="modal-footer">
                <button class="btn" onclick="closeEditModal()">Cancel</button>
                <button class="btn btn-success" onclick="saveFile()">Save</button>
            </div>
        </div>
    </div>

    <script>
        let currentPath = '/';
        let editingFile = '';

        async function loadFiles() {
            try {
                const response = await fetch(`/api/files?path=${encodeURIComponent(currentPath)}`);
                const data = await response.json();
                
                if (!data.success) {
                    showToast('Error loading files', 'error');
                    return;
                }

                updateBreadcrumb();
                updateStorageInfo(data.storage);
                renderFiles(data.files);
            } catch (error) {
                showToast('Error loading files: ' + error.message, 'error');
            }
        }

        function updateBreadcrumb() {
            const container = document.getElementById('breadcrumb');
            const path = currentPath || '/';
            if (path === '/' || path === '') {
                container.textContent = '/';
                return;
            }

            // Build clickable breadcrumb segments
            const parts = path.split('/').filter(p => p.length > 0);
            let html = '<a href="#" onclick="goToPath(0)">/</a>';
            let accum = '';
            for (let i = 0; i < parts.length; i++) {
                accum += '/' + parts[i];
                html += ' <span>/</span> <a href="#" onclick="goToPath(' + (i + 1) + ')">' + escapeHtml(parts[i]) + '</a>';
            }
            container.innerHTML = html;
        }

        function goToPath(index) {
            // index 0 == root, index >0 correspond to parts index
            if (index === 0) {
                currentPath = '/';
            } else {
                const parts = (currentPath || '/').split('/').filter(p => p.length > 0);
                const newParts = parts.slice(0, index);
                currentPath = '/' + newParts.join('/');
            }
            loadFiles();
        }

        function goUp() {
            if (!currentPath || currentPath === '/' ) return;
            let p = currentPath;
            if (p.endsWith('/')) p = p.substring(0, p.length - 1);
            const last = p.lastIndexOf('/');
            if (last === -1) {
                currentPath = '/';
            } else if (last === 0) {
                currentPath = '/';
            } else {
                currentPath = p.substring(0, last);
            }
            loadFiles();
        }

        function updateStorageInfo(storage) {
            const used = Math.round(storage.used / 1024);
            const total = Math.round(storage.total / 1024);
            const percent = Math.round(storage.percent);
            
            document.getElementById('storageUsed').textContent = used;
            document.getElementById('storageTotal').textContent = total;
            document.getElementById('storagePercent').textContent = percent;
            document.getElementById('progressBar').style.width = percent + '%';
        }

        function renderFiles(files) {
            const fileList = document.getElementById('fileList');
            if (files.length === 0) {
                fileList.innerHTML = '<div class="file-item"><div class="file-info">No files or folders</div></div>';
                return;
            }

            fileList.innerHTML = files.map(file => `
                <div class="file-item">
                    <div class="file-info" onclick="handleItemClick('${file.name}', ${file.isDir})">
                        <div class="file-icon">${file.isDir ? '📁' : '📄'}</div>
                        <div class="file-details">
                            <div class="file-name">${escapeHtml(file.name)}</div>
                            <div class="file-meta">${file.isDir ? 'Folder' : formatSize(file.size)}</div>
                        </div>
                    </div>
                    <div class="file-actions">
                        ${!file.isDir && isTextFile(file.name) ? `<button class="btn btn-primary btn-small" onclick="editFile('${file.name}')">✏️ Edit</button>` : ''}
                        ${!file.isDir ? `<button class="btn btn-success btn-small" onclick="downloadFile('${file.name}')">⬇ Download</button>` : ''}
                        <button class="btn btn-danger btn-small" onclick="deleteItem('${file.name}', ${file.isDir})">🗑 Delete</button>
                    </div>
                </div>
            `).join('');
        }

        function handleItemClick(name, isDir) {
            if (isDir) {
                currentPath = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
                loadFiles();
            }
        }

        async function createFolder() {
            document.getElementById('folderModal').classList.add('active');
            document.getElementById('folderName').value = '';
            document.getElementById('folderName').focus();
        }

        function closeFolderModal() {
            document.getElementById('folderModal').classList.remove('active');
        }

        async function confirmCreateFolder() {
            const folderName = document.getElementById('folderName').value.trim();
            if (!folderName) {
                showToast('Folder name cannot be empty', 'error');
                return;
            }

            try {
                const response = await fetch('/api/create-folder', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: currentPath, name: folderName })
                });
                const data = await response.json();
                
                if (data.success) {
                    showToast('Folder created', 'success');
                    closeFolderModal();
                    loadFiles();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (error) {
                showToast('Error creating folder: ' + error.message, 'error');
            }
        }

        async function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            if (!fileInput.files.length) return;

            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append('file', file);
            formData.append('path', currentPath);

            try {
                const response = await fetch('/api/upload', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    showToast('File uploaded', 'success');
                    fileInput.value = '';
                    loadFiles();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (error) {
                showToast('Error uploading file: ' + error.message, 'error');
            }
        }

        async function downloadFile(name) {
            const path = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
            window.location.href = `/api/download?path=${encodeURIComponent(path)}`;
        }

        async function editFile(name) {
            const path = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
            editingFile = path;
            
            try {
                const response = await fetch(`/api/read-file?path=${encodeURIComponent(path)}`);
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('editTitle').textContent = 'Edit: ' + name;
                    document.getElementById('fileContent').value = data.content;
                    document.getElementById('editModal').classList.add('active');
                } else {
                    showToast('Error reading file: ' + data.error, 'error');
                }
            } catch (error) {
                showToast('Error reading file: ' + error.message, 'error');
            }
        }

        function closeEditModal() {
            document.getElementById('editModal').classList.remove('active');
            editingFile = '';
        }

        async function saveFile() {
            const content = document.getElementById('fileContent').value;
            
            try {
                const response = await fetch('/api/write-file', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ path: editingFile, content: content })
                });
                const data = await response.json();
                
                if (data.success) {
                    showToast('File saved', 'success');
                    closeEditModal();
                    loadFiles();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (error) {
                showToast('Error saving file: ' + error.message, 'error');
            }
        }

        async function deleteItem(name, isDir) {
            const path = currentPath.endsWith('/') ? currentPath + name : currentPath + '/' + name;
            if (!confirm(`Delete ${isDir ? 'folder' : 'file'}: ${name}?`)) return;
            
            try {
                const response = await fetch(`/api/delete?path=${encodeURIComponent(path)}&isDir=${isDir}`, {
                    method: 'DELETE'
                });
                const data = await response.json();
                
                if (data.success) {
                    showToast('Item deleted', 'success');
                    loadFiles();
                } else {
                    showToast('Error: ' + data.error, 'error');
                }
            } catch (error) {
                showToast('Error deleting item: ' + error.message, 'error');
            }
        }

        async function shutdownServer() {
            if (!confirm('Are you sure you want to shutdown the file manager server?')) return;
            
            try {
                await fetch('/api/shutdown', { method: 'POST' });
                showToast('Server shutting down...', 'success');
                setTimeout(() => {
                    window.location.href = 'about:blank';
                }, 1000);
            } catch (error) {
                showToast('Error: ' + error.message, 'error');
            }
        }

        function isTextFile(filename) {
            const textExtensions = ['.txt', '.md', '.json', '.js', '.css', '.html', '.cpp', '.h', '.c', '.py', '.log', '.conf'];
            return textExtensions.some(ext => filename.toLowerCase().endsWith(ext));
        }

        function formatSize(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
        }

        function escapeHtml(text) {
            const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
            return text.replace(/[&<>"']/g, m => map[m]);
        }

        function showToast(message, type = 'success') {
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.textContent = message;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 3000);
        }

        // Initial load
        loadFiles();
        loadSettings();
        setInterval(updateStorageInfo, 5000);

        function hexToRGB(hex) {
            // Remove # if present
            hex = hex.replace('#', '');
            // Handle 8-char hex (RRGGBBAA)
            if (hex.length === 8) hex = hex.substring(0, 6);
            const r = parseInt(hex.substring(0, 2), 16);
            const g = parseInt(hex.substring(2, 4), 16);
            const b = parseInt(hex.substring(4, 6), 16);
            return { r, g, b };
        }

        function isColorWhite(hexColor) {
            const rgb = hexToRGB(hexColor);
            // Consider it white if all components are > 240
            return rgb.r > 240 && rgb.g > 240 && rgb.b > 240;
        }

        function createGradient(hexColor) {
            const rgb = hexToRGB(hexColor);
            // Create a gradient from the color to a slightly darker version
            const darkerFactor = 0.85;
            const r = Math.max(0, Math.floor(rgb.r * darkerFactor));
            const g = Math.max(0, Math.floor(rgb.g * darkerFactor));
            const b = Math.max(0, Math.floor(rgb.b * darkerFactor));
            const darkerColor = `rgb(${r}, ${g}, ${b})`;
            return `linear-gradient(135deg, ${hexColor} 0%, ${darkerColor} 100%)`;
        }

        async function loadSettings() {
            try {
                const response = await fetch('/api/settings');
                const data = await response.json();
                if (data.bg_color) {
                    const gradient = createGradient(data.bg_color);
                    document.documentElement.style.setProperty('--bg-gradient', gradient);
                }
                if (data.tx_color && !isColorWhite(data.tx_color)) {
                    // Only apply text color if it's not white
                    document.documentElement.style.setProperty('--tx-color', data.tx_color);
                    document.documentElement.style.setProperty('color', data.tx_color);
                }
            } catch (error) {
                console.log('Could not load settings');
            }
        }
    </script>
</body>
</html>
)rawliteral";
  }

  // Helper function to get MIME type from filename
  static String getMimeType(const String& filename) {
    if (filename.endsWith(".html")) return "text/html";
    if (filename.endsWith(".css")) return "text/css";
    if (filename.endsWith(".js")) return "application/javascript";
    if (filename.endsWith(".json")) return "application/json";
    if (filename.endsWith(".txt")) return "text/plain";
    if (filename.endsWith(".md")) return "text/markdown";
    if (filename.endsWith(".png")) return "image/png";
    if (filename.endsWith(".jpg") || filename.endsWith(".jpeg")) return "image/jpeg";
    if (filename.endsWith(".gif")) return "image/gif";
    if (filename.endsWith(".pdf")) return "application/pdf";
    return "application/octet-stream";
  }

  // API: Get file list
  static void handleListFiles(AsyncWebServerRequest *request) {
    String path = request->hasParam("path") ? request->getParam("path")->value() : "/";
    
    DynamicJsonDocument doc(JSON_BUFFER_SIZE);
    doc["success"] = true;
    JsonArray filesArray = doc.createNestedArray("files");
    
    File dir = FSYS.open(path);
    if (!dir || !dir.isDirectory()) {
      doc["success"] = false;
      doc["error"] = "Directory not found";
      String response;
      serializeJson(doc, response);
      request->send(200, "application/json", response);
      return;
    }

    File file = dir.openNextFile();
    while (file) {
      JsonObject fileObj = filesArray.createNestedObject();
      fileObj["name"] = file.name();
      fileObj["isDir"] = file.isDirectory();
      fileObj["size"] = file.size();
      file = dir.openNextFile();
    }

    // Add storage info
    JsonObject storage = doc.createNestedObject("storage");
    uint32_t totalBytes = FSYS.totalBytes();
    uint32_t usedBytes = FSYS.usedBytes();
    storage["total"] = totalBytes;
    storage["used"] = usedBytes;
    storage["percent"] = (usedBytes * 100) / totalBytes;

    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
  }

  // API: Upload file
  static void handleUpload(AsyncWebServerRequest *request, const String& filename, size_t index, uint8_t *data, size_t len, bool final) {
    String path = request->hasParam("path") ? request->getParam("path")->value() : "/";
    String filePath = path;
    if (!filePath.endsWith("/")) filePath += "/";
    filePath += filename;

    if (index == 0) {
      logMessage("Starting upload: " + filePath);
    }

    File file = FSYS.open(filePath, index == 0 ? "w" : "a");
    if (file) {
      file.write(data, len);
      file.close();
    }

    if (final) {
      logMessage("Upload complete: " + filePath);
      DynamicJsonDocument doc(256);
      doc["success"] = true;
      doc["message"] = "File uploaded successfully";
      String response;
      serializeJson(doc, response);
      request->send(200, "application/json", response);
    }
  }

  // API: Create folder
  static void handleCreateFolder(AsyncWebServerRequest *request, const JsonVariant &json) {
    if (!json.is<JsonObject>()) {
      DynamicJsonDocument doc(256);
      doc["success"] = false;
      doc["error"] = "Invalid request";
      String response;
      serializeJson(doc, response);
      request->send(400, "application/json", response);
      return;
    }

    String path = json["path"];
    String name = json["name"];
    
    String fullPath = path;
    if (!fullPath.endsWith("/")) fullPath += "/";
    fullPath += name;

    if (FSYS.mkdir(fullPath)) {
      logMessage("Folder created: " + fullPath);
      DynamicJsonDocument doc(256);
      doc["success"] = true;
      String response;
      serializeJson(doc, response);
      request->send(200, "application/json", response);
    } else {
      DynamicJsonDocument doc(256);
      doc["success"] = false;
      doc["error"] = "Failed to create folder";
      String response;
      serializeJson(doc, response);
      request->send(400, "application/json", response);
    }
  }

  // API: Read file
  static void handleReadFile(AsyncWebServerRequest *request) {
    String path = request->hasParam("path") ? request->getParam("path")->value() : "/";
    
    File file = FSYS.open(path, "r");
    if (!file) {
      DynamicJsonDocument doc(256);
      doc["success"] = false;
      doc["error"] = "File not found";
      String response;
      serializeJson(doc, response);
      request->send(404, "application/json", response);
      return;
    }

    DynamicJsonDocument doc(JSON_BUFFER_SIZE);
    doc["success"] = true;
    doc["content"] = file.readString();
    
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
    file.close();
  }

  // API: Write file
  static void handleWriteFile(AsyncWebServerRequest *request, const JsonVariant &json) {
    if (!json.is<JsonObject>()) {
      DynamicJsonDocument doc(256);
      doc["success"] = false;
      doc["error"] = "Invalid request";
      String response;
      serializeJson(doc, response);
      request->send(400, "application/json", response);
      return;
    }

    String path = json["path"];
    String content = json["content"];

    File file = FSYS.open(path, "w");
    if (!file) {
      DynamicJsonDocument doc(256);
      doc["success"] = false;
      doc["error"] = "Failed to open file";
      String response;
      serializeJson(doc, response);
      request->send(400, "application/json", response);
      return;
    }

    file.print(content);
    file.close();
    
    logMessage("File saved: " + path);
    DynamicJsonDocument doc(256);
    doc["success"] = true;
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
  }

  // API: Download file
  static void handleDownload(AsyncWebServerRequest *request) {
    String path = request->hasParam("path") ? request->getParam("path")->value() : "/";
    
    File file = FSYS.open(path, "r");
    if (!file) {
      request->send(404, "text/plain", "File not found");
      return;
    }

    String filename = path;
    int lastSlash = filename.lastIndexOf('/');
    if (lastSlash != -1) {
      filename = filename.substring(lastSlash + 1);
    }

    request->send(file, path, "application/octet-stream", true);
  }

  // API: Delete item
  static void handleDelete(AsyncWebServerRequest *request) {
    String path = request->hasParam("path") ? request->getParam("path")->value() : "/";
    bool isDir = request->hasParam("isDir") ? request->getParam("isDir")->value() == "true" : false;

    bool success = false;
    if (isDir) {
      success = FSYS.rmdir(path);
    } else {
      success = FSYS.remove(path);
    }

    DynamicJsonDocument doc(256);
    if (success) {
      logMessage("Deleted: " + path);
      doc["success"] = true;
      String response;
      serializeJson(doc, response);
      request->send(200, "application/json", response);
    } else {
      doc["success"] = false;
      doc["error"] = "Failed to delete";
      String response;
      serializeJson(doc, response);
      request->send(400, "application/json", response);
    }
  }

  // API: Shutdown server
  static void handleShutdown(AsyncWebServerRequest *request) {
    DynamicJsonDocument doc(256);
    doc["success"] = true;
    doc["message"] = "Server shutting down";
    String response;
    serializeJson(doc, response);
    request->send(200, "application/json", response);
    
    logMessage("Web File Manager shutdown requested");
    
    // Schedule shutdown after response is sent
    delay(100);
    end();
  }


  bool begin(int /*pinD_minus*/, int /*pinD_plus*/) {
    if (is_active) {
      return true;
    }

    if (!web_server) {
      web_server = new AsyncWebServer(WEB_SERVER_PORT);
      
      // Serve main UI
      web_server->on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
        request->send_P(200, "text/html", getIndexHTML());
      });

      // API: Get settings colors
      web_server->on("/api/settings", HTTP_GET, [](AsyncWebServerRequest *request) {
        DynamicJsonDocument doc(256);
        doc["bg_color"] = bg_color;
        doc["tx_color"] = tx_color;
        String response;
        serializeJson(doc, response);
        request->send(200, "application/json", response);
      });

      // API endpoints
      web_server->on("/api/files", HTTP_GET, handleListFiles);
      
      web_server->on("/api/upload", HTTP_POST, 
        [](AsyncWebServerRequest *request) {
          // Handled by onFileUpload
        },
        [](AsyncWebServerRequest *request, const String& filename, size_t index, uint8_t *data, size_t len, bool final) {
          handleUpload(request, filename, index, data, len, final);
        }
      );

      web_server->on("/api/create-folder", HTTP_POST, [](AsyncWebServerRequest *request) {
        // Handled by onBody
      }, nullptr, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
        DynamicJsonDocument doc(JSON_BUFFER_SIZE);
        deserializeJson(doc, (const char*)data);
        handleCreateFolder(request, doc.as<JsonVariant>());
      });

      web_server->on("/api/read-file", HTTP_GET, handleReadFile);

      web_server->on("/api/write-file", HTTP_POST, [](AsyncWebServerRequest *request) {
        // Handled by onBody
      }, nullptr, [](AsyncWebServerRequest *request, uint8_t *data, size_t len, size_t index, size_t total) {
        DynamicJsonDocument doc(JSON_BUFFER_SIZE);
        deserializeJson(doc, (const char*)data);
        handleWriteFile(request, doc.as<JsonVariant>());
      });

      web_server->on("/api/download", HTTP_GET, handleDownload);

      web_server->on("/api/delete", HTTP_DELETE, handleDelete);

      web_server->on("/api/shutdown", HTTP_POST, handleShutdown);

      // 404 handler
      web_server->onNotFound([](AsyncWebServerRequest *request) {
        request->send(404, "text/plain", "Not Found");
      });
    }

    web_server->begin();
    is_active = true;
    logMessage("Web File Manager started on port " + String(WEB_SERVER_PORT));

    return true;
  }

  void end() {
    if (is_active && web_server) {
      web_server->end();
      is_active = false;
      logMessage("Web File Manager stopped");
    }
    
    if (web_server) {
      delete web_server;
      web_server = nullptr;
    }
  }

  bool isActive() {
    return is_active;
  }
}
