#!/bin/bash

set -e

REPO_URL="https://devsur11.github.io/M5Gotchi/firmware"

# Step 1: Ask user to compile full version manually
echo "🛠️  Please compile the FULL version of your firmware now (press Enter when done)..."
read -r

# Step 2: Ask for version
read -p "📄 Enter firmware version (e.g., 0.3.1): " VERSION

# Step 3: Create output folder if it doesn't exist
mkdir -p firmware

# Step 4: Copy firmware binary to /firmware/firmware.bin
FULL_BIN_PATH=$(find .pio/build -type f -name "firmware.bin" | head -n 1)
if [ ! -f "$FULL_BIN_PATH" ]; then
    echo "❌ Full firmware.bin not found!"
    exit 1
fi
cp "$FULL_BIN_PATH" firmware/firmware.bin
echo "✅ Full firmware copied to firmware/firmware.bin"

# Step 5: Ask user to compile lite version manually
echo "🛠️  Please compile the LITE version of your firmware now (press Enter when done)..."
read -r

# Step 6: Copy lite binary to /firmware/lite.bin
LITE_BIN_PATH=$(find .pio/build -type f -name "firmware.bin" | head -n 1)
if [ ! -f "$LITE_BIN_PATH" ]; then
    echo "❌ Lite firmware.bin not found!"
    exit 1
fi
cp "$LITE_BIN_PATH" firmware/lite.bin
echo "✅ Lite firmware copied to firmware/lite.bin"

# Step 7: Create firmware.json with full URL
DATE=$(date +%F)
cat <<EOF > firmware/firmware.json
{
  "version": "$VERSION",
  "file": "$REPO_URL/firmware.bin",
  "date": "$DATE",
  "notes": "Full version"
}
EOF

# Step 8: Create lite.json with full URL
cat <<EOF > firmware/lite.json
{
  "version": "$VERSION",
  "file": "$REPO_URL/lite.bin",
  "date": "$DATE",
  "notes": "Lite version"
}
EOF

echo "✅ Metadata files with full download URLs created"