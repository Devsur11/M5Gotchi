#!/bin/bash
set -e

REPO_URL="https://devsur11.github.io/M5Gotchi/firmware"

read -p "Enter firmware version (e.g., 0.3.1): " VERSION

# Function to cleanup and exit
cleanup() {
    # Clear any build flags containing credentials
    # Unset environment variables
    unset MQTT_USERNAME
    unset MQTT_PASSWORD
    unset MQTT_HOST
    unset MQTT_PORT
}

# Ensure cleanup runs even if script is interrupted
trap cleanup EXIT

# Read MQTT credentials securely
read -p "Enter MQTT username: " MQTT_USERNAME
read -p "Enter MQTT password: " MQTT_PASSWORD
echo
read -p "Enter MQTT host: " MQTT_HOST
read -p "Enter MQTT port [1883]: " MQTT_PORT
MQTT_PORT=${MQTT_PORT:-1883}

# Validate input
if [ -z "$MQTT_USERNAME" ] || [ -z "$MQTT_PASSWORD" ] || [ -z "$MQTT_HOST" ]; then
    echo "Error: All fields except port are required"
    exit 1
fi

# Export credentials as build flags
export PLATFORMIO_BUILD_FLAGS="$PLATFORMIO_BUILD_FLAGS -DMQTT_USERNAME='\"$MQTT_USERNAME\"' -DMQTT_PASSWORD='\"$MQTT_PASSWORD\"' -DMQTT_HOST='\"$MQTT_HOST\"' -DMQTT_PORT=$MQTT_PORT -DENABLE_COREDUMP_LOGGING -DCURRENT_VERSION='\"$VERSION\"'"

# Determine environments to build: if no argument provided, build all known envs
if [ -z "$1" ]; then
    ENVS=("Cardputer-dev" "Cardputer-full")
else
    ENVS=("$1")
fi

echo "Building for environment(s): ${ENVS[*]}"

read -p "Would you like to upload the firmware after building? (y/n): " UPLOAD_CHOICE
if [[ "$UPLOAD_CHOICE" =~ ^[Yy]$ ]]; then
    UPLOAD=true
else
    UPLOAD=false
fi

# Build (and optionally upload) for each selected environment
for ENV in "${ENVS[@]}"; do
    echo "=> Processing environment: $ENV"
    if [ "$UPLOAD" = true ]; then
        pio run --target upload -e "$ENV" || { echo "Upload failed for $ENV"; exit 1; }
    else
        pio run -e "$ENV" || { echo "Build failed for $ENV"; exit 1; }
    fi
done

mkdir -p firmware

FULL_BIN_PATH=$(find .pio/build/Cardputer-full/ -type f -name "firmware.bin" | head -n 1)
if [ ! -f "$FULL_BIN_PATH" ]; then
    echo "❌ Full firmware.bin not found!"
    exit 1
fi
cp "$FULL_BIN_PATH" ../firmware/firmware.bin
echo "✅ Full firmware copied to firmware/firmware.bin"

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


esptool.py --chip esp32s3 merge_bin -o full.bin   --flash_mode dio   --flash_freq 80m   --flash_size 8MB   0x0000 .pio/build/Cardputer-full/bootloader.bin   0x8000 .pio/build/Cardputer-full/partitions.bin   0xE000 ../../Documents/boot_app0.bin   0x10000 .pio/build/Cardputer-full/firmware.bin

echo "✅ Metadata files with full download URLs created"

git tag -a "v$VERSION"