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


# Ask about coredump logging
read -p "Compile with coredump logging? (y/n): " COREDUMP_CHOICE
if [[ "$COREDUMP_CHOICE" =~ ^[Yy]$ ]]; then
    COREDUMP_FLAG="-DENABLE_COREDUMP_LOGGING"
else
    COREDUMP_FLAG=""
fi

# Export credentials as build flags
export PLATFORMIO_BUILD_FLAGS="$PLATFORMIO_BUILD_FLAGS -DMQTT_USERNAME='\"$MQTT_USERNAME\"' -DMQTT_PASSWORD='\"$MQTT_PASSWORD\"' -DMQTT_HOST='\"$MQTT_HOST\"' -DMQTT_PORT=$MQTT_PORT -DCURRENT_VERSION='\"$VERSION\"' $COREDUMP_FLAG"

# Determine environments to build: if no argument provided, build all known envs
if [ -z "$1" ]; then
    ENVS=("Cardputer-dev" "Cardputer-full" "m5sticks3")
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

# Process Cardputer-full
FULL_BIN_PATH=$(find .pio/build/Cardputer-full/ -type f -name "firmware.bin" | head -n 1)
if [ ! -f "$FULL_BIN_PATH" ]; then
    echo "❌ Full firmware.bin not found!"
    exit 1
fi
cp "$FULL_BIN_PATH" firmware/firmware.bin
echo "✅ Full firmware copied to firmware/firmware.bin"

cat <<EOF > firmware/firmware.json
{
  "version": "$VERSION",
  "file": "$REPO_URL/firmware.bin",
  "date": "$(date +%F)",
  "notes": "Full version"
}
EOF

# Process M5StickS3
M5STICKS3_BIN_PATH=$(find .pio/build/m5sticks3/ -type f -name "firmware.bin" | head -n 1)
if [ ! -f "$M5STICKS3_BIN_PATH" ]; then
    echo "❌ M5StickS3 firmware.bin not found!"
    exit 1
fi
cp "$M5STICKS3_BIN_PATH" firmware/m5sticks3.bin
echo "✅ M5StickS3 firmware copied to firmware/m5sticks3.bin"

cat <<EOF > firmware/m5sticks3.json
{
  "version": "$VERSION",
  "file": "$REPO_URL/m5sticks3.bin",
  "date": "$(date +%F)",
  "notes": "M5StickS3 version"
}
EOF

esptool.py --chip esp32s3 merge_bin -o cardputer.bin --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0000 .pio/build/Cardputer-full/bootloader.bin 0x8000 .pio/build/Cardputer-full/partitions.bin 0xE000 ../../Documents/boot_app0.bin 0x10000 .pio/build/Cardputer-full/firmware.bin
esptool.py --chip esp32s3 merge_bin -o m5stick.bin --flash_mode dio --flash_freq 80m --flash_size 8MB 0x0000 .pio/build/m5sticks3/bootloader.bin 0x8000 .pio/build/m5sticks3/partitions.bin 0xE000 ../../Documents/boot_app0.bin 0x10000 .pio/build/m5sticks3/firmware.bin

echo "✅ Metadata files with full download URLs created"

git tag -a "v$VERSION"
