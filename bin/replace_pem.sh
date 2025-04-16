#!/bin/bash

# Usage: ./replace_cert.sh <binary> <pem_file>
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <binary> <pem_file>"
    exit 1
fi

BINARY="$1"
PEM_FILE="$2"

# Extract the new certificate base64 string from the PEM file by removing header/footer and whitespace.
NEW_CERT=$(sed -e '/-----BEGIN CERTIFICATE-----/d' -e '/-----END CERTIFICATE-----/d' "$PEM_FILE" | tr -d '\n\r')
NEW_LEN=${#NEW_CERT}

if [ $NEW_LEN -eq 0 ]; then
    echo "Error: No certificate data found in $PEM_FILE."
    exit 1
fi

# Locate the old certificate string in the binary.
# This assumes the certificate in the binary starts with "MIIFC" (as in your example).
OLD_CERT=$(strings "$BINARY" | grep 'MIIFC')
if [ -z "$OLD_CERT" ]; then
    echo "Error: Could not find the old certificate string in $BINARY."
    exit 1
fi
OLD_LEN=${#OLD_CERT}

echo "Old certificate length: $OLD_LEN"
echo "New certificate length: $NEW_LEN"

if [ "$NEW_LEN" -gt "$OLD_LEN" ]; then
    echo "Error: New certificate is longer than the old certificate in the binary. Aborting."
    exit 1
fi

# Pad the new certificate with null bytes (0x00) so that it is exactly the same length as the old one.
PAD_LENGTH=$((OLD_LEN - NEW_LEN))
# Generate PAD_LENGTH null bytes. (Note: This uses printf in a loop.)
PAD=""
for ((i=0; i<PAD_LENGTH; i++)); do
    PAD="${PAD}\0"
done

# Concatenate the new certificate and padding.
# The final replacement string will be a binary string (with embedded nulls).
REPLACEMENT="${NEW_CERT}${PAD}"

# For our in-place replacement we'll work in hex.
# Convert the old certificate (which is ASCII) to its hex representation.
OLD_CERT_HEX=$(echo -n "$OLD_CERT" | xxd -p -c 9999)
# Convert the replacement string to hex. Use printf %s to avoid issues with embedded nulls.
REPLACEMENT_HEX=$(printf "%s" "$REPLACEMENT" | xxd -p -c 9999)

echo "OLD_CERT_HEX: $OLD_CERT_HEX"
echo "REPLACEMENT_HEX: $REPLACEMENT_HEX"

# Dump the binary to a hex file.
xxd -p "$BINARY" > binary.hex

# Use perl to do the replacement in the hex dump.
# \Q and \E are used to quote the OLD_CERT_HEX so that special regex characters are treated literally.
perl -pe "s/\Q${OLD_CERT_HEX}\E/${REPLACEMENT_HEX}/g" binary.hex > binary_new.hex

# Convert the modified hex dump back into a binary.
xxd -r -p binary_new.hex > "${BINARY}.patched"

echo "Certificate replaced in ${BINARY}.patched"

# Cleanup temporary files.
rm binary.hex binary_new.hex

