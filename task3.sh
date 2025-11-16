#!/bin/bash

# task3.sh - Key Re-wrapping for Secure File Sharing

set -e

# Cleanup function to remove all temporary files
cleanup() {
    rm -rf "$TEMP_DIR"
    rm -f file_hash_$$.bin
}

# Error handling function
error_exit() {
    echo "ERROR mong.e: $1" >&2
    cleanup
    exit 1
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Validate arguments
[ "$#" -ne 7 ] && error_exit "Usage: $0 <zip_filename> <generator_priv> <original_sender_pub> <receiver1_pub> <receiver2_pub> <receiver3_pub> <new_zip_filename>"

ZIP_FILENAME="$1"
GENERATOR_PRIV="$2"
ORIGINAL_SENDER_PUB="$3"
RECEIVER1_PUB="$4"
RECEIVER2_PUB="$5"
RECEIVER3_PUB="$6"
NEW_ZIP_FILENAME="$7"

TEMP_DIR="temp_rewrap_$$"

# Validate input files
[ ! -f "$ZIP_FILENAME" ] && error_exit "Zip file not found"
[ ! -f "$GENERATOR_PRIV" ] && error_exit "Generator private key not found"
[ ! -f "$ORIGINAL_SENDER_PUB" ] && error_exit "Original sender public key not found"
[ ! -f "$RECEIVER1_PUB" ] && error_exit "Receiver 1 public key not found"
[ ! -f "$RECEIVER2_PUB" ] && error_exit "Receiver 2 public key not found"
[ ! -f "$RECEIVER3_PUB" ] && error_exit "Receiver 3 public key not found"

# Step 1: Extract files from original zip
mkdir -p "$TEMP_DIR" || error_exit "Failed to create temporary directory"
unzip -q "$ZIP_FILENAME" -d "$TEMP_DIR" || error_exit "Failed to unzip file"

# Locate required files
ENCRYPTED_FILE=$(find "$TEMP_DIR" -name "encrypted_file.enc" -type f | head -1)
SIGNATURE=$(find "$TEMP_DIR" -name "signature.bin" -type f | head -1)

[ -z "$ENCRYPTED_FILE" ] && error_exit "Encrypted file not found in zip"
[ -z "$SIGNATURE" ] && error_exit "Signature file not found in zip"

# Step 2: Verify original sender's signature
openssl dgst -sha256 -binary -out file_hash_$$.bin "$ENCRYPTED_FILE" || \
    error_exit "Failed to hash encrypted file"

openssl pkeyutl -verify -pubin -inkey "$ORIGINAL_SENDER_PUB" \
    -in file_hash_$$.bin -sigfile "$SIGNATURE" || \
    error_exit "Signature verification failed"

# Step 3: Perform ECDH to get shared secret
SHARED_SECRET="$TEMP_DIR/shared_secret_received_$$.bin"
openssl pkeyutl -derive \
    -inkey "$GENERATOR_PRIV" \
    -peerkey "$ORIGINAL_SENDER_PUB" \
    -out "$SHARED_SECRET" || \
    error_exit "ECDH key exchange failed"

# Step 4: Try to decrypt each envelope to get the session key
SESSION_KEY_FILE="$TEMP_DIR/session_key_recovered_$$.bin"
SESSION_KEY_FOUND=0

for i in 1 2 3; do
    ENVELOPE=$(find "$TEMP_DIR" -name "envelope_${i}.enc" -type f | head -1)
    
    if [ ! -f "$ENVELOPE" ]; then
        continue
    fi
    
    # Get file size to calculate where salt starts (last 8 bytes are salt)
    ENVELOPE_SIZE=$(wc -c < "$ENVELOPE")
    ENCRYPTED_KEY_SIZE=$((ENVELOPE_SIZE - 8))
    
    # Extract encrypted session key (all bytes except last 8)
    head -c $ENCRYPTED_KEY_SIZE "$ENVELOPE" > "$TEMP_DIR/encrypted_session_key_extracted_$$.bin"
    
    # Extract salt (last 8 bytes)
    tail -c 8 "$ENVELOPE" > "$TEMP_DIR/salt_extracted_$$.bin"
    
    # Try to decrypt envelope using PBKDF2-derived key from shared secret
    if openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 \
        -S $(xxd -p "$TEMP_DIR/salt_extracted_$$.bin" | tr -d '\n') \
        -in "$TEMP_DIR/encrypted_session_key_extracted_$$.bin" \
        -out "$SESSION_KEY_FILE" \
        -pass file:"$SHARED_SECRET" 2>/dev/null; then
        
        # Verify recovered session key is valid (32 bytes for AES-256)
        if [ -s "$SESSION_KEY_FILE" ]; then
            KEY_SIZE=$(wc -c < "$SESSION_KEY_FILE")
            if [ "$KEY_SIZE" -eq 32 ]; then
                SESSION_KEY_FOUND=1
                break
            fi
        fi
    fi
    
    # Clean up failed attempt
    rm -f "$SESSION_KEY_FILE" "$TEMP_DIR/encrypted_session_key_extracted_$$.bin" "$TEMP_DIR/salt_extracted_$$.bin"
done

[ $SESSION_KEY_FOUND -eq 0 ] && error_exit "Failed to decrypt envelope"

# Step 5: Create new envelopes for new receivers
create_envelope() {
    local RECEIVER_NUM=$1
    local RECEIVER_PUB=$2
    local OUTPUT_ENVELOPE="$3"
    
    # Perform ECDH: generator_priv + receiver_pub = shared_secret
    local SHARED_SECRET_NEW="$TEMP_DIR/shared_secret_${RECEIVER_NUM}_$$.bin"
    openssl pkeyutl -derive \
        -inkey "$GENERATOR_PRIV" \
        -peerkey "$RECEIVER_PUB" \
        -out "$SHARED_SECRET_NEW" || return 1
    
    # Generate random 8-byte salt for PBKDF2
    local SALT_FILE="$TEMP_DIR/salt_${RECEIVER_NUM}_$$.bin"
    openssl rand 8 > "$SALT_FILE" || return 1
    
    # Encrypt session key using PBKDF2-derived key from shared secret
    local ENCRYPTED_SESSION_KEY="$TEMP_DIR/encrypted_session_key_${RECEIVER_NUM}_$$.bin"
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -md sha256 \
        -S $(xxd -p "$SALT_FILE" | tr -d '\n') \
        -in "$SESSION_KEY_FILE" \
        -out "$ENCRYPTED_SESSION_KEY" \
        -pass file:"$SHARED_SECRET_NEW" || return 1
    
    # Create envelope: encrypted_session_key + salt (concatenate them)
    cat "$ENCRYPTED_SESSION_KEY" "$SALT_FILE" > "$OUTPUT_ENVELOPE" || return 1
    
    # Clean up intermediate files
    rm -f "$SHARED_SECRET_NEW" "$SALT_FILE" "$ENCRYPTED_SESSION_KEY"
    
    return 0
}

NEW_TEMP_DIR="$TEMP_DIR/new_package"
mkdir -p "$NEW_TEMP_DIR"

NEW_ENVELOPE1="$NEW_TEMP_DIR/envelope_1.enc"
NEW_ENVELOPE2="$NEW_TEMP_DIR/envelope_2.enc"
NEW_ENVELOPE3="$NEW_TEMP_DIR/envelope_3.enc"

create_envelope 1 "$RECEIVER1_PUB" "$NEW_ENVELOPE1" || \
    error_exit "Failed to create envelope for receiver 1"

create_envelope 2 "$RECEIVER2_PUB" "$NEW_ENVELOPE2" || \
    error_exit "Failed to create envelope for receiver 2"

create_envelope 3 "$RECEIVER3_PUB" "$NEW_ENVELOPE3" || \
    error_exit "Failed to create envelope for receiver 3"

# Step 6: Assemble new zip file
cp "$ENCRYPTED_FILE" "$NEW_TEMP_DIR/encrypted_file.enc"
cp "$SIGNATURE" "$NEW_TEMP_DIR/signature.bin"

cd "$NEW_TEMP_DIR" || error_exit "Failed to change directory"
zip -q "../../$NEW_ZIP_FILENAME" \
    encrypted_file.enc \
    signature.bin \
    envelope_1.enc \
    envelope_2.enc \
    envelope_3.enc || \
    error_exit "Failed to create new zip file"
cd ../.. || exit 1

echo "Key re-wrapping completed successfully"
exit 0
