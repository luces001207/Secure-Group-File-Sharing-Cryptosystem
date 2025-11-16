#!/bin/bash

# task1.sh - Secure Group File Sharing with ECDH, PBKDF2, and ECDSA

set -e

# Error handling function
error_exit() {
    echo "ERROR mong.e: $1" >&2
    cleanup
    exit 1
}

# Cleanup function to remove all temporary files
cleanup() {
    rm -f session_key_$$.bin encrypted_file_$$.bin signature_$$.bin \
          envelope_*_$$.bin shared_secret_*_$$.bin salt_*_$$.bin \
          encrypted_session_key_*_$$.bin \
          encrypted_file.enc envelope_*.enc signature.bin \
          shared_secret_received_$$.bin session_key_recovered_$$.bin \
          salt_extracted_$$.bin encrypted_session_key_extracted_$$.bin 
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

#############################################
# SENDER MODE
#############################################

if [ "$1" == "-sender" ]; then
    
    # Validate arguments
    [ "$#" -ne 7 ] && error_exit "Usage: $0 -sender <receiver1_pub> <receiver2_pub> <receiver3_pub> <sender_priv> <plaintext_file> <zip_filename>"
    
    RECEIVER1_PUB="$2"
    RECEIVER2_PUB="$3"
    RECEIVER3_PUB="$4"
    SENDER_PRIV="$5"
    PLAINTEXT_FILE="$6"
    ZIP_FILENAME="$7"
    
    # Validate input files
    [ ! -f "$RECEIVER1_PUB" ] && error_exit "Receiver1 public key not found"
    [ ! -f "$RECEIVER2_PUB" ] && error_exit "Receiver2 public key not found"
    [ ! -f "$RECEIVER3_PUB" ] && error_exit "Receiver3 public key not found"
    [ ! -f "$SENDER_PRIV" ] && error_exit "Sender private key not found"
    [ ! -f "$PLAINTEXT_FILE" ] && error_exit "Plaintext file not found"
    
    # Step 1: Generate random 256-bit session key
    openssl rand 32 > session_key_$$.bin || error_exit "Failed to generate session key"
    
    # Step 2: Encrypt file with AES-256-CBC using session key
    openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -md sha256 \
        -in "$PLAINTEXT_FILE" \
        -out encrypted_file_$$.bin \
        -pass file:session_key_$$.bin || error_exit "Failed to encrypt file"
    
    # Step 3: Sign the encrypted file with ECDSA (secp256r1)
    openssl dgst -sha256 -sign "$SENDER_PRIV" \
        -out signature_$$.bin \
        encrypted_file_$$.bin || error_exit "Failed to sign file"
    
    # Step 4: Create cryptographic envelope for each receiver
    for i in 1 2 3; do

        # Get receiver's public key
        eval RECEIVER_PUB=\$RECEIVER${i}_PUB
        
        # Perform ECDH: sender_private + receiver_public = shared_secret
        openssl pkeyutl -derive \
            -inkey "$SENDER_PRIV" \
            -peerkey "$RECEIVER_PUB" \
            -out shared_secret_${i}_$$.bin || \
            error_exit "ECDH failed for receiver $i"
        
        # Generate random 8-byte salt for PBKDF2
        openssl rand 8 > salt_${i}_$$.bin || error_exit "Failed to generate salt for receiver $i"
        
        # Encrypt session key using PBKDF2-derived key from shared secret
        openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 -md sha256 \
            -S $(xxd -p salt_${i}_$$.bin | tr -d '\n') \
            -in session_key_$$.bin \
            -out encrypted_session_key_${i}_$$.bin \
            -pass file:shared_secret_${i}_$$.bin || \
            error_exit "Failed to encrypt session key for receiver $i"
        
        # Create envelope: encrypted_session_key + salt (concatenate them)
        cat encrypted_session_key_${i}_$$.bin salt_${i}_$$.bin > envelope_${i}_$$.bin || \
            error_exit "Failed to create envelope for receiver $i"
        
        # Clean up intermediate files
        rm -f shared_secret_${i}_$$.bin salt_${i}_$$.bin encrypted_session_key_${i}_$$.bin
    done
    
    # Step 5: Prepare files for zip
    cp encrypted_file_$$.bin encrypted_file.enc
    cp signature_$$.bin signature.bin
    cp envelope_1_$$.bin envelope_1.enc
    cp envelope_2_$$.bin envelope_2.enc
    cp envelope_3_$$.bin envelope_3.enc
    
    # Step 6: Create zip package
    zip -q -j "$ZIP_FILENAME" \
        encrypted_file.enc \
        signature.bin \
        envelope_1.enc \
        envelope_2.enc \
        envelope_3.enc || error_exit "Failed to create zip"
    
    # Clean up final temporary files
    rm -f encrypted_file.enc signature.bin envelope_*.enc 
    
    echo "[SENDER] Encryption completed successfully. Output: $ZIP_FILENAME"

#############################################
# RECEIVER MODE
#############################################

elif [ "$1" == "-receiver" ]; then
    
    # Validate arguments
    [ "$#" -ne 5 ] && error_exit "Usage: $0 -receiver <receiver_priv> <sender_pub> <zip_file> <plaintext_file>"
    
    RECEIVER_PRIV="$2"
    SENDER_PUB="$3"
    ZIP_FILE="$4"
    PLAINTEXT_FILE="$5"
    
    # Validate input files
    [ ! -f "$RECEIVER_PRIV" ] && error_exit "Receiver private key not found"
    [ ! -f "$SENDER_PUB" ] && error_exit "Sender public key not found"
    [ ! -f "$ZIP_FILE" ] && error_exit "Zip file not found"
    
    # Step 1: Extract zip file
    unzip -q -o "$ZIP_FILE" || error_exit "Failed to extract zip"
    
    # Validate extracted files
    [ ! -f "encrypted_file.enc" ] && error_exit "Missing encrypted_file.enc in zip"
    [ ! -f "signature.bin" ] && error_exit "Missing signature.bin in zip"
    
    # Step 2: Verify sender's signature BEFORE decryption (authenticity check)
    if ! openssl dgst -sha256 -verify "$SENDER_PUB" \
        -signature signature.bin \
        encrypted_file.enc; then
        error_exit "Signature verification failed! File may be tampered or from wrong sender."
    fi
    
    # Step 3: Perform ECDH to derive shared secret
    openssl pkeyutl -derive \
        -inkey "$RECEIVER_PRIV" \
        -peerkey "$SENDER_PUB" \
        -out shared_secret_received_$$.bin || \
        error_exit "ECDH key exchange failed"
    
    # Step 4: Try to decrypt each envelope
    SESSION_KEY_FOUND=0
    
    for i in 1 2 3; do
        # Check if envelope exists
        if [ ! -f "envelope_${i}.enc" ]; then
            continue
        fi

        # Get file size to calculate where salt starts (last 8 bytes are salt)
        ENVELOPE_SIZE=$(wc -c < "envelope_${i}.enc")
        ENCRYPTED_KEY_SIZE=$((ENVELOPE_SIZE - 8))
        
        # Extract encrypted session key (all bytes except last 8)
        head -c $ENCRYPTED_KEY_SIZE "envelope_${i}.enc" > encrypted_session_key_extracted_$$.bin
        
        # Extract salt (last 8 bytes)
        tail -c 8 "envelope_${i}.enc" > salt_extracted_$$.bin
        
        # Try to decrypt envelope using PBKDF2-derived key from shared secret
        if openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 \
            -S $(xxd -p salt_extracted_$$.bin | tr -d '\n') \
            -in encrypted_session_key_extracted_$$.bin \
            -out session_key_recovered_$$.bin \
            -pass file:shared_secret_received_$$.bin 2>/dev/null; then
            
            # Verify recovered session key is valid (32 bytes for AES-256)
            if [ -s session_key_recovered_$$.bin ]; then
                KEY_SIZE=$(wc -c < session_key_recovered_$$.bin)
                if [ "$KEY_SIZE" -eq 32 ]; then
                    SESSION_KEY_FOUND=1
                    break
                fi
            fi
        fi
        
        # Clean up failed attempt
        rm -f session_key_recovered_$$.bin encrypted_session_key_extracted_$$.bin salt_extracted_$$.bin
    done
    
    [ $SESSION_KEY_FOUND -eq 0 ] && error_exit "Failed to decrypt any envelope with provided private key"
    
    # Step 5: Decrypt file with recovered session key
    openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -md sha256 \
        -in encrypted_file.enc \
        -out "$PLAINTEXT_FILE" \
        -pass file:session_key_recovered_$$.bin || \
        error_exit "Failed to decrypt file"
    
    # Clean up extracted files
    rm -f encrypted_file.enc signature.bin envelope_*.enc
    rm -f encrypted_session_key_extracted_$$.bin salt_extracted_$$.bin
    
    echo "[RECEIVER] Decryption completed successfully. Output: $PLAINTEXT_FILE"

else
    error_exit "Invalid mode. Use -sender or -receiver"
fi

exit 0
