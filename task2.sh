#!/bin/bash

# task2.sh - Digital Signature and Verification for Zip Files

set -e

# Error handling function
error_exit() {
    echo "ERROR mong.e: $1" >&2
    cleanup
    exit 1
}

# Cleanup function to remove all temporary files
cleanup() {
    rm -f file_hash_$$.bin
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

#############################################
# SENDER MODE
#############################################

if [ "$1" == "-sender" ]; then
    
    # Validate arguments
    [ "$#" -ne 4 ] && error_exit "Usage: $0 -sender <zip_file> <sender_priv> <signature_file>"

    ZIP_FILENAME="$2"
    SENDER_PRIV="$3"
    ZIP_FILE_SIGNATURE="$4"
    
    # Validate input files
    [ ! -f "$ZIP_FILENAME" ] && error_exit "Zip file not found"
    [ ! -f "$SENDER_PRIV" ] && error_exit "Sender private key not found"
    
    # Step 1: Generate SHA-256 hash of the zip file
    openssl dgst -sha256 -binary -out file_hash_$$.bin "$ZIP_FILENAME" || \
        error_exit "Failed to hash zip file"
    
    # Step 2: Sign the hash using sender's private key (ECDSA with secp256r1)
    openssl pkeyutl -sign -inkey "$SENDER_PRIV" -in file_hash_$$.bin \
        -out "$ZIP_FILE_SIGNATURE" || \
        error_exit "Failed to sign file"
    
    echo "Signature created successfully"

#############################################
# RECEIVER MODE
#############################################

elif [ "$1" == "-receiver" ]; then

    # Validate arguments
    [ "$#" -ne 4 ] && error_exit "Usage: $0 -receiver <sender_pub> <signature_file> <zip_file>"

    SENDER_PUB="$2"
    ZIP_FILE_SIGNATURE="$3"
    ZIP_FILENAME="$4"
    
    # Validate input files
    [ ! -f "$SENDER_PUB" ] && error_exit "Sender public key not found"
    [ ! -f "$ZIP_FILE_SIGNATURE" ] && error_exit "Signature file not found"
    [ ! -f "$ZIP_FILENAME" ] && error_exit "Zip file not found"
    
    # Step 1: Generate SHA-256 hash of the zip file
    openssl dgst -sha256 -binary -out file_hash_$$.bin "$ZIP_FILENAME" || \
        error_exit "Failed to hash zip file"
    
    # Step 2: Verify signature using sender's public key
    if openssl pkeyutl -verify -pubin -inkey "$SENDER_PUB" \
        -in file_hash_$$.bin -sigfile "$ZIP_FILE_SIGNATURE" 2>/dev/null; then
        echo "Signature verified successfully"
        exit 0
    else
        echo "Signature verification failed"
        exit 1
    fi

else
    error_exit "Invalid mode. Use -sender or -receiver"
fi

exit 0
