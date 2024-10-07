// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto.h>

#include <utils.h>

// IWYU pragma: no_include <oqs/common.h>
// IWYU pragma: no_include <oqs/kem_kyber.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <oqs/oqs.h> // IWYU pragma: keep
#include <stdio.h>
#include <string>
#include <vector>

// Static method to generate a public/secret key pair for encryption.
bool CCrypter::GenerateKeyPair(uint8_t* public_key, uint8_t* secret_key)
{
    // Generate key pairs for the encryption process.
    OQS_STATUS rc = OQS_KEM_kyber_768_keypair(public_key, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: [%s] OQS_KEM_kyber_768_keypair failed!\n", __func__);

        // Avoid leaking sensitive information.
        OQS_MEM_cleanse(secret_key, OQS_KEM_kyber_768_length_secret_key);
        OQS_MEM_cleanse(public_key, OQS_KEM_kyber_768_length_public_key);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Static method to generate ciphertext and a shared secret.
bool CCrypter::GenerateCiphertext(uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key)
{
    // Check if public_key is null
    if (!public_key) {
        fprintf(stderr, "ERROR: [%s] Invalid public_key: pointer is null.\n", __func__);

        // Return false on failure
        return false;
    }

    // Perform key encapsulation to generate the shared secret and ciphertext.
    OQS_STATUS rc = OQS_KEM_kyber_768_encaps(ciphertext, shared_secret, public_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: [%s] OQS_KEM_kyber_768_encaps failed!\n", __func__);

        // Avoid leaking sensitive information.
        OQS_MEM_cleanse(ciphertext, OQS_KEM_kyber_768_length_ciphertext);
        OQS_MEM_cleanse(shared_secret, OQS_KEM_kyber_768_length_shared_secret);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Static method to recover the shared secret from the ciphertext
bool CCrypter::RecoverSharedSecret(uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key)
{
    // Check if secret_key is null
    if (!secret_key) {
        fprintf(stderr, "ERROR: [%s] Invalid secret_key: pointer is null.\n", __func__);

        // Return false on failure
        return false;
    }

    // Perform key decapsulation to recover the shared secret from the ciphertext.
    OQS_STATUS rc = OQS_KEM_kyber_768_decaps(shared_secret, ciphertext, secret_key);
    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: [%s] OQS_KEM_kyber_768_decaps failed!\n", __func__);

        // Avoid leaking sensitive information.
        OQS_MEM_cleanse(shared_secret, OQS_KEM_kyber_768_length_shared_secret);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Static method to encrypt data using AES-256-CBC.
bool CCrypter::EncryptData(const std::vector<unsigned char>& message, std::vector<unsigned char>& enc, const uint8_t* shared_secret, std::vector<unsigned char>& iv)
{
    // Check if shared_secret is null
    if (!shared_secret) {
        fprintf(stderr, "ERROR: [%s] Invalid shared_secret: pointer is null.\n", __func__);
        return false;
    }

    // Check if the message is empty
    if (message.empty()) {
        fprintf(stderr, "ERROR: [%s] No data to encrypt. The message is empty!\n", __func__);
        return false;
    }

    // Try to generate a random initialization vector (IV)
    iv.resize(EVP_MAX_IV_LENGTH); // IV length is 16 bytes for AES-256-CBC
    if (!RAND_bytes(iv.data(), iv.size())) {
        fprintf(stderr, "ERROR: [%s] Failed to generate IV.\n", __func__);
        return false;
    }

#ifdef DEBUG
    printf("%s: iv (size=%zu): %s\n", __func__, iv.size(), FormatHex(iv).data());
    printf("%s: message (size=%zu): %s\n", __func__, message.size(), FormatHex(message).data());
#endif

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ERROR: [%s] Failed to create cipher context.\n", __func__);
        return false;
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv.data())) {
        fprintf(stderr, "ERROR: [%s] Failed to initialize AES encryption.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Resize the encrypted vector to accommodate the message size plus padding for AES.
    enc.resize(message.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));

    int len = 0, ciphertext_len = 0;

    // Perform encryption
    if (1 != EVP_EncryptUpdate(ctx, enc.data(), &len, message.data(), message.size())) {
        fprintf(stderr, "ERROR: [%s] Data encryption failed.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, enc.data() + len, &len)) {
        fprintf(stderr, "ERROR: [%s] Data encryption finalization failed.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;
    enc.resize(ciphertext_len); // Resize to actual encrypted size

    EVP_CIPHER_CTX_free(ctx);

#ifdef DEBUG
    printf("%s: enc (size=%zu): %s\n", __func__, enc.size(), FormatHex(enc).data());
#endif

    return true;
}

// Static method to decrypt data using AES-256-CBC.
bool CCrypter::DecryptData(const std::vector<unsigned char>& enc, std::vector<unsigned char>& message, const uint8_t* shared_secret, const std::vector<unsigned char>& iv)
{
    // Check if shared_secret is null
    if (!shared_secret) {
        fprintf(stderr, "ERROR: [%s] Invalid shared_secret: pointer is null.\n", __func__);
        return false;
    }

    // Check the length of the IV (should be 16 bytes for AES-256-CBC)
    if (iv.size() != EVP_MAX_IV_LENGTH) {
        fprintf(stderr, "ERROR: [%s] Invalid IV length. Must be 16 bytes, but got %zu.\n", __func__, iv.size());
        return false;
    }

    // Check if the encrypted data is empty
    if (enc.empty()) {
        fprintf(stderr, "ERROR: [%s] No data to decrypt. The encrypted message is empty!\n", __func__);
        return false;
    }

#ifdef DEBUG
    printf("%s: iv (size=%zu): %s\n", __func__, iv.size(), FormatHex(iv).data());
    printf("%s: enc (size=%zu): %s\n", __func__, enc.size(), FormatHex(enc).data());
#endif

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "ERROR: [%s] Failed to create cipher context.\n", __func__);
        return false;
    }

    // Initialize decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, shared_secret, iv.data())) {
        fprintf(stderr, "ERROR: [%s] Failed to initialize AES decryption.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Allocate enough space for the decrypted data
    message.resize(enc.size());

    int len = 0, plaintext_len = 0;

    // Perform decryption
    if (1 != EVP_DecryptUpdate(ctx, message.data(), &len, enc.data(), enc.size())) {
        fprintf(stderr, "ERROR: [%s] Data decryption failed.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // Finalize decryption
    if (1 != EVP_DecryptFinal_ex(ctx, message.data() + len, &len)) {
        fprintf(stderr, "ERROR: [%s] Data decryption finalization failed.\n", __func__);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;
    message.resize(plaintext_len); // Resize to actual decrypted size

    EVP_CIPHER_CTX_free(ctx);

#ifdef DEBUG
    printf("%s: message (size=%zu): %s\n", __func__, message.size(), FormatHex(message).data());
#endif

    return true;
}