// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_CRYPTO_H
#define QYRA_CRYPTO_H

#include <cstdint>
#include <vector>

/**
 * @brief A class that provides cryptographic functionalities including key generation, encryption, and hashing.
 */
class CCrypter
{
public:
    /**
     * @brief Generates a public/secret key pair for encryption.
     *
     * @param public_key A pointer to a buffer where the generated public key will be stored.
     * @param secret_key A pointer to a buffer where the generated secret key will be stored.
     *
     * @return true if the key pair was generated successfully, false otherwise.
     */
    static bool GenerateKeyPair(uint8_t* public_key, uint8_t* secret_key);

    /**
     * @brief Generates ciphertext and a shared secret using the provided public key.
     *
     * @param ciphertext A pointer to a buffer where the generated ciphertext will be stored.
     * @param shared_secret A pointer to a buffer where the generated shared secret will be stored.
     * @param public_key A pointer to the public key used for encryption.
     *
     * @return true if the key encapsulation was successful, false otherwise.
     */
    static bool GenerateCiphertext(uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key);

    /**
     * @brief Recovers the shared secret from the ciphertext using the Kyber KEM decryption.
     *
     * @param shared_secret A pointer to a buffer where the recovered shared secret will be stored.
     * @param ciphertext A pointer to the ciphertext from which the shared secret will be recovered.
     * @param secret_key A pointer to the secret key used for decryption.
     *
     * @return true if the decryption operation was successful, false otherwise.
     */
    static bool RecoverSharedSecret(uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key);

    /**
     * @brief Encrypts data using AES-256-CBC and a shared secret.
     *
     * @param message The data to be encrypted.
     * @param enc A reference to a vector where the encrypted data will be stored.
     * @param shared_secret A pointer to the shared secret used as the encryption key.
     * @param iv A reference to a vector where the generated IV will be stored.
     *
     * @return true if the encryption was successful, false otherwise.
     */
    static bool EncryptData(const std::vector<unsigned char>& message, std::vector<unsigned char>& enc, const uint8_t* shared_secret, std::vector<unsigned char>& iv);

    /**
     * @brief Decrypts data using AES-256-CBC and a shared secret.
     *
     * @param enc The encrypted data to be decrypted.
     * @param message A reference to a vector where the decrypted data will be stored.
     * @param shared_secret A pointer to the shared secret used as the decryption key.
     * @param iv A reference to a vector containing the initialization vector (IV) used for decryption.
     *
     * @return true if the decryption was successful, false otherwise.
     */
    static bool DecryptData(const std::vector<unsigned char>& enc, std::vector<unsigned char>& message, const uint8_t* shared_secret, const std::vector<unsigned char>& iv);
};

#endif // QYRA_CRYPTO_H