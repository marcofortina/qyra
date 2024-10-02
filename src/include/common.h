// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_COMMON_H
#define QYRA_COMMON_H

/**
 * @brief Explanation of data structure sizes for encryption
 *
 * The plaintext consists of two parts:
 * - **Header**: 108 bytes
 * - **Nonce**: 32 bytes
 *
 * Together, this makes a total of 140 bytes of plaintext data.
 *
 * Since AES-256-CBC operates in 16-byte blocks, and the plaintext size is not a multiple of 16,
 * 4 bytes of padding will be added to reach a size of 144 bytes.
 *
 * The encrypted version of this 140-byte plaintext will always be 144 bytes due to padding.
 */

#define ENC_SIZE 144         // Size of encrypted data
#define IV_SIZE 16           // Size of initialization vector (AES_BLOCK_SIZE)
#define CIPHERTEXT_SIZE 1088 // Size of ciphertext for Kyber768
#define HASH_SIZE 32         // Size of hash

// Define total size for the combined vector
#define TOTAL_SIZE (ENC_SIZE + IV_SIZE + CIPHERTEXT_SIZE)

// Define total size for the solution vector including the hash
#define SOLUTION_SIZE (TOTAL_SIZE + HASH_SIZE)

#endif // QYRA_COMMON_H