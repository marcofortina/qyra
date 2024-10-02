// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <hash.h>

#include <blake3.h>
#include <vector>

// Computes the BLAKE3 hash of a given byte vector.
std::vector<unsigned char> CHasher::BLAKE3(const std::vector<unsigned char>& data)
{
    // Create a hasher object
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);

    // Update the hasher with the data
    blake3_hasher_update(&hasher, data.data(), data.size());

    // Buffer to store the hash output
    unsigned char hash[BLAKE3_OUT_LEN];

    // Finalize the hash and store it
    blake3_hasher_finalize(&hasher, hash, sizeof(hash));

    // Return the hash as a vector of unsigned characters
    return std::vector<unsigned char>(hash, hash + BLAKE3_OUT_LEN);
}