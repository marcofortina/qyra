// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_HASH_H
#define QYRA_HASH_H

#include <string>
#include <vector>

/**
 * @brief A class that provides hashing functionalities.
 */
class CHasher
{
public:
    /**
     * @brief Computes the BLAKE3 hash of a given byte vector.
     *
     * @param data The input vector of bytes to hash.
     *
     * @return A vector containing the BLAKE3 hash of the input data.
     */
    static std::vector<unsigned char> BLAKE3(const std::vector<unsigned char>& data);
};

#endif // QYRA_HASH_H