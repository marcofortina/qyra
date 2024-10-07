// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_UTILS_H
#define QYRA_UTILS_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * @brief Converts a string to its hexadecimal string representation.
 *
 * @param input The string to format as hex.
 * @return A string representing the input in hexadecimal format.
 */
std::string FormatHex(const std::string& input);

/**
 * @brief Converts a byte vector to a hexadecimal string.
 *
 * @param data A vector of bytes (uint8_t) to be converted to a hexadecimal string.
 * @return std::string The resulting hexadecimal string.
 */
std::string FormatHex(const std::vector<uint8_t>& data);

/**
 * @brief Converts an array of uint8_t to a hexadecimal string.
 *
 * This function accepts an array of any size and converts it to
 * a hexadecimal string representation.
 *
 * @tparam N The size of the array.
 * @param data The array of bytes to convert.
 * @return A string representing the hexadecimal representation of the bytes.
 */
template <std::size_t N>
std::string FormatHex(const uint8_t (&data)[N])
{
    // Create a std::vector<uint8_t> from the array.
    return FormatHex(std::vector<uint8_t>(data, data + N));
}

/**
 * @brief Converts a hexadecimal string into a vector of unsigned chars.
 *
 * @param str The input hexadecimal string.
 * @return std::vector<unsigned char> A vector containing the corresponding unsigned char values.
 * @throws std::invalid_argument If the string has an odd length.
 */
std::vector<unsigned char> ParseHex(const std::string& str);

/**
 * @brief Packs a vector of unsigned char into a vector of uint16_t using 12-bit groups.
 *
 * This function pads the input vector with zeros to ensure its size
 * is divisible by 3, then processes the input in groups of 12 bits,
 * converting each group into uint16_t.
 *
 * @param input A vector of unsigned char to be packed.
 * @return A vector of uint16_t resulting from the packing process.
 * @throws std::invalid_argument If the input vector is empty.
 */
std::vector<uint16_t> Pack12(const std::vector<unsigned char>& input);

/**
 * @brief Retrieves the current Unix timestamp.
 *
 * @return uint32_t Current time in Unix format (seconds since epoch).
 */
uint32_t GetTime();

#endif // QYRA_UTILS_H