// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <utils.h>

#include <ctime>
#include <endian.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

// Converts a string to a hexadecimal string.
std::string FormatHex(const std::string& input)
{
    std::ostringstream oss;

    // Convert each byte to a two-digit hexadecimal representation.
    for (unsigned char byte : input) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    // Return the resulting hex string.
    return oss.str();
}

// Converts a byte array to a hexadecimal string.
std::string FormatHex(const std::vector<uint8_t>& data)
{
    std::ostringstream oss;

    // Convert each byte to a two-digit hexadecimal representation.
    for (const auto& byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }

    // Return the final hex string.
    return oss.str();
}

// Converts a hexadecimal string into a vector of unsigned chars.
std::vector<unsigned char> ParseHex(const std::string& str)
{
    std::vector<unsigned char> result;

    // Check if the string length is even
    if (str.length() % 2 != 0) {
        throw std::invalid_argument("Invalid hex string length");
    }

    // Iterate over the string two characters at a time
    for (std::size_t i = 0; i < str.length(); i += 2) {
        // Extract two characters (a byte in hex representation)
        std::string byteString = str.substr(i, 2);

        // Convert the pair of characters into an unsigned char
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

// Packs a vector of unsigned char into a vector of uint16_t using 12-bit groups.
std::vector<uint16_t> Pack12(const std::vector<unsigned char>& input)
{
    std::vector<unsigned char> paddedInput = input;

    // Calculate the padding size to make the input size divisible by 3
    std::size_t paddingSize = (3 - (paddedInput.size() % 3)) % 3;

    // Add padding if necessary
    paddedInput.resize(paddedInput.size() + paddingSize, 0);

    std::vector<uint16_t> output;

    // Process the input in groups of 12 bits
    for (std::size_t i = 0; i < paddedInput.size(); i += 3) {
        // Combine three bytes into a 24-bit value
        uint32_t value = (static_cast<uint32_t>(paddedInput[i])) |
                         (static_cast<uint32_t>(paddedInput[i + 1]) << 8) |
                         (static_cast<uint32_t>(paddedInput[i + 2]) << 16);

        // Extract two 12-bit values from the 24-bit value
        uint16_t low = static_cast<uint16_t>(value & 0x0FFF);          // Lower 12 bits
        uint16_t high = static_cast<uint16_t>((value >> 12) & 0x0FFF); // Higher 12 bits

        // If the system is big-endian, convert the values to little-endian
#if __BYTE_ORDER == __BIG_ENDIAN
        low = htole16(low);
        high = htole16(high);
#endif

        // Add to the output
        output.push_back(low);
        output.push_back(high);
    }

    return output;
}

// Function to get the current Unix timestamp
uint32_t GetTime()
{
    // Get the current time in seconds since Unix epoch (1970)
    std::time_t currentTime = std::time(nullptr);

    // Return the time as a uint32_t value
    return static_cast<uint32_t>(currentTime);
}
