// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_STREAM_H
#define QYRA_STREAM_H

#include <endian.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

// CStream class for handling a stream of data.
class CStream
{
private:
    // Vector to store the stream data.
    std::vector<unsigned char> vchData = {};

    // Current position in the stream.
    std::size_t nPos = 0;

public:
    // Default constructor
    CStream() = default;

    // Constructor that accepts a vector of unsigned char
    CStream(const std::vector<unsigned char>& input) : vchData(input), nPos(0) {}

    // Overloaded operator<< to append a vector of unsigned char to the stream.
    CStream& operator<<(const std::vector<unsigned char>& input)
    {
        vchData.insert(vchData.end(), input.begin(), input.end());
        return *this;
    }

    // Overloaded operator<< to append a uint16_t value to the stream, converting
    CStream& operator<<(uint16_t value)
    {
#if __BYTE_ORDER == __BIG_ENDIAN
        // Convert to little-endian format if the system is big-endian.
        value = htole16(value);
#endif
        vchData.insert(vchData.end(), reinterpret_cast<unsigned char*>(&value),
                       reinterpret_cast<unsigned char*>(&value) + sizeof(value));

        return *this;
    }

    // Overloaded operator>> to extract data into a vector of unsigned char from the stream.
    CStream& operator>>(std::vector<unsigned char>& output)
    {
        // Check if there is enough data to read.
        if (nPos + output.size() > vchData.size()) {
            throw std::out_of_range("Not enough data to read");
        }

        // Copy data from the stream into the output vector.
        std::copy(vchData.begin() + nPos, vchData.begin() + nPos + output.size(), output.begin());

        // Update the current position.
        nPos += output.size();

        return *this;
    }

    // Overloaded operator>> to extract data into a uint8_t pointer from the stream.
    CStream& operator>>(uint8_t* output)
    {
        // Check if there is enough data to read.
        if (nPos + sizeof(output) > vchData.size()) {
            throw std::out_of_range("Not enough data to read");
        }

        // Copy data from the stream into the output pointer.
        std::copy(vchData.begin() + nPos, vchData.end(), output);

        // Update the current position.
        nPos += sizeof(output);

        return *this;
    }

    // Returns a constant reference to the underlying data vector.
    const std::vector<unsigned char>& Data() const
    {
        return vchData;
    }

    // Returns the size of the data in the stream.
    std::size_t Size() const
    {
        return vchData.size();
    }

    // Returns a hexadecimal representation of the data in the stream.
    std::string GetHex() const
    {
        std::ostringstream oss;
        for (unsigned char byte : vchData) {
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }

        // Return the hex string.
        return oss.str();
    }
};

#endif // QYRA_STREAM_H