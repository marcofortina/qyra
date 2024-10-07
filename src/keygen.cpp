// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto.h>

// IWYU pragma: no_include <oqs/kem_kyber.h>

#include <cstddef>
#include <iomanip>
#include <iostream>
#include <oqs/oqs.h> // IWYU pragma: keep
#include <stdint.h>

int main()
{
    // Public key.
    uint8_t public_key[OQS_KEM_kyber_768_length_public_key];

    // Secret key.
    uint8_t secret_key[OQS_KEM_kyber_768_length_secret_key];

    // Generate public/secret key pair.
    CCrypter::GenerateKeyPair(public_key, secret_key);

    // Informational message to the user
    std::cout << "Use this code snippet to declare and store the public and secret keys.\n";
    std::cout << "Never share the secret key with anyone.\n\n";

    // Print public key in the desired format.
    std::cout << "///< Public key.\n";
    std::cout << "uint8_t public_key[1184] =\n";
    std::cout << "{\n    ";
    for (std::size_t i = 0; i < sizeof(public_key); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)public_key[i];
        // Determine if a comma is needed or not
        if (i < sizeof(public_key) - 1) {
            std::cout << ",";
            // Print a space after the comma only if not at the end of the line
            if ((i + 1) % 8 != 0) {
                std::cout << " ";
            }
        }
        // Wrap the line every 8 values.
        if ((i + 1) % 8 == 0 && i != sizeof(public_key) - 1) {
            std::cout << "\n    ";
        }
    }
    std::cout << "\n};\n\n";

    // Print secret key in the desired format.
    std::cout << "///< Secret key.\n";
    std::cout << "uint8_t secret_key[2400] =\n";
    std::cout << "{\n    ";
    for (std::size_t i = 0; i < sizeof(secret_key); ++i) {
        std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)secret_key[i];
        // Determine if a comma is needed or not
        if (i < sizeof(secret_key) - 1) {
            std::cout << ",";
            // Print a space after the comma only if not at the end of the line
            if ((i + 1) % 8 != 0) {
                std::cout << " ";
            }
        }
        // Wrap the line every 8 values.
        if ((i + 1) % 8 == 0 && i != sizeof(secret_key) - 1) {
            std::cout << "\n    ";
        }
    }
    std::cout << "\n};\n";

    return 0;
}