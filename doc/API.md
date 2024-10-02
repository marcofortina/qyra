# Qyra API Documentation

## Overview

Qyra provides a cryptographic Proof-of-Work (PoW) system that utilizes Kyber-768 for quantum-safe encryption and AES-256-CBC for graph-based mining and validation. This document outlines the main classes and functions in the Qyra API.

## Classes

### `LibQYRA::CQYRA`

This class is the core interface for interacting with the Qyra PoW system.

#### Methods

- **`CQYRA()`**
  Initializes the Qyra object and internal components.

- **`~CQYRA()`**
  Cleans up resources used by the Qyra instance.

- **`bool Initialize(const uint8_t* public_key, const uint8_t* secret_key)`**
  Initializes the Qyra system with the provided public and secret keys for cryptographic operations.

- **`void EnableParallelDFS()`**
  Enables parallel execution of Depth-First Search (DFS) using multiple threads.

- **`void SetHeader(const std::vector<unsigned char>& vch)`**
  Sets the block header data used in mining and validation.

- **`void SetNonce(const std::vector<unsigned char>& vch)`**
  Sets the nonce used during the mining process.

- **`bool Validate(const std::vector<unsigned char>& vch) const`**
  Validates a solution by checking both the graph and DFS path.

- **`bool Mine()`**
  Begins the mining process to find a valid graph solution.

- **`bool IsValid() const`**
  Checks if the current solution is valid.

### `LibQYRA::CSolutionData`

Manages solution-related data, including encryption and cryptographic information.

#### Attributes

- **`std::vector<unsigned char> enc`**
  Encrypted message.

- **`std::vector<unsigned char> iv`**
  Initialization vector used in AES-256-CBC encryption.

- **`std::vector<unsigned char> ciphertext`**
  Ciphertext generated from Kyber-768 encryption.

- **`std::vector<unsigned char> hash`**
  The Blake3 hash of the solution's DFS path.

#### Methods

- **`void Clear()`**
  Clears the current solution data.

- **`std::vector<unsigned char> Get() const`**
  Returns the current solution as a vector.

- **`std::string ToString() const`**
  Converts the solution data to a human-readable string.

- **`std::size_t Size() const`**
  Returns the size of the solution data.

## Example Usage

### Mining Example

```cpp
#include <qyra.h>

int main() {
    LibQYRA::CQYRA qyra;

    // Initialize public and secret keys for Kyber-768
    uint8_t publicKey[Kyber768_PUBLICKEYBYTES] = { /* Public key data */ };
    uint8_t secretKey[Kyber768_SECRETKEYBYTES] = { /* Secret key data */ };

    // Initialize Qyra with cryptographic keys
    qyra.Initialize(publicKey, secretKey);

    // Set block header and nonce
    std::vector<unsigned char> header = { /* Block header data */ };
    std::vector<unsigned char> nonce = { /* Nonce data */ };
    qyra.SetHeader(header);
    qyra.SetNonce(nonce);

    // Enable parallel DFS for mining
    qyra.EnableParallelDFS();

    // Start mining
    if (qyra.Mine()) {
        // Solution found
        std::cout << "Solution found: " << qyra.solution.ToString() << std::endl;
        std::cout << "Is the solution valid: " << (qyra.IsValid() ? "True" : "False") << std::endl;
    } else {
        std::cout << "No solution found." << std::endl;
    }

    return 0;
}
```

### Validation Example

```cpp
#include <qyra.h>

int main() {
    LibQYRA::CQYRA qyra;

    // Initialize public and secret keys for Kyber-768
    uint8_t publicKey[Kyber768_PUBLICKEYBYTES] = { /* Public key data */ };
    uint8_t secretKey[Kyber768_SECRETKEYBYTES] = { /* Secret key data */ };

    // Initialize Qyra with cryptographic keys
    qyra.Initialize(publicKey, secretKey);

    // Set block header and nonce
    std::vector<unsigned char> header = { /* Block header data */ };
    std::vector<unsigned char> nonce = { /* Nonce data */ };
    qyra.SetHeader(header);
    qyra.SetNonce(nonce);

    // Enable parallel DFS for mining
    qyra.EnableParallelDFS();

    // Assume we have a valid solution to validate
    std::vector<unsigned char> solution = { /* Solution data */ };

    // Validate the solution
    if (qyra.Validate(solution)) {
        std::cout << "The solution is valid!" << std::endl;
    } else {
        std::cout << "The solution is invalid." << std::endl;
    }

    return 0;
}
```

## Donations

If you appreciate the work on Qyra and want to support its development, you can make a donation in Bitcoin to the following address:

**1N2rQimKbeUQA8N2LU5vGopYQJmZsBM2d6**

## License

Qyra is distributed under the MIT License. See [LICENSE](https://opensource.org/licenses/MIT) for more details.