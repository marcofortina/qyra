// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_H
#define QYRA_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifndef QYRA_API
#if defined(_WIN32)
#define QYRA_API __declspec(dllexport)
#elif defined(__GNUC__) && (__GNUC__ >= 4)
#define QYRA_API __attribute__((visibility("default")))
#else
#define QYRA_API
#endif
#endif

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
#define ENC_SIZE 144         ///< Size of encrypted data
#define IV_SIZE 16           ///< Size of initialization vector (AES_BLOCK_SIZE)
#define CIPHERTEXT_SIZE 1088 ///< Size of ciphertext for Kyber768
#define HASH_SIZE 32         ///< Size of hash

#define TOTAL_SIZE (ENC_SIZE + IV_SIZE + CIPHERTEXT_SIZE) ///< Define total size for the combined vector
#define SOLUTION_SIZE (TOTAL_SIZE + HASH_SIZE)            ///< Define total size for the solution vector including the hash

/**
 * @class CGraph
 * @brief Forward declaration of the CGraph class.
 *
 * This class represents a graph structure used in various graph algorithms.
 */
class CGraph;

/**
 * @class CPath
 * @brief Forward declaration of the CPath class.
 *
 * This class is used to represent a path within a graph, enabling
 * traversal and pathfinding operations.
 */
class CPath;

/**
 * @namespace LibQYRA
 * @brief A namespace for the LibQYRA library.
 *
 * This namespace encompasses all classes and functions
 * related to the LibQYRA library, providing modularity and
 * preventing name collisions.
 */
namespace LibQYRA {

/**
 * @brief CCryptoData holds cryptographic information like encryption, IV, ciphertext, and hash.
 */
class CCryptoData
{
public:
    std::vector<unsigned char> enc;        ///< Encryption key data.
    std::vector<unsigned char> iv;         ///< Initialization vector (IV) for encryption.
    std::vector<unsigned char> ciphertext; ///< Encrypted ciphertext.
    std::vector<unsigned char> hash;       ///< Hash of the data.
};

/**
 * @brief CSolutionData manages solution-related data.
 */
class CSolutionData
{
    friend class CQYRA;

public:
    /**
     * @brief Clears the current solution data.
     */
    void Clear();

    /**
     * @brief Returns the current solution as a vector of unsigned chars.
     *
     * @return Solution data.
     */
    std::vector<unsigned char> Get() const;

    /**
     * @brief Converts the solution to a human-readable string format.
     *
     * @return Solution as a string.
     */
    std::string ToString() const;

    /**
     * @brief Returns the size of the current solution data.
     *
     * @return Size of the solution data.
     */
    std::size_t Size() const;

    CCryptoData cryptoData; ///< Cryptographic data associated with the solution.

private:
    /**
     * @brief Assignment operator to set the solution from a vector of unsigned chars.
     *
     * @param data The new solution data.
     *
     * @return A reference to the current object.
     */
    CSolutionData& operator=(const std::vector<unsigned char>& data)
    {
        solution = data;
        return *this;
    }

    std::vector<unsigned char> solution; ///< Internal solution data.
};

/**
 * @brief CQYRA provides the core API for interacting with the Qyra cryptographic solution.
 */
class CQYRA
{
public:
    /**
     * @brief Constructs a CQYRA object and initializes internal components.
     */
    CQYRA();

    /**
     * @brief Destroys the CQYRA object, freeing allocated resources.
     */
    ~CQYRA();

    /**
     * @brief Initializes the Qyra system, preparing it for use.
     *
     * @param public_key The public key used for cryptographic operations.
     * @param secret_key The secret key that must be securely provided.
     *
     * @return True if initialization was successful, false otherwise.
     */
    QYRA_API bool Initialize(const uint8_t* public_key, const uint8_t* secret_key);

    /**
     * @brief Enables DFS parallelization by setting the number of threads.
     *
     * This function uses the number of cores available on the system to
     * set the optimal number of threads for parallel DFS execution.
     */
    QYRA_API void EnableParallelDFS();

    /**
     * @brief Sets the header data.
     *
     * @param vch The header as a vector of unsigned chars.
     */
    QYRA_API void SetHeader(const std::vector<unsigned char>& vch);

    /**
     * @brief Sets the nonce used in the mining process.
     *
     * @param vch The nonce as a vector of unsigned chars.
     */
    QYRA_API void SetNonce(const std::vector<unsigned char>& vch);

    /**
     * @brief Validates the provided solution by checking both the graph and path.
     *
     * This function verifies the correctness of the solution by validating the graph and path components.
     * It uses the provided solution vector to ensure that the graph is correctly generated and the path is
     * correctly computed based on the validated graph.
     *
     * @param vch The solution vector containing only the encrypted data (enc), initialization vector (iv),
     *            and ciphertext. The hash is not included in this vector.
     *
     * @return True if both the graph and path are valid; false otherwise.
     */
    QYRA_API bool Validate(const std::vector<unsigned char>& vch) const;

    /**
     * @brief Starts the mining process to find a solution to the graph.
     *
     * @return True if a valid solution to the graph is found, otherwise false.
     */
    QYRA_API bool Mine();

    /**
     * @brief Checks if the current solution is valid.
     *
     * @return True if the solution is valid, otherwise false.
     */
    QYRA_API bool IsValid() const;

    CSolutionData solution; ///< Holds the current solution data.

private:
    CGraph* graph; ///< Pointer to the graph used in the mining process.
    CPath* path;   ///< Pointer to the path used for solving the graph.
};

} // namespace LibQYRA

#endif // QYRA_H