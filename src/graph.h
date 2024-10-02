// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_GRAPH_H
#define QYRA_GRAPH_H

#include <bitset>
#include <oqs/oqs.h>
#include <string>
#include <vector>

/**
 * @brief Maximum number of nodes allowed in the graph.
 *
 * Defines the maximum size of the graph's adjacency matrix, where each node can
 * be represented as a bit in a bitset. This limit is set to 4096 bits.
 */
constexpr std::size_t MAX_NODES = 4096;

/**
 * @brief Represents a graph with an adjacency matrix and cryptographic components.
 */
class CGraph
{
    friend class CPath;

public:
    /**
     * @brief Constructs an empty CGraph with an initialized adjacency matrix.
     */
    CGraph();

    /**
     * @brief Adds an edge between two nodes in the graph.
     *
     * @param from The starting node.
     * @param to The ending node.
     *
     * @return true if the edge was added successfully, false otherwise.
     */
    bool AddEdge(uint16_t from, uint16_t to);

    /**
     * @brief Initializes the graph and generates cryptographic keys.
     *
     * @param public_key The public key to be used for cryptographic operations.
     * @param secret_key The secret key that must be securely provided.
     *
     * @return true if initialization is successful, false otherwise.
     */
    bool Initialize(const uint8_t* public_key, const uint8_t* secret_key);

    void Clear();

    /**
     * @brief Sets the header used in cryptographic operations.
     *
     * @param vch Vector containing header data.
     */
    void SetHeader(const std::vector<unsigned char>& vch);

    /**
     * @brief Sets the nonce used in cryptographic operations.
     *
     * @param vch Vector containing nonce data.
     */
    void SetNonce(const std::vector<unsigned char>& vch);

    /**
     * @brief Encrypts the graph's data and updates the adjacency matrix with the encrypted data.
     *
     * @return true if the operation succeeded; false otherwise.
     */
    bool Generate();

    /**
     * @brief Validates if the provided data was generated from a correct graph
     * created with the right header and nonce.
     *
     * This function verifies that the provided vector contains the expected sizes for encrypted data (enc),
     * initialization vector (iv), and ciphertext. It does not validate the solution itself but ensures that
     * the graph was correctly generated from the header and nonce.
     *
     * @param vch The vector containing the encrypted data (enc), initialization vector (iv), and ciphertext.
     *
     * @return True if the graph was generated correctly; false otherwise.
     */
    bool Validate(const std::vector<unsigned char>& solution);

    /**
     * @brief Dumps the graph's data for debugging purposes.
     */
    void Dump() const;

    /**
     * @brief Converts the graph's adjacency matrix to a string representation.
     *
     * @return A string representing the adjacency matrix.
     */
    std::string ToString() const;

    /**
     * @brief Gets the total number of entries in the adjacency matrix.
     *
     * @return The total number of entries (nodes * nodes).
     */
    std::size_t Size() const;

    /**
     * @brief Retrieves the adjacency matrix of the graph.
     *
     * @return A constant reference to the adjacency matrix.
     */
    const std::vector<std::bitset<MAX_NODES>>& GetAdjacencyMatrix() const;

    /**
     * @brief Computes the hash of the graph's adjacency matrix.
     *
     * @return A vector containing the hash of the graph.
     */
    std::vector<unsigned char> GetHash() const;

    /**
     * @brief Retrieves the encrypted message.
     *
     * @return A vector containing the encrypted message.
     */
    std::vector<unsigned char> GetEncMessage() const;

    /**
     * @brief Retrieves the ciphertext used in the key encapsulation.
     *
     * @return A vector containing the ciphertext.
     */
    std::vector<unsigned char> GetCiphertext() const;

    /**
     * @brief Retrieves the initialization vector used in encryption.
     *
     * @return A vector containing the initialization vector.
     */
    std::vector<unsigned char> GetIV() const;

    /**
     * @brief Saves the adjacency matrix to a file
     *
     * @param filename Name of the output file
     *
     * @return True if the matrix was saved successfully; false otherwise.
     */
    bool SaveAdjacencyMatrixToFile(const std::string& filename) const;

    // Function to set the number of threads
    void SetNumThreads(unsigned int numThreads);

private:
    ///< Adjacency matrix of the graph.
    std::vector<std::bitset<MAX_NODES>> adjacencyMatrix;

    ///< Header data.
    std::vector<unsigned char> header;

    ///< Nonce data.
    std::vector<unsigned char> nonce;

    ///< Encrypted message.
    std::vector<unsigned char> enc;

    ///< Initialization vector.
    std::vector<unsigned char> iv;

    ///< Public key.
    uint8_t publicKey[OQS_KEM_kyber_768_length_public_key];

    ///< Secret key.
    uint8_t secretKey[OQS_KEM_kyber_768_length_secret_key];

    ///< Ciphertext.
    uint8_t ciphertext[OQS_KEM_kyber_768_length_ciphertext];

    /**
     * @brief Updates the graph using the decrypted data.
     *
     * This function is private and should not be called directly. It is used internally
     * by other methods like Generate and Validate to update the adjacency matrix with edges.
     *
     * @param data The decrypted data used to update the graph.
     *
     * @return Returns true if the graph was updated successfully, false otherwise.
     */
    bool UpdateGraphFromData(const std::vector<unsigned char>& data);

    // Number of threads to use for parallel processing.
    unsigned int nThreads = 1;
};

#endif // QYRA_GRAPH_H
