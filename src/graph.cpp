// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <common.h>
#include <crypto.h>
#include <graph.h>
#include <hash.h>
#include <stream.h>
#include <utils.h>

#include <algorithm>
#include <array>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <stdexcept>
#include <thread>
#include <unordered_set>

// Constructor of the CGraph class.
// Initializes the adjacency matrix with a maximum number of nodes.
CGraph::CGraph() : adjacencyMatrix(MAX_NODES) {}

// Adds an edge between two nodes in the graph.
bool CGraph::AddEdge(uint16_t from, uint16_t to)
{
    // Check if the 'from' and 'to' nodes are valid (less than MAX_NODES)
    if (from >= MAX_NODES) {
        fprintf(stderr, "ERROR: [%s] 'from' node index (%u) is out of bounds (MAX_NODES = %zu)!\n", __func__, from, MAX_NODES);

        // Return false on failure
        return false;
    }
    if (to >= MAX_NODES) {
        fprintf(stderr, "ERROR: [%s] 'to' node index (%u) is out of bounds (MAX_NODES = %zu)!\n", __func__, to, MAX_NODES);

        // Return false on failure
        return false;
    }

    // Skip processing if the 'from' node has already been modified.
    if (!adjacencyMatrix[from].none()) {
        return true;
    }

#ifdef DEBUG
    printf("%s: %u -> %u\n", __func__, from, to);
#endif

    // Reset the bitset for the 'from' node, clearing all edges from this node.
    adjacencyMatrix[from].reset();

    try {
        // Set the bit indicating an edge from 'from' to 'to'.
        adjacencyMatrix[from].set(to);
    } catch (const std::exception& e) {
        fprintf(stderr, "ERROR: [%s] Failed to set edge from %u to %u: %s\n", __func__, from, to, e.what());

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Initializes the graph and generates cryptographic keys.
bool CGraph::Initialize(const uint8_t* public_key, const uint8_t* secret_key)
{
    // Initialize the adjacency matrix with bitsets
    adjacencyMatrix.resize(MAX_NODES);

    // Check if public_key is null
    if (!public_key) {
        fprintf(stderr, "ERROR: [%s] Invalid public_key: pointer is null.\n", __func__);

        // Return false on failure
        return false;
    }

    // Copy the content of public_key to publicKey
    std::copy(public_key, public_key + OQS_KEM_kyber_768_length_public_key, publicKey);

    // Check if secret_key is null
    if (!secret_key) {
        fprintf(stderr, "ERROR: [%s] Invalid secret_key: pointer is null.\n", __func__);

        // Return false on failure
        return false;
    }

    // Copy the content of secret_key to secretKey
    std::copy(secret_key, secret_key + OQS_KEM_kyber_768_length_secret_key, secretKey);

    // Return true on success
    return true;
}

void CGraph::Clear()
{
    // Clear adjacencyMatrix
    adjacencyMatrix.clear();

    // Initialize the adjacency matrix with bitsets
    adjacencyMatrix.resize(MAX_NODES);
}

// Sets the header used in cryptographic operations.
void CGraph::SetHeader(const std::vector<unsigned char>& vch)
{
    header = vch;
}

// Sets the nonce used in cryptographic operations.
void CGraph::SetNonce(const std::vector<unsigned char>& vch)
{
    nonce = vch;
}

// Private function to update the graph with the given data.
bool CGraph::UpdateGraphFromData(const std::vector<unsigned char>& data)
{
    // Avoid dirty adjacencyMatrix
    Clear();

    // Check if data is empty
    if (data.empty()) {
        fprintf(stderr, "ERROR: [%s] Decrypted data is empty!\n", __func__);

        // Return false on failure
        return false;
    }

    // Initialize a set to keep track of visited nodes.
    std::unordered_set<uint16_t> visited;

    // Convert data to std::vector<uint16_t>
    std::vector<uint16_t> edges = Pack12(data);

    // Check if the edges vector is valid
    if (edges.size() < 2) {
        fprintf(stderr, "ERROR: [%s] Insufficient edges to update the graph!\n", __func__);

        // Return false on failure
        return false;
    }

    // Update the adjacency matrix with edges based on the converted data.
    for (std::size_t i = 0; i < (edges.size() - 1); ++i) {
        // Starting node of the edge.
        uint16_t from = edges[i];

        // Ending node of the edge.
        uint16_t to = edges[i + 1];

        // Avoid adding a self-loop and prevent creating cycles.
        if (from != to && visited.find(to) == visited.end()) {
            // Add an edge to the adjacency matrix.
            if (!AddEdge(from, to)) {
                fprintf(stderr, "ERROR: [%s] Failed to add edge from %u to %u!\n", __func__, from, to);

                // Return false on failure
                return false;
            }

            // Attempt to add the 'from' node to the visited set.
            auto result = visited.insert(from);
            if (!result.second) {
#ifdef DEBUG
                fprintf(stderr, "ERROR: [%s] Node %u was already visited!\n", __func__, from);
#endif
            }
        }
    }

    // Return true on success
    return true;
}

// Encrypts the graph's data and updates the adjacency matrix with the encrypted data.
bool CGraph::Generate()
{
    // Combine the header and nonce into a single vector for encryption.
    CStream s;
    s << header;
    s << nonce;

#ifdef DEBUG
    printf("%s: s.Data() (size=%zu): %s\n", __func__, s.Size(), s.GetHex().data());
#endif

    // Create an instance of CCrypter
    CCrypter crypter;

    // Generate a shared secret and ciphertext.
    uint8_t sharedSecret[OQS_KEM_kyber_768_length_shared_secret];
    if (!crypter.GenerateCiphertext(ciphertext, sharedSecret, publicKey)) {
        fprintf(stderr, "ERROR: [%s] Failed to generate ciphertext!\n", __func__);

        // Return false on failure
        return false;
    }

#ifdef DEBUG
    printf("%s: sharedSecret (size=%zu): %s\n", __func__, sizeof(sharedSecret), FormatHex(sharedSecret).data());
    printf("%s: ciphertext   (size=%zu): %s\n", __func__, sizeof(ciphertext), FormatHex(ciphertext).data());
#endif

    // Encrypt the data.
    if (!crypter.EncryptData(s.Data(), enc, sharedSecret, iv)) {
        fprintf(stderr, "ERROR: [%s] Encryption failed!\n", __func__);

        // Return false on failure
        return false;
    }

#ifdef DEBUG
    printf("%s: iv (size=%zu): %s\n", __func__, iv.size(), FormatHex(iv).data());
    printf("%s: enc (size=%zu): %s\n", __func__, enc.size(), FormatHex(enc).data());
#endif

    // Update the graph using the encrypted data.
    if (!UpdateGraphFromData(enc)) {
        fprintf(stderr, "ERROR: [%s] Failed to update graph from encrypted data!\n", __func__);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Validates if the provided data was generated from a correct graph
// created with the right header and nonce.
bool CGraph::Validate(const std::vector<unsigned char>& vch)
{
    // Check if the input vector is empty
    if (vch.empty()) {
        fprintf(stderr, "ERROR: [%s] Invalid input vector: vector is empty.\n", __func__);

        // Return false on failure
        return false;
    }

    // Ensure the size of vch matches the expected size for enc, iv, and ciphertext.
    if (vch.size() != TOTAL_SIZE) {
        // Invalid data size for enc, iv, and ciphertext.
        fprintf(stderr, "ERROR: [%s] Invalid data size for enc, iv, and ciphertext: expected %u, got %zu.\n", __func__, TOTAL_SIZE, vch.size());

        // Return false on failure
        return false;
    }

    enc.resize(ENC_SIZE);
    iv.resize(IV_SIZE);

    // Unpack the solution into its components (use existing class members).
    CStream s(vch);
    s >> enc;
    s >> iv;
    s >> ciphertext;

#ifdef DEBUG
    printf("%s: ss (size=%zu): %s\n", __func__, s.Size(), s.GetHex().data());
    printf("%s: enc (size=%zu): %s\n", __func__, enc.size(), FormatHex(enc).data());
    printf("%s: iv (size=%zu): %s\n", __func__, iv.size(), FormatHex(iv).data());
    printf("%s: ciphertext (size=%zu): %s\n", __func__, sizeof(ciphertext), FormatHex(ciphertext).data());
#endif

    // Create an instance of CCrypter
    CCrypter crypter;

    // Recover the shared secret using the ciphertext and the secret key.
    uint8_t sharedSecret[OQS_KEM_kyber_768_length_shared_secret];
    if (!crypter.RecoverSharedSecret(sharedSecret, ciphertext, secretKey)) {
        fprintf(stderr, "ERROR: [%s] Failed to recover shared secret.\n", __func__);

        // Return false on failure
        return false;
    }

#ifdef DEBUG
    printf("%s: sharedSecret (size=%zu): %s\n", __func__, sizeof(sharedSecret), FormatHex(sharedSecret).data());
#endif

#ifdef DEBUG
    printf("%s: enc (size=%zu): %s\n", __func__, enc.size(), FormatHex(enc).data());
#endif

    // Decrypt the encrypted data (enc) using the recovered shared secret and the IV.
    std::vector<unsigned char> decryptedMessage;
    if (!crypter.DecryptData(enc, decryptedMessage, sharedSecret, iv)) {
        fprintf(stderr, "ERROR: [%s] Failed to decrypt data.\n", __func__);

        // Return false on failure
        return false;
    }

    // Combine the header and nonce to verify against the decrypted message.
    std::vector<unsigned char> expectedMessage(header);
    expectedMessage.insert(expectedMessage.end(), nonce.begin(), nonce.end());

#ifdef DEBUG
    printf("%s: decryptedMessage (size=%zu): %s\n", __func__, decryptedMessage.size(), FormatHex(decryptedMessage).data());
    printf("%s: expectedMessage (size=%zu): %s\n", __func__, expectedMessage.size(), FormatHex(expectedMessage).data());
#endif

    if (decryptedMessage != expectedMessage) {
        // The decrypted message doesn't match the expected header + nonce.
        return false;
    }

    // Update the graph using the encrypted data.
    if (!UpdateGraphFromData(enc)) {
        fprintf(stderr, "ERROR: [%s] Failed to update the graph from encrypted data.\n", __func__);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Computes the hash of the graph's adjacency matrix.
std::vector<unsigned char> CGraph::GetHash() const
{
    // Create a vector to hold the rows' binary data
    std::vector<unsigned char> data;

    // Process each row of the adjacency matrix
    for (const auto& row : adjacencyMatrix) {
        // Create a temporary vector for the current row
        std::vector<unsigned char> rowBytes(MAX_NODES / 8, 0);

        if (!row.none()) {
            // Fill the rowBytes vector from the bitset
            for (std::size_t i = 0; i < MAX_NODES; ++i) {
                if (row[i]) {
                    // Set the appropriate bit
                    rowBytes[i / 8] |= (1 << (i % 8));
                }
            }
        }

        // Append the current row's bytes to data
        data.insert(data.end(), rowBytes.begin(), rowBytes.end());
    }

    // Return the hash of the byte vector.
    return CHasher::BLAKE3(data);
}

// Converts the graph's adjacency matrix to a string representation.
std::string CGraph::ToString() const
{
    // Create a vector to hold the rows' binary data
    std::vector<unsigned char> data;

    // Process each row of the adjacency matrix
    for (const auto& row : adjacencyMatrix) {
        // Create a temporary vector for the current row
        std::array<unsigned char, MAX_NODES / 8> rowBytes = {0};
        if (!row.none()) {
            for (std::size_t i = 0; i < MAX_NODES; ++i) {
                if (row[i]) {
                    // Set the appropriate bit
                    rowBytes[i / 8] |= (1 << (i % 8));
                }
            }
        }

        // Append the current row's bytes to data
        data.insert(data.end(), rowBytes.begin(), rowBytes.end());
    }

    // Return hex representation.
    return FormatHex(data);
}

// Dumps the graph's adjacency matrix to the console.
void CGraph::Dump() const
{
    for (std::size_t i = 0; i < adjacencyMatrix.size(); ++i) {
        for (std::size_t j = 0; j < adjacencyMatrix.size(); ++j) {
            if (adjacencyMatrix[i].test(j)) {
                printf("Edge: %zu -> %zu\n", i, j);
            }
        }
    }
}

// Gets the total number of entries in the adjacency matrix.
std::size_t CGraph::Size() const
{
    std::size_t numNodes = adjacencyMatrix.size();
    return numNodes * numNodes;
}

// Retrieves the adjacency matrix of the graph.
const std::vector<std::bitset<MAX_NODES>>& CGraph::GetAdjacencyMatrix() const
{
    return adjacencyMatrix;
}

// Retrieves the encrypted message.
std::vector<unsigned char> CGraph::GetEncMessage() const
{
    return enc;
}

// Retrieves the ciphertext used in the key encapsulation.
std::vector<unsigned char> CGraph::GetCiphertext() const
{
    return std::vector<unsigned char>(ciphertext, ciphertext + OQS_KEM_kyber_768_length_ciphertext);
}

// Retrieves the initialization vector used in encryption.
std::vector<unsigned char> CGraph::GetIV() const
{
    return iv;
}

// Saves the adjacency matrix to a file
bool CGraph::SaveAdjacencyMatrixToFile(const std::string& filename) const
{
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        fprintf(stderr, "ERROR: [%s] Could not open file for writing: %s\n", __func__, filename.c_str());

        // Return false on failure
        return false;
    }

    // Write each bitset to the file
    for (const auto& row : adjacencyMatrix) {
        // Write the bitset as bytes
        std::array<unsigned char, MAX_NODES / 8> rowBytes = {0};

        if (!row.none()) {
            for (std::size_t i = 0; i < MAX_NODES; ++i) {
                if (row[i]) {
                    // Set the appropriate bit
                    rowBytes[i / 8] |= (1 << (i % 8));
                }
            }
        }

        outFile.write(reinterpret_cast<const char*>(rowBytes.data()), rowBytes.size());
        if (!outFile) {
            fprintf(stderr, "ERROR: [%s] Failed to write nodes to file: %s\n", __func__, filename.c_str());

            // Return false on failure
            return false;
        }
    }

    outFile.close();

    // Return true on success
    return true;
}

// Function to set the number of threads
void CGraph::SetNumThreads(unsigned int numThreads)
{
    // Ensure that the number of threads is valid (greater than 0 and less than or equal to the maximum allowed)
    assert(numThreads > 0 && numThreads <= std::thread::hardware_concurrency() && "Invalid number of threads!");

    // Set the number of threads
    nThreads = numThreads;
}