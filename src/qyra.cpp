// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <qyra.h>

#include <graph.h>
#include <path.h>
#include <stream.h>
#include <utils.h>

#include <stdio.h>
#include <thread>
#include <vector>

namespace LibQYRA {
// Constructs a CQYRA object and initializes internal components.
CQYRA::CQYRA() : graph(nullptr), path(nullptr)
{
    graph = new CGraph();
    path = new CPath();
}

// Destroys the CQYRA object, freeing allocated resources.
CQYRA::~CQYRA()
{
    delete graph;
    delete path;
}

// Assembles cryptographic data into a single vector.
std::vector<unsigned char> Assemble(CCryptoData cryptoData)
{
    CStream s;

    s << cryptoData.enc;
    s << cryptoData.iv;
    s << cryptoData.ciphertext;
    s << cryptoData.hash;

    return s.Data();
}

// Clears the current solution data.
void CSolutionData::Clear()
{
    solution.clear();
}

// Returns the current solution as a vector of unsigned chars.
std::vector<unsigned char> CSolutionData::Get() const
{
    return solution;
}

// Converts the solution to a human-readable string format.
std::string CSolutionData::ToString() const
{
    return FormatHex(solution);
}

// Returns the size of the current solution data.
std::size_t CSolutionData::Size() const
{
    return solution.size();
}

// Initializes the Qyra system with public and secret keys.
bool CQYRA::Initialize(const uint8_t* public_key, const uint8_t* secret_key)
{
    // Attempt to initialize the graph and return true or false based on success.
    return graph->Initialize(public_key, secret_key);
}

// Enables DFS parallelization by setting the number of threads based on system cores.
void CQYRA::EnableParallelDFS()
{
    // Get the number of cores available on the system
    uint8_t numCores = std::thread::hardware_concurrency();

    // Set the number of threads for parallel DFS in the graph
    graph->SetNumThreads(numCores);
}

// Sets the header data.
void CQYRA::SetHeader(const std::vector<unsigned char>& vch)
{
    graph->SetHeader(vch);
}

// Sets the nonce data.
void CQYRA::SetNonce(const std::vector<unsigned char>& vch)
{
    graph->SetNonce(vch);
}

// Validates the provided solution by checking both the graph and path.
bool CQYRA::Validate(const std::vector<unsigned char>& vch) const
{
    // Ensure the solution vector has the expected size.
    if (vch.size() < SOLUTION_SIZE) {
        fprintf(stderr, "ERROR: [%s] Solution vector size is less than expected.\n", __func__);

        // Return false on failure
        return false;
    }

    // Unpack the solution into its components: graph and path hash.
    std::vector<unsigned char> graphData;
    std::vector<unsigned char> pathHash;

    graphData.resize(TOTAL_SIZE);
    pathHash.resize(HASH_SIZE);

    CStream s(vch);
    s >> graphData;
    s >> pathHash;

    // Validate the graph.
    if (!graph->Validate(graphData)) {
        fprintf(stderr, "ERROR: [%s] Graph validation failed.\n", __func__);

        // Return false on failure
        return false;
    }

    // Validate the path using the hash and the graph.
    if (!path->Validate(pathHash, *graph)) {
        fprintf(stderr, "ERROR: [%s] Path validation failed.\n", __func__);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Starts the mining process to find a solution to the graph.
bool CQYRA::Mine()
{
    // Build the graph from header and nonce
    if (!graph->Generate()) {
        // Log error message
        fprintf(stderr, "ERROR: [%s] Failed to generate the graph.\n", __func__);

        // Return false on failure
        return false;
    }

    // Check if the graph was generated successfully.
    // If the graph size is zero, it means the graph was not generated correctly.
    if (graph->Size() == 0) {
        fprintf(stderr, "ERROR: [%s] Graph size is zero.\n", __func__);

        // Return false on failure
        return false;
    }

    // Finds the longest path in the graph using Depth-First Search (DFS).
    std::vector<uint16_t> foundPath = path->FindDFS(*graph);

    // Check if a valid path was found.
    // If the path size is zero, it indicates no valid path was found.
    if (path->Size() == 0) {
        fprintf(stderr, "ERROR: [%s] No valid path found.\n", __func__);

        // Return false on failure
        return false;
    }

    // Check if the found path is valid.
    // If the path is not valid according to the `IsValid` method,
    // the mining process is considered unsuccessful, and `false` is returned.
    if (!path->IsValid(*graph)) {
        fprintf(stderr, "ERROR: [%s] Invalid path found.\n", __func__);

        // Return false on failure
        return false;
    }

    // Clear any existing solution data before storing the new result.
    solution.Clear();

    // Get encryption message
    solution.cryptoData.enc = graph->GetEncMessage();

    // Get initialization vector
    solution.cryptoData.iv = graph->GetIV();

    // Get ciphertext
    solution.cryptoData.ciphertext = graph->GetCiphertext();

    // Get hash of the path
    solution.cryptoData.hash = path->GetHash();

    // Verify that all cryptographic data is non-empty.
    // If any of the data fields are empty, the mining process failed.
    if (solution.cryptoData.enc.empty() ||
        solution.cryptoData.iv.empty() ||
        solution.cryptoData.ciphertext.empty() ||
        solution.cryptoData.hash.empty()) {
        fprintf(stderr, "ERROR: [%s] Cryptographic data is empty.\n", __func__);

        // Return false on failure
        return false;
    }

    // Assemble the cryptographic data into a single solution vector.
    solution = Assemble(solution.cryptoData);

#ifdef DEBUG
    printf("solution hash (size=%zu): %s\n", solution.cryptoData.hash.size(), FormatHex(solution.cryptoData.hash).data());
#endif

    // Check if the assembled solution vector is valid.
    // If the solution vector size is zero, it indicates that the assembly failed.
    if (solution.Size() == 0) {
        fprintf(stderr, "ERROR: [%s] Assembled solution vector size is zero.\n", __func__);

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Checks if the current solution is valid.
bool CQYRA::IsValid() const
{
    return path->IsValid(*graph);
}

} // namespace LibQYRA