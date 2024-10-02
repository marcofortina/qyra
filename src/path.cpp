// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <crypto.h>
#include <graph.h>
#include <hash.h>
#include <path.h>
#include <stream.h>
#include <utils.h>

#include <algorithm>
#include <fstream>
#include <iostream>
#include <mutex>
#include <numeric>
#include <sstream>
#include <thread>

// Constructs a CPath from a set of nodes.
CPath::CPath(const std::vector<uint16_t>& nodes) : nodes(nodes) {}

// Retrieves the nodes of the path.
const std::vector<uint16_t>& CPath::GetNodes() const
{
    // Return the nodes vector.
    return nodes;
}

// Computes the SHA3-256 hash of the path.
std::vector<unsigned char> CPath::GetHash() const
{
    CStream s;

    for (uint16_t node : nodes) {
        s << node;
    }

    // Return the hash of the byte vector.
    return CHasher::BLAKE3(s.Data());
}

// Validates the path against the graph.
bool CPath::IsValid(const CGraph& graph) const
{
#ifdef DEBUG
    std::cout << __func__ << " - nodes.size(): " << nodes.size() << std::endl;
#endif

    // Empty path is invalid.
    if (nodes.empty()) {
        fprintf(stderr, "ERROR: [%s] Empty nodes\n", __func__);
        return false;
    }

    // Retrieve the adjacency matrix.
    const auto& adjacencyMatrix = graph.GetAdjacencyMatrix();

    // Validate each edge in the path.
    for (std::size_t i = 0; i < nodes.size() - 1; ++i) {
        // Current node in the sequence.
        uint16_t from = nodes[i];
        // Next node in the sequence.
        uint16_t to = nodes[i + 1];

#ifdef DEBUG
        std::cout << __func__ << " - Edge: " << from << " -> " << to << std::endl;
#endif

        // Check edge validity.
        if (from >= MAX_NODES || to >= MAX_NODES || !adjacencyMatrix[from].test(to)) {
#ifdef DEBUG
            std::cout << __func__ << " - MAX_NODES: " << MAX_NODES << std::endl;
            std::cout << __func__ << " - from: " << from << std::endl;
            std::cout << __func__ << " - to: " << from << std::endl;
            std::cout << __func__ << " - test: " << adjacencyMatrix[from].test(to) << std::endl;
#endif

            return false;
        }
    }

    // All edges are valid.
    return true;
}

void CPath::Clear()
{
    // Clear nodes
    nodes.clear();
}

// Validates if the given hash matches the hash of a path found in the provided graph.
bool CPath::Validate(const std::vector<unsigned char>& hash, const CGraph& graph)
{
#ifdef DEBUG
    printf("hash (size=%zu): %s\n", hash.size(), FormatHex(hash).data());
#endif

    // Find the path in the provided graph
    std::vector<uint16_t> foundPath = FindDFS(graph);

    // Get the hash of the found path
    std::vector<unsigned char> foundHash = GetHash();

#ifdef DEBUG
    printf("foundHash (size=%zu): %s\n", foundHash.size(), FormatHex(foundHash).data());
#endif

    // Compare the hashes
    return foundHash == hash;
}

// Converts the path to a string.
std::string CPath::ToString() const
{
    CStream s;

    for (uint16_t node : nodes) {
        s << node;
    }

    // Return hex representation.
    return FormatHex(s.Data());
}

// Returns the number of nodes in the path.
std::size_t CPath::Size() const
{
    // Return the count of nodes.
    return nodes.size();
}

// Saves the nodes to a file
bool CPath::SaveNodesToFile(const std::string& filename) const
{
    std::ofstream outFile(filename, std::ios::binary);
    if (!outFile) {
        fprintf(stderr, "ERROR: [%s] Could not open file for writing: %s\n", __func__, filename.c_str());

        // Return false on failure
        return false;
    }

    // Write each uint16_t to the file
    outFile.write(reinterpret_cast<const char*>(nodes.data()), nodes.size() * sizeof(uint16_t));

    if (!outFile) {
        fprintf(stderr, "ERROR: [%s] Failed to write nodes to file: %s\n", __func__, filename.c_str());

        // Return false on failure
        return false;
    }

    // Return true on success
    return true;
}

// Utility function for Depth-First Search (DFS) to find the longest path
void CPath::DFSHelper(const CGraph& graph, std::size_t node, std::vector<bool>& visited, std::vector<uint16_t>& currentPath, std::vector<uint16_t>& longestPath, std::mutex& mtx)
{
    // Mark the current node as visited and add it to the current path
    visited[node] = true;
    currentPath.push_back(node);

    // Get the neighbors of the current node from the adjacency matrix
    std::bitset<MAX_NODES> neighbors = graph.adjacencyMatrix[node];

    // Explore unvisited neighbors efficiently using _Find_first and _Find_next
    for (std::size_t neighbor = neighbors._Find_first();
         neighbor < MAX_NODES;
         neighbor = neighbors._Find_next(neighbor)) {
        // If the neighbor hasn't been visited, recurse into DFS
        if (!visited[neighbor]) {
            DFSHelper(graph, neighbor, visited, currentPath, longestPath, mtx);
        }
    }

    // If we reached a leaf node (no further neighbors)
    if (neighbors.none()) {
        // Lock the mutex for thread safety
        std::lock_guard<std::mutex> lock(mtx);

        // Check if the current path is longer than the longest path found so far
        if (currentPath.size() > longestPath.size()) {
            longestPath = currentPath;
        }
    }

    // Backtrack: remove the current node from the path and mark it as unvisited
    currentPath.pop_back();
    visited[node] = false;
}

// Finds the longest path in the graph represented by the adjacency matrix
std::vector<uint16_t> CPath::FindDFS(const CGraph& graph)
{
    // Clear the current path to avoid dirty adjacencyMatrix
    Clear();

    // Mutex for thread safety when updating longestPath
    std::mutex mtx;

    // Get the total number of nodes
    unsigned int totalNodes = MAX_NODES;

    // Create a vector of threads
    std::vector<std::thread> threads;

    // Vector to store the longest path found by all threads
    std::vector<uint16_t> longestPath;

    // Divide work among threads
    for (unsigned int threadIndex = 0; threadIndex < graph.nThreads; ++threadIndex) {
        threads.emplace_back([&, threadIndex]() {
            // Vector to store the current path during the DFS traversal for this thread
            std::vector<uint16_t> currentPath;

            // Calculate the number of nodes each thread will process
            unsigned int nodesPerThread = totalNodes / graph.nThreads;

            // Determine start and end range for this thread
            uint16_t startNode = threadIndex * nodesPerThread;
            uint16_t endNode = (threadIndex + 1 == graph.nThreads) ? totalNodes : startNode + nodesPerThread;

            // Iterate through the assigned nodes
            for (uint16_t start = startNode; start < endNode; ++start) {
                // Skip nodes without edges
                if (graph.adjacencyMatrix[start].none()) {
                    continue;
                }

                // Track visited nodes
                std::vector<bool> visited(MAX_NODES, false);

                // Start DFS from the valid node
                DFSHelper(graph, start, visited, currentPath, longestPath, mtx);
            }
        });
    }

    // Wait for all threads to finish
    for (auto& thread : threads) {
        thread.join();
    }

#ifdef DEBUG
    std::cout << "Depth-First Search (DFS): ";
    for (std::size_t node : longestPath) {
        std::cout << node << " ";
    }
    std::cout << std::endl;
#endif

    // Store the longest path in nodes
    nodes = longestPath;

    // Return the longest path found
    return longestPath;
}