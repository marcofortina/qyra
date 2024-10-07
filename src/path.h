// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef QYRA_PATH_H
#define QYRA_PATH_H

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class CGraph;

/**
 * @brief Represents a path in terms of a set of nodes.
 */
class CPath
{
public:
    /**
     * @brief Default constructor for CPath.
     *
     * Initializes an empty path.
     */
    CPath() : nodes() {}

    void Clear();

    /**
     * @brief Constructor that initializes the path with a given vector.
     *
     * @param nodes A vector of nodes to initialize the path.
     */
    CPath(const std::vector<uint16_t>& nodes);

    /**
     * @brief Retrieves the nodes of the path.
     *
     * @return A const reference to the vector of nodes.
     */
    const std::vector<uint16_t>& GetNodes() const;

    /**
     * @brief Computes and returns the SHA3-256 hash of the path.
     *
     * @return A vector of unsigned characters containing the hash.
     */
    std::vector<unsigned char> GetHash() const;

    /**
     * @brief Validates the path against the provided graph.
     *
     * @param graph A reference to the graph object.
     *
     * @return True if the path is valid, false otherwise.
     */
    bool IsValid(const CGraph& graph) const;

    /**
     * @brief Validates if the provided hash matches the hash of the path found in the graph.
     *
     * This function takes the input hash and a reference to the graph object. It uses the graph to find a path
     * and then compares the hash of the found path with the provided hash. If they match, the solution is valid.
     *
     * @param hash The vector containing the expected hash of the path.
     * @param graph The reference to the CGraph object from which the path is generated.
     *
     * @return True if the hashes match, indicating that the path was correctly found and verified, false otherwise.
     */
    bool Validate(const std::vector<unsigned char>& hash, const CGraph& graph);

    /**
     * @brief Converts the path to a string.
     *
     * @return A string representation of the path.
     */
    std::string ToString() const;

    /**
     * @brief Returns the number of nodes in the path.
     *
     * @return The size of the path (number of nodes).
     */
    std::size_t Size() const;

    /**
     * @brief Saves the nodes to a file
     *
     * @param filename Name of the output file
     *
     * @return True if the nodes were saved successfully; false otherwise.
     */
    bool SaveNodesToFile(const std::string& filename) const;

    /**
     * @brief Finds the longest path in the graph represented by the adjacency matrix.
     *
     * This function iterates through all nodes and performs DFS from each valid node.
     *
     * @param graph The reference to the CGraph object.
     *
     * @return A vector containing the nodes in the longest path found.
     */
    std::vector<uint16_t> FindDFS(const CGraph& graph);

private:
    ///< A vector containing the nodes of the path.
    std::vector<uint16_t> nodes;

    /**
     * @brief Utility function for Depth-First Search (DFS) to find the longest path.
     *
     * This function explores all possible paths from the current node recursively.
     *
     * @param graph The reference to the CGraph object.
     * @param node The current node being explored.
     * @param visited A vector that keeps track of visited nodes for the current thread's processing range.
     * @param currentPath A vector that stores the current path being explored.
     * @param longestPath A reference to the longest path found so far, which may be updated during the search.
     * @param mtx A mutex to protect access to shared data (longestPath) among multiple threads.
     */
    void DFSHelper(const CGraph& graph, std::size_t node, std::vector<bool>& visited, std::vector<uint16_t>& currentPath, std::vector<uint16_t>& longestPath, std::mutex& mtx);
};

#endif // QYRA_PATH_H