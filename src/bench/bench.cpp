// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <bench.h>
#include <common.h>
#include <data/solutions.json.h>
#include <fstream>
#include <graph.h>
#include <path.h>
#include <stream.h>
#include <utils.h>

#include <chrono>
#include <iostream>
#include <random>
#include <thread>
#include <vector>

// Define the number of rounds for the loop
#define NUM_ROUNDS 100

// Define the number of iterations for the loop
#define NUM_ITERATIONS 100

// Total number of solutions per second generated across all iterations
double totalGeneratedPerSecond = 0.0;

// Total number of solutions per second validated across all iterations
double totalValidatedPerSecond = 0.0;

// Variables to store the minimum and maximum solutions per second
double minGeneratedPerSecond = std::numeric_limits<double>::max();
double maxGeneratedPerSecond = 0.0;
double minValidatedPerSecond = std::numeric_limits<double>::max();
double maxValidatedPerSecond = 0.0;

/**
 * @brief Prints the number of solutions generated or validated per second.
 *
 * @param time Time taken in seconds.
 * @param solutions Number of solutions generated or validated.
 * @param label Descriptive label for the output.
 *
 * @return The calculated solutions per second.
 */
double PrintSolutionsPerSecond(double time, std::size_t solutions, const std::string& label)
{
    // Calculate solutions per second
    double solutionsPerSecond = solutions / time;

    // To hold the suffix for the units
    std::string suffix;

    // To hold the value to display
    double displayValue;

    // Determine the appropriate suffix and value based on the number of solutions
    if (solutionsPerSecond >= 1e9) {
        // Billions of solutions
        displayValue = solutionsPerSecond / 1e9;
        suffix = "GSol/s";
    } else if (solutionsPerSecond >= 1e6) {
        // Millions of solutions
        displayValue = solutionsPerSecond / 1e6;
        suffix = "MSol/s";
    } else if (solutionsPerSecond >= 1e3) {
        // Thousands of solutions
        displayValue = solutionsPerSecond / 1e3;
        suffix = "KSol/s";
    } else {
        // Solutions (<1000)
        displayValue = solutionsPerSecond;
        suffix = "sol/s";
    }

    // Print the result
    printf("%s: %.2f %s\n", label.c_str(), displayValue, suffix.c_str());

    // Return the solutions per second
    return solutionsPerSecond;
}

/**
 * @brief Generates a random vector of the specified size.
 *
 * @param size Size of the vector.
 *
 * @return A vector of random bytes.
 */
std::vector<unsigned char> GenerateRandomBytes(std::size_t size)
{
    // Create a vector to hold random bytes
    std::vector<unsigned char> vch(size);

    // Create a random number generator
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Fill the vector with random values
    for (std::size_t i = 0; i < size; ++i) {
        vch[i] = static_cast<unsigned char>(dis(gen));
    }

    return vch;
}

/**
 * @brief Benchmarks the generation of solutions.
 */
void BenchGenerated()
{
    // Create a graph object
    CGraph graph;

    // Create a path object
    CPath path;

    // Define time points for measurement
    std::chrono::high_resolution_clock::time_point start;
    std::chrono::high_resolution_clock::time_point end;

    // Duration for elapsed time measurement
    std::chrono::duration<double> elapsed;

    // Number of solutions generated
    std::size_t nGenerated = 0;

    // Initialize the graph with public and secret keys
    graph.Initialize(publicKey, secretKey);

    // Get the number of cores available on the system
    uint8_t numCores = std::thread::hardware_concurrency();

    // Set the number of threads to be used for parallel DFS processing
    graph.SetNumThreads(numCores);

    // Measure time for generation
    start = std::chrono::high_resolution_clock::now();

    // Loop to generate a number of solutions
    for (std::size_t i = 0; i < NUM_ITERATIONS; i++) {
        // Create the header for the graph
        int32_t nVersion = 2;
        std::vector<unsigned char> hashPrevBlock = GenerateRandomBytes(32);
        std::vector<unsigned char> hashMerkleRoot = GenerateRandomBytes(32);
        std::vector<unsigned char> hashReserved(32, 0x00);
        uint32_t nTime = GetTime();
        uint32_t nBits = 0x1e1a7099;

        // Create a stream to hold the header data
        CStream header;
        header << nVersion;
        header << hashPrevBlock;
        header << hashMerkleRoot;
        header << hashReserved;
        header << nTime;
        header << nBits;

        // Set the header in the graph
        graph.SetHeader(header.Data());

        // Generate a random nonce for the graph
        std::vector<unsigned char> nNonce = GenerateRandomBytes(32);

        // Set the nonce in the graph
        graph.SetNonce(nNonce);

        // Generate the graph
        graph.Generate();

        // Find a path using depth-first search
        std::vector<uint16_t> longestPath = path.FindDFS(graph);

#ifdef DEBUG
        // Get the path hash
        std::vector<unsigned char> pathHash = path.GetHash();

        // Get the encrypted message
        std::vector<unsigned char> encMessage = graph.GetEncMessage();

        // Get the ciphertext
        std::vector<unsigned char> cipherText = graph.GetCiphertext();

        // Get the initialization vector
        std::vector<unsigned char> iv = graph.GetIV();

        // Print debug information when in DEBUG mode.
        std::vector<unsigned char> graphHash = graph.GetHash();

        std::cout << "header Data: " << FormatHex(header.Data()) << std::endl;
        std::cout << "header Size: " << header.Size() << std::endl;
        std::cout << "nonce:       " << FormatHex(nNonce) << std::endl;

        std::cout << "encMessage:  " << FormatHex(encMessage) << std::endl;
        std::cout << "IV:          " << FormatHex(iv) << std::endl;
        std::cout << "cipherText:  " << FormatHex(cipherText) << std::endl;

        std::cout << "path:        " << path.ToString() << std::endl;
        std::cout << "pathHash:    " << FormatHex(pathHash) << std::endl;
        std::cout << "graphHash:   " << FormatHex(graphHash) << std::endl;

        // Check if the path is valid based on the graph.
        std::cout << "Valid:       " << (path.IsValid(graph) ? "True" : "False") << std::endl;

        // Prepare a stream to pack the encrypted message, IV, ciphertext, and path hash.
        CStream s;
        s << encMessage;
        s << iv;
        s << cipherText;
        s << pathHash;

        // Extract the packed solution data.
        std::vector<unsigned char> solution = s.Data();

        // Print debug information when in DEBUG mode.
        std::cout << "Solution Data: " << FormatHex(solution) << std::endl;
        std::cout << "Solution Size: " << solution.size() << " )" << std::endl;

        // Save adjacency matrix and nodes for debugging
        graph.SaveAdjacencyMatrixToFile("adjacency_matrix.bin");
        path.SaveNodesToFile("nodes.bin");
#endif

        // Increment the count of generated solutions
        ++nGenerated;
    }

    // Record end time
    end = std::chrono::high_resolution_clock::now();

    // Calculate total elapsed time
    elapsed = end - start;

    // Calculate and print the solutions per second
    double generatedPerSecond = PrintSolutionsPerSecond(elapsed.count(), nGenerated, "Generated Solutions");

    // Update total, min, and max generated solutions per second
    totalGeneratedPerSecond += generatedPerSecond;
    if (generatedPerSecond < minGeneratedPerSecond) {
        minGeneratedPerSecond = generatedPerSecond;
    }
    if (generatedPerSecond > maxGeneratedPerSecond) {
        maxGeneratedPerSecond = generatedPerSecond;
    }
}

/**
 * @brief Benchmarks the validation of solutions.
 */
void BenchValidated()
{
    // Create a graph object
    CGraph graph;

    // Create a path object
    CPath path;

    // Define time points for measurement
    std::chrono::high_resolution_clock::time_point start;
    std::chrono::high_resolution_clock::time_point end;

    // Duration for elapsed time measurement
    std::chrono::duration<double> elapsed;

    // Number of solutions validated
    std::size_t nValidated = 0;

    // Initialize the graph
    graph.Initialize(publicKey, secretKey);

    // Get the number of cores available on the system
    uint8_t numCores = std::thread::hardware_concurrency();

    // Set the number of threads to be used for parallel DFS processing
    graph.SetNumThreads(numCores);

    // Measure time for validation
    start = std::chrono::high_resolution_clock::now();

    // Loop to validate the generated solutions
    for (std::size_t i = 0; i < numSolutions; ++i) {
        // Vector to hold graph data
        std::vector<unsigned char> graphData;

        // Vector to hold path hash
        std::vector<unsigned char> pathHash;

        // Resize graph data vector
        graphData.resize(TOTAL_SIZE);

        // Resize path hash vector
        pathHash.resize(HASH_SIZE);

        // Create a stream from the solution
        CStream s(solutions[i].solution);
        s >> graphData;
        s >> pathHash;

        // Set header and nonce for the graph
        graph.SetHeader(solutions[i].header);
        graph.SetNonce(solutions[i].nonce);

        // Validate the graph.
        if (!graph.Validate(graphData)) {
            fprintf(stderr, "ERROR: [%s] Graph validation failed.\n", __func__);
        }

        // Validate the path using the hash and the graph.
        if (!path.Validate(pathHash, graph)) {
            fprintf(stderr, "ERROR: [%s] Path validation failed.\n", __func__);
        }

        // Increment the count of validated solutions
        ++nValidated;
    }

    // Record end time
    end = std::chrono::high_resolution_clock::now();

    // Calculate total elapsed time
    elapsed = end - start;

    // Calculate and print the solutions per second
    double validatedPerSecond = PrintSolutionsPerSecond(elapsed.count(), nValidated, "Validated Solutions");

    // Update total, min, and max validated solutions per second
    totalValidatedPerSecond += validatedPerSecond;
    if (validatedPerSecond < minValidatedPerSecond) {
        minValidatedPerSecond = validatedPerSecond;
    }
    if (validatedPerSecond > maxValidatedPerSecond) {
        maxValidatedPerSecond = validatedPerSecond;
    }
}

/**
 * @brief Runs the benchmark for a specific round.
 *
 * @param round The current round number.
 */
void Benchmark(std::size_t round)
{
    printf("Round: %zu\n", round + 1);
    BenchGenerated();
    BenchValidated();
    printf("------------------------------------------------\n");
}

int main()
{
    // Loop NUM_ROUNDS times, each time calling the Benchmark function with the current index (i) as the argument.
    for (std::size_t i = 0; i < NUM_ROUNDS; i++) {
        Benchmark(i);
    }

    // Calculate the averages for generated and validated solutions per second
    double avgGeneratedPerSecond = totalGeneratedPerSecond / NUM_ROUNDS;
    double avgValidatedPerSecond = totalValidatedPerSecond / NUM_ROUNDS;

    // Print the formatted summary of average, min, and max solutions per second
    printf("\n=============================================================\n");
    printf("Average Generated Solutions Per Second :     %10.2f sol/s\n", avgGeneratedPerSecond);
    printf("Average Validated Solutions Per Second :     %10.2f sol/s\n", avgValidatedPerSecond);
    printf("-------------------------------------------------------------\n");
    printf("Min Generated Solutions Per Second     :     %10.2f sol/s\n", minGeneratedPerSecond);
    printf("Max Generated Solutions Per Second     :     %10.2f sol/s\n", maxGeneratedPerSecond);
    printf("-------------------------------------------------------------\n");
    printf("Min Validated Solutions Per Second     :     %10.2f sol/s\n", minValidatedPerSecond);
    printf("Max Validated Solutions Per Second     :     %10.2f sol/s\n", maxValidatedPerSecond);
    printf("=============================================================\n");

    return 0;
}