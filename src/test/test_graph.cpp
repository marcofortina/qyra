// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <test.h>

#include <graph.h>
#include <path.h>
#include <qyra.h>
#include <stream.h>
#include <utils.h>

// IWYU pragma: no_include <boost/preprocessor/arithmetic/limits/dec_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/comparison/limits/not_equal_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/control/expr_iif.hpp>
// IWYU pragma: no_include <boost/preprocessor/control/iif.hpp>
// IWYU pragma: no_include <boost/preprocessor/detail/limits/auto_rec_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/logical/compl.hpp>
// IWYU pragma: no_include <boost/preprocessor/logical/limits/bool_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/repetition/detail/limits/for_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/repetition/for.hpp>
// IWYU pragma: no_include <boost/preprocessor/seq/limits/elem_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/seq/limits/size_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/tuple/elem.hpp>
// IWYU pragma: no_include <boost/preprocessor/variadic/limits/elem_64.hpp>
// IWYU pragma: no_include <boost/test/tools/old/interface.hpp>
// IWYU pragma: no_include <boost/test/tree/auto_registration.hpp>
// IWYU pragma: no_include <boost/test/unit_test_suite.hpp>
// IWYU pragma: no_include <boost/test/utils/basic_cstring/basic_cstring.hpp>
// IWYU pragma: no_include <boost/test/utils/lazy_ostream.hpp>

#include <boost/test/unit_test.hpp> // IWYU pragma: keep
#include <iostream>
#include <stdint.h>
#include <string>
#include <thread>
#include <vector>

// Define a test suite for testing the CGraph class.
BOOST_FIXTURE_TEST_SUITE(TestCGraph, ExtendedTestingSetup)

// Test case for graph generation.
BOOST_AUTO_TEST_CASE(Generate)
{
    // Create a graph object.
    CGraph graph;

    // Create a path object.
    CPath path;

    // Initialize the graph with public and secret keys.
    BOOST_CHECK(graph.Initialize(publicKey, secretKey) == true);

    // Get the number of cores available on the system
    uint8_t numCores = std::thread::hardware_concurrency();

    // Set the number of threads to be used for parallel DFS processing
    graph.SetNumThreads(numCores);

    // Set the header for the graph.
    graph.SetHeader(header);

    // Set the nonce for the graph.
    graph.SetNonce(nonce);

    // Generate the graph structure.
    BOOST_CHECK(graph.Generate() == true);

    // Use Depth-First Search (DFS) to find a path in the graph.
    BOOST_CHECK_NO_THROW(path.FindDFS(graph));

    // Get the graph hash
    std::vector<unsigned char> graphHash = graph.GetHash();

    // Get the path hash
    std::vector<unsigned char> pathHash = path.GetHash();

    // Get the encrypted message
    std::vector<unsigned char> encMessage = graph.GetEncMessage();

    // Get the ciphertext
    std::vector<unsigned char> cipherText = graph.GetCiphertext();

    // Get the initialization vector
    std::vector<unsigned char> iv = graph.GetIV();

    // Check if hash of the path is valid
    BOOST_CHECK(path.Validate(pathHash, graph) == true);

    // Check if path is valid
    BOOST_CHECK(path.IsValid(graph) == true);

#ifdef DEBUG
    // Print debug information when in DEBUG mode.
    std::cout << "header:     " << FormatHex(header) << std::endl;
    std::cout << "nonce:      " << FormatHex(nonce) << std::endl;

    std::cout << "encMessage: " << FormatHex(encMessage) << std::endl;
    std::cout << "IV:         " << FormatHex(iv) << std::endl;
    std::cout << "cipherText: " << FormatHex(cipherText) << std::endl;
    std::cout << "path:       " << path.ToString() << std::endl;

    std::cout << "graphHash:  " << FormatHex(graphHash) << std::endl;
    std::cout << "pathHash:   " << FormatHex(pathHash) << std::endl;

    // Check if the path is valid based on the graph.
    std::cout << "Valid:      " << (path.IsValid(graph) ? "True" : "False") << std::endl;

    // Save adjacency matrix and nodes for debugging
    graph.SaveAdjacencyMatrixToFile("adjacency_matrix.bin");
    path.SaveNodesToFile("nodes.bin");
#endif

    // Prepare a stream to pack the encrypted message, IV, ciphertext, and path hash.
    CStream s;
    s << encMessage;
    s << iv;
    s << cipherText;
    s << pathHash;

    // Extract the packed solution data.
    std::vector<unsigned char> solution = s.Data();

#ifdef DEBUG
    // Print debug information when in DEBUG mode.
    std::cout << "Solution Data: " << FormatHex(solution) << std::endl;
    std::cout << "Solution Size: " << solution.size() << " )" << std::endl;
#endif
}

// Test case for validating the solution.
BOOST_AUTO_TEST_CASE(Validate)
{
    // Sample solution string (hexadecimal representation).
    std::string solutionStr = "fc29160c7d3218a064b6a3c4ecbed083fb959c5d31887cf0bc3a973df2d1514676f4c7486a2f7e0c624d54cbaa5b85cf39df334d1afaf16f00010ae1e41933a5647761bb20c0f291310735c3669c6a709c9b5739d96425937524ef117236c71190551e7cab08a30d596c28a46b033dacf1553e1643b97661a675e08681b68fa0f39d4ab667394c4bbbef69cab715b0acd8a3532de318f6ab25d86efc9ce642bb6a970f18229c381b3a05fb41c233bdcfcd4aeb312328de6e94af11eeecb375856be32bd4f9520935c6314401bfdae218f1a7aa08fdf4665bee58987039d02e236dbe97f4f27bf2fbeb1b124801a992365e3d6506d7713f898edb3be62438748a63bc35ddf3e3b6bc9f8118db3eba971e198e87bcde2ba16b30f52563558901a015cfa5a013dd0bf86de9c52243a0a995d30d97a9e9fb34bef3d4d8ef5aa8ffd1b76c939ae41d514c42ed8e7931418e5e7d71735c5ae7d665225d1fa8bdf52789fac366937ac9fc7539b93029e0d6c9e953ed4d9f532815a647ef099c305361061432e3894227bf7dec2da7e886655caa3b9cc10a7fc9dfeb272f89f869630371f050d53a84e03bde9a03af3ae67ee0b08f9006bef98ec0b8d6abff92aa0afe402d6375b22ede53fb123d2318eed89937b04190d8143f4358af27953d6191f4d976a4112a8a87616cdde418e95284c9b0a008bfa2ab01c860c650b67b2a5f7254a5484d14cad8ab72f5bf5c2838ca908044138c451357dbe683a9fa1f9800402656c98050dfcc35864453c1230de3036b887b9ffcf104291ec696b9bfd2de2ab3d210112bf981adac3f4f1b3eac3fe36393084541bb11b146bf21d5b31149cd0ff4a8db77885d51182f340603c4574781fec688668f89b0e0133a8361dc5c86a6bc77a70adf091065cba33a8212b836c16f7b902449f56fb35cc71bbc5094b13d7e019e24b02cbb18ef6d10c9a6a3ca8f093c04bb03c619e28076890822648b51e92f23697e172b1a6313ef9b257882cc7480e8c18e9a4c3769f0274105ea5a17ca3179c8ad38bfe55f62a59236d67d0973c0a1ae40fd2d778945e06fe706a971af547c3442080329b59d31b7b95b6a5a66494ea0f7e7fb532bc9b255a75421c3da0d15be37acde440fa7a8452604559bbe5389dfe3ae64dbee7a270127402e06cc1775dae75fea9f2635a88e096a6008b987e28d192a83b2cfedc3898a673363dbf8ab182cc14c20a372d49052311afdf22a9575677b7eddde0b3f13175499c61ebfe3bbb72ef26c04b58866af686cc88e6a174a078f132ed0b0de58f273274aefa9a0676d1caa8eb5347970117d1621fcfc556499925fc1b7934122db4a5777356e8ddea38a7853f03324c2cbb919a5f39cd79c3dad2c09e900f7f4217946ff3cc1c3615aeed05d9d1a89e1666db252f015238000a195c9177dd7e861a7c46cfa228e37d1b41a8b63c8b51f04f3e789cc7612d314726b96f8d0d880387277d63a0a982db575f39a05ea3dc9797af4e80490a55ef66ed13c2c1bf01254494f1a21b59b4e311912ec510faeecee9909437a020288ae490bba8a2118fddcb5e31ce5c4775987e816c9c550424d3726992c5db25d372171aee05d4d13b78ce1fde85ff876f2c742832faeed26ecef521ada37e0859c10e42c82f0e5a4bdc5f057eddda571ebf981af5bd0056563ebe682c1fafc27e4fb1c47864f3db26761b0d08c6cd78fbed0ac92adde51b634683ea2ab06af93f2883ee528ec3cb0edc9a3ba7ac10401c4ae3fdcae1184d12a76fcb45a2b1c754a84fffbbea28c92e5c031f6e2";

    // Parse the hex representation of the solution string into a byte vector
    std::vector<unsigned char> solution = ParseHex(solutionStr);

    // Unpack the solution into its components: graph and path hash.
    std::vector<unsigned char> graphData;
    std::vector<unsigned char> pathHash;

    // Resize the vectors to appropriate sizes
    graphData.resize(TOTAL_SIZE);
    pathHash.resize(HASH_SIZE);

    // Create a stream to extract data from the solution
    CStream s(solution);
    s >> graphData;
    s >> pathHash;

#ifdef DEBUG
    // Print debug information when in DEBUG mode.
    std::cout << "graphData: " << FormatHex(graphData) << std::endl;
    std::cout << "pathHash:  " << FormatHex(pathHash) << std::endl;
#endif

    // Create a new CGraph object
    CGraph graph;

    // Initialize the graph with public and secret keys
    BOOST_CHECK_NO_THROW(graph.Initialize(publicKey, secretKey));

    // Get the number of cores available on the system
    uint8_t numCores = std::thread::hardware_concurrency();

    // Set the number of threads to be used for parallel DFS processing
    graph.SetNumThreads(numCores);

    // Set the header and nonce for the graph
    graph.SetHeader(header);
    graph.SetNonce(nonce);

    // Validate the graph data extracted from the solution
    BOOST_CHECK_EQUAL(graph.Validate(graphData), true);

    // Expected values for the encrypted message, initialization vector (IV), ciphertext,
    // hash of the path, and hash of the graph
    std::string expectedEncMessage = "fc29160c7d3218a064b6a3c4ecbed083fb959c5d31887cf0bc3a973df2d1514676f4c7486a2f7e0c624d54cbaa5b85cf39df334d1afaf16f00010ae1e41933a5647761bb20c0f291310735c3669c6a709c9b5739d96425937524ef117236c71190551e7cab08a30d596c28a46b033dacf1553e1643b97661a675e08681b68fa0f39d4ab667394c4bbbef69cab715b0ac";
    std::string expectedIV = "d8a3532de318f6ab25d86efc9ce642bb";
    std::string expectedCiphertext = "6a970f18229c381b3a05fb41c233bdcfcd4aeb312328de6e94af11eeecb375856be32bd4f9520935c6314401bfdae218f1a7aa08fdf4665bee58987039d02e236dbe97f4f27bf2fbeb1b124801a992365e3d6506d7713f898edb3be62438748a63bc35ddf3e3b6bc9f8118db3eba971e198e87bcde2ba16b30f52563558901a015cfa5a013dd0bf86de9c52243a0a995d30d97a9e9fb34bef3d4d8ef5aa8ffd1b76c939ae41d514c42ed8e7931418e5e7d71735c5ae7d665225d1fa8bdf52789fac366937ac9fc7539b93029e0d6c9e953ed4d9f532815a647ef099c305361061432e3894227bf7dec2da7e886655caa3b9cc10a7fc9dfeb272f89f869630371f050d53a84e03bde9a03af3ae67ee0b08f9006bef98ec0b8d6abff92aa0afe402d6375b22ede53fb123d2318eed89937b04190d8143f4358af27953d6191f4d976a4112a8a87616cdde418e95284c9b0a008bfa2ab01c860c650b67b2a5f7254a5484d14cad8ab72f5bf5c2838ca908044138c451357dbe683a9fa1f9800402656c98050dfcc35864453c1230de3036b887b9ffcf104291ec696b9bfd2de2ab3d210112bf981adac3f4f1b3eac3fe36393084541bb11b146bf21d5b31149cd0ff4a8db77885d51182f340603c4574781fec688668f89b0e0133a8361dc5c86a6bc77a70adf091065cba33a8212b836c16f7b902449f56fb35cc71bbc5094b13d7e019e24b02cbb18ef6d10c9a6a3ca8f093c04bb03c619e28076890822648b51e92f23697e172b1a6313ef9b257882cc7480e8c18e9a4c3769f0274105ea5a17ca3179c8ad38bfe55f62a59236d67d0973c0a1ae40fd2d778945e06fe706a971af547c3442080329b59d31b7b95b6a5a66494ea0f7e7fb532bc9b255a75421c3da0d15be37acde440fa7a8452604559bbe5389dfe3ae64dbee7a270127402e06cc1775dae75fea9f2635a88e096a6008b987e28d192a83b2cfedc3898a673363dbf8ab182cc14c20a372d49052311afdf22a9575677b7eddde0b3f13175499c61ebfe3bbb72ef26c04b58866af686cc88e6a174a078f132ed0b0de58f273274aefa9a0676d1caa8eb5347970117d1621fcfc556499925fc1b7934122db4a5777356e8ddea38a7853f03324c2cbb919a5f39cd79c3dad2c09e900f7f4217946ff3cc1c3615aeed05d9d1a89e1666db252f015238000a195c9177dd7e861a7c46cfa228e37d1b41a8b63c8b51f04f3e789cc7612d314726b96f8d0d880387277d63a0a982db575f39a05ea3dc9797af4e80490a55ef66ed13c2c1bf01254494f1a21b59b4e311912ec510faeecee9909437a020288ae490bba8a2118fddcb5e31ce5c4775987e816c9c550424d3726992c5db25d372171aee05d4d13b78ce1fde85ff876f2c742832faeed26ecef521ada37e0859c10e42c82f0e5a4bdc5f057eddda571ebf981af5bd0056563ebe682c1fafc27e4fb1c47864f3db26761b0d08c6cd78fbed0ac92adde51b634683ea2ab06af93f2883ee528ec3cb0edc9a3ba7a";
    std::string expectedGraphHash = "b70ab216563abb831549fd137ed35cec152f027f6590b67e56bf96a0506c7065";
    std::string expectedPathHash = "c10401c4ae3fdcae1184d12a76fcb45a2b1c754a84fffbbea28c92e5c031f6e2";

    // Check if the formatted ciphertext from the graph matches the expected ciphertext
    BOOST_CHECK_EQUAL(FormatHex(graph.GetCiphertext()), expectedCiphertext);

    // Check if the formatted hash of the graph matches the expected graph hash
    BOOST_CHECK_EQUAL(FormatHex(graph.GetHash()), expectedGraphHash);

    // Check if the formatted encrypted message from the graph matches the expected encrypted message
    BOOST_CHECK_EQUAL(FormatHex(graph.GetEncMessage()), expectedEncMessage);

    // Check if the formatted initialization vector from the graph matches the expected initialization vector
    BOOST_CHECK_EQUAL(FormatHex(graph.GetIV()), expectedIV);

    // Create a CPath object for validation
    CPath path;

    // Validate the path against the provided path hash and the graph
    BOOST_CHECK_EQUAL(path.Validate(pathHash, graph), true);

    // Check if the formatted hash of the path matches the expected path hash
    BOOST_CHECK_EQUAL(FormatHex(path.GetHash()), expectedPathHash);
}

// End of test suite for CGraph class.
BOOST_AUTO_TEST_SUITE_END()