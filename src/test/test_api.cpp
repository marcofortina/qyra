// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <test.h>

#include <qyra.h>
#include <utils.h>

// IWYU pragma: no_include <boost/preprocessor/comparison/limits/not_equal_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/control/iif.hpp>
// IWYU pragma: no_include <boost/preprocessor/logical/compl.hpp>
// IWYU pragma: no_include <boost/preprocessor/logical/limits/bool_256.hpp>
// IWYU pragma: no_include <boost/test/tools/old/interface.hpp>
// IWYU pragma: no_include <boost/test/tree/auto_registration.hpp>
// IWYU pragma: no_include <boost/test/unit_test_suite.hpp>
// IWYU pragma: no_include <boost/test/utils/basic_cstring/basic_cstring.hpp>
// IWYU pragma: no_include <boost/test/utils/lazy_ostream.hpp>

#include <boost/test/unit_test.hpp> // IWYU pragma: keep
#include <iostream>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(TestAPI, ExtendedTestingSetup)

BOOST_AUTO_TEST_CASE(MineSolution)
{
    // Create an instance of CQYRA
    LibQYRA::CQYRA qyra;

    BOOST_CHECK(qyra.Initialize(publicKey, secretKey) == true);

    // Enables DFS parallelization
    qyra.EnableParallelDFS();

    // Set the header for the mining operation
    qyra.SetHeader(header);

    // Set the nonce for the mining operation
    qyra.SetNonce(nonce);

    BOOST_CHECK(qyra.Mine() == true);

    // Retrieve the generated solution
    std::vector<unsigned char> solution = qyra.solution.Get();

#ifdef DEBUG
    // Print debug information when in DEBUG mode.
    std::cout << "Solution: " << qyra.solution.ToString() << std::endl;
    std::cout << "Size: " << qyra.solution.Size() << std::endl;
    std::cout << "Path is valid: " << (qyra.IsValid() ? "True" : "False") << std::endl;
#endif
}

BOOST_AUTO_TEST_CASE(ValidateSolution)
{
    // Sample solution string (hexadecimal representation).
    std::string solutionStr = "cc59cde552fb99f2b3d822d585dc918419559912ea440af92578aa6f8bd70125b62bb1ed36bea744ba05f5f948e537bd44c0d71948bf2e946382d4fc20c01f2796e9ae06f9bcc4e4548a68539fed76d5358fe52727ff1d4eb77d30f5fcd19192d4b28c3f40de806c7921a03026bac3e5db20ddd55bacdb61da61529ce05376136d59b273604d10c992911950ec13229a3474f4524b12fbbcef6cd155790830d1bca2f43e45fa8c6b2d3c1ba432f4e40393ea4e6f6d629ffc89e104d29ae707360e01a34625f2dc86861f6d36684c64707dc85dc35c741ac0f047cfb050768adf1d2684480534d639be124a363db86404b414fa85080df1fc40c03710176dea70af3983cd8148cf3d7727746da813963f84e704e49dfd8518649c61c7774ebc2b6f32effb076793187e0df04c1783c20e0c6387956b21980d1eeb7288b85a4c8b14c19766ddae6f6bffb34c45658db3d0e46b6db5c1ca7d543bca37c5a6ad3a60802498713059ca605e8d0a3cc5c5e58468ced03942b51fb9249c92ec0a7b8b7054d5fa8957d3cefe98f2bf4aa18777010e9f9959a50004cc0479f46cb06ea382541770022928f91af72e175419b460356fb7f730bbaf5c5b6c1234787ba8785455fd7acfd9e8fc78e3e6d1e008fb25a37b5c6e7ad7384effde9815d825e54fdb96c36cbd8316d95e7eaab6e7a8c5a8a72f1294f139e10f01085f4cb67496958cc201d677ef8137ffa27e8f8bf7de5a2c418287bbf4e02ac0cb61bcd297f91145d6b1ce6a3ec2b4efcd73eb7f2558b1dca0dbedc8e8e71214e5cde8cabe85b90a30c7c2ab722a7c203e785a7712aba8da631fbbfb846e3eb3b9a2ce366eda411d5fcc8e547c93f1b388f875156fd1691c5df391c1050cece8e7ef4ada43f4761c4286b96970f68dd72e47a77706d127d5eb98de1bb1c0a8ed235e71523817db93322a156477aedf26881bbef264bf39b2a968db2b14c1bf0338ecd20cb6e65abec604d484d19e46d9a230f9b17c26981e11c7bf012ebac6a248bc62fb76960b5e1b2a006032ab6ccd93f18628cdcc4998bafdde0f50586d17cb3aaca4075b7c2a43a42343a4f5781737a4fd90ae6915bab2fef19002f28e05e8918ee01b00a0810cb0a68755b06df9076ac0efc8c6f9eb4b61790ff5e4c83add1a26070a565ff95184bd7956072f851683e86c980a6b988a1a9b4b645a9f0603000969245906a6dd0440f411a02127d65b507ffcc8c728fee416b7155150638d714e7bead421655945035e3971e9612051c13ede7755303c29f8f92de32d76d16433502672388c815035ca8fcfa02f63203c3fcae93122b5ac45409d1f4e573bc36c314e440b41cdb41313ecf26fc4b8f3e788d84e033c33d0b779ef137785547a07517df90d6725d6b2216b04b88f7d176917f0672e7877b5a656042be7609220c44db165497f5f0ad4fb125cdff136fbf08b44faa88596c79faa5db39dce2cbcd9bc485181b489e27dd5e5c9c52ccb15e5190923a0b563c35e96936a22afe7a21102445785e15b112263f14a98bb4f85eb51e02f16b781274dd72734bf8b00fc74869ce22ee97bc5f93074b2536bef03794bb46ff3df1b25be05ccbb2a1560a2f06792e27e058de1a968a856788241d7b841a505cc3a986575a3d2fd3a9be2beabe61eec980d42111ab1d754508da5c211535a857bcf0ab4ba03dbe111cfe856302a024592314765cd2b9eb5ac98e4fc601c6f88859a935b9f3d8ce6076b100d99b2f5f6fbac93a6959a0d46f89bbd90595e7bdf3f1a853450eb3e0d7d8622530709c17cc23d";

    // Parse the hex representation of the solution string into a byte vector
    std::vector<unsigned char> solution = ParseHex(solutionStr);

    // Create an instance of CQYRA
    LibQYRA::CQYRA qyra;

    BOOST_CHECK(qyra.Initialize(publicKey, secretKey) == true);

    // Set the header for the validating operation
    qyra.SetHeader(header);

    // Set the nonce for the validating operation
    qyra.SetNonce(nonce);

    // Validate the solution using the CQYRA Validate function
    BOOST_CHECK(qyra.Validate(solution) == true);

#ifdef DEBUG
    // Print debug information when in DEBUG mode.
    std::cout << "Path is valid: " << (qyra.IsValid() ? "True" : "False") << std::endl;
#endif
}

BOOST_AUTO_TEST_SUITE_END()