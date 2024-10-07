// Copyright (c) 2024 Marco Fortina
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include <test.h>

#include <crypto.h>

// IWYU pragma: no_include <oqs/kem_kyber.h>
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
// IWYU pragma: no_include <boost/preprocessor/seq/limits/enum_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/seq/limits/size_256.hpp>
// IWYU pragma: no_include <boost/preprocessor/tuple/elem.hpp>
// IWYU pragma: no_include <boost/preprocessor/variadic/limits/elem_64.hpp>
// IWYU pragma: no_include <boost/test/tools/old/interface.hpp>
// IWYU pragma: no_include <boost/test/tree/auto_registration.hpp>
// IWYU pragma: no_include <boost/test/unit_test_suite.hpp>
// IWYU pragma: no_include <boost/test/utils/basic_cstring/basic_cstring.hpp>
// IWYU pragma: no_include <boost/test/utils/lazy_ostream.hpp>

#include <boost/test/unit_test.hpp> // IWYU pragma: keep
#include <openssl/evp.h>
#include <oqs/oqs.h> // IWYU pragma: keep
#include <vector>

// Define a test suite for testing the CCrypter class.
BOOST_FIXTURE_TEST_SUITE(TestCCrypter, BasicTestingSetup)

// Test case for generating key pairs for encryption.
BOOST_AUTO_TEST_CASE(KeyPairs)
{
    CCrypter crypter;
    bool ret;

    // Check if key pair generation does not throw any exceptions.
    ret = crypter.GenerateKeyPair(public_key, secret_key);
    BOOST_CHECK(ret == true);

    // Verify the size of the generated public key matches the expected length.
    BOOST_CHECK_EQUAL(sizeof(public_key), OQS_KEM_kyber_768_length_public_key);

    // Verify the size of the generated secret key matches the expected length.
    BOOST_CHECK_EQUAL(sizeof(secret_key), OQS_KEM_kyber_768_length_secret_key);
}

// Test case for generating and recovering ciphertext and shared secrets.
BOOST_AUTO_TEST_CASE(Ciphertext)
{
    CCrypter crypter;
    bool ret;

    // Check if key pair generation does not throw any exceptions.
    ret = crypter.GenerateKeyPair(public_key, secret_key);
    BOOST_CHECK(ret == true);

    // Check if ciphertext generation does not throw any exceptions.
    ret = crypter.GenerateCiphertext(cipher_text, shared_secret_e, public_key);
    BOOST_CHECK(ret == true);

    // Verify the size of the generated ciphertext matches the expected length.
    BOOST_CHECK_EQUAL(sizeof(cipher_text), OQS_KEM_kyber_768_length_ciphertext);

    // Verify the size of the shared secret matches the expected length.
    BOOST_CHECK_EQUAL(sizeof(shared_secret_e), OQS_KEM_kyber_768_length_shared_secret);

    // Check if recovering the shared secret does not throw any exceptions.
    ret = crypter.RecoverSharedSecret(shared_secret_d, cipher_text, secret_key);
    BOOST_CHECK(ret == true);

    // Verify the size of the recovered shared secret matches the expected length.
    BOOST_CHECK_EQUAL(sizeof(shared_secret_d), OQS_KEM_kyber_768_length_shared_secret);

    // Verify that the original shared secret and the recovered shared secret are equal.
    BOOST_CHECK_EQUAL_COLLECTIONS(
        shared_secret_e, shared_secret_e + OQS_KEM_kyber_768_length_shared_secret,
        shared_secret_d, shared_secret_d + OQS_KEM_kyber_768_length_shared_secret);
}

// Test case for encrypting and decrypting data.
BOOST_AUTO_TEST_CASE(EncryptDecrypt)
{
    CCrypter crypter;

    // Vector to hold the encrypted data
    std::vector<unsigned char> encryptedData;

    // Vector to hold the decrypted data.
    std::vector<unsigned char> decryptedData;

    // Check if data encryption does not throw any exceptions.
    BOOST_CHECK_NO_THROW(crypter.EncryptData(originalData, encryptedData, shared_secret_d, iv));

    // Verify that the size of the initialization vector (IV) matches the AES block size.
    BOOST_CHECK_EQUAL(iv.size(), EVP_MAX_IV_LENGTH);

    // Check if data decryption does not throw any exceptions.
    BOOST_CHECK_NO_THROW(crypter.DecryptData(encryptedData, decryptedData, shared_secret_d, iv));

    // Verify that the decrypted data matches the original data.
    BOOST_CHECK_EQUAL_COLLECTIONS(originalData.begin(), originalData.end(),
                                  decryptedData.begin(), decryptedData.end());
}

// End of test suite for CCrypter class.
BOOST_AUTO_TEST_SUITE_END()