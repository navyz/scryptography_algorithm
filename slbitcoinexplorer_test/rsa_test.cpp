#include <string>
#include <iostream>
#include <fstream>


#define ASSERT assert

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <memory>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <cassert>

#include <boost/test/unit_test.hpp>

#include "util/encoding_util.h"
#include "crypto/key.h"
#include "util/common_util.h"
#include "crypto/rsa.h"

namespace rsa_test_ns
{

using std::unique_ptr;
using BN_ptr = std::unique_ptr<BIGNUM, decltype(&::BN_free)>;
using RSA_ptr = std::unique_ptr<RSA, decltype(&::RSA_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&::EVP_PKEY_free)>;
using BIO_FILE_ptr = std::unique_ptr<BIO, decltype(&::BIO_free)>;


CRSAPrivateKey *privKey = NULL;
CRSAPublicKey *pubKey = NULL;
std::string temp_folder = "/tmp/rsa";

struct rsa_test_fixture_testsuite
{

    rsa_test_fixture_testsuite() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "---------------------- rsa_test setup -----------------------" );
        ::CreateFolderIfNotExists(temp_folder);

    }
    ~rsa_test_fixture_testsuite()
    {
        BOOST_TEST_MESSAGE( "---------------------- rsa_test tear down -------------------" );
    }

    int i;
};

struct rsa_test_fixture__per_testcase
{

    rsa_test_fixture__per_testcase() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "--- start test case ---" + to_string(i));
        ::CreateFolderIfNotExists(temp_folder);

    }
    ~rsa_test_fixture__per_testcase()
    {
        BOOST_TEST_MESSAGE( "--- end test case ---" );
    }

    int i;
};

#define BOOST_TEST_MODULE rsa_test

#define RSA_TEST_CASE(name_) \
    BOOST_FIXTURE_TEST_CASE(rsa_##name_, rsa_test_fixture__per_testcase)

BOOST_FIXTURE_TEST_SUITE(rsa_test, rsa_test_fixture_testsuite)



void TestRSAGenKey(int nKeySize)
{
    CRSA::OpenSSL_GenerateNewKey(nKeySize, privKey, pubKey);

    std::string priFileName = string("/tmp/rsa/rsa_") + to_string(nKeySize) + ".key" ;
    std::string pubFileName = string("/tmp/rsa/rsa_") + to_string(nKeySize) + ".pub" ;

    std::string priFileName_ssl = string("/tmp/rsa/rsa_") + to_string(nKeySize) + ".key.ssl" ;
    std::string pubFileName_ssl = string("/tmp/rsa/rsa_") + to_string(nKeySize) + ".pub.ssl" ;

    //Using my functions. Each files in two format: PEM and DER
    privKey->SaveToFile(priFileName, crypto::PEM_);
    privKey->SaveToFile(priFileName, crypto::DER_);

    pubKey->SaveToFile(pubFileName, crypto::PEM_);
    pubKey->SaveToFile(pubFileName, crypto::DER_);

    //Using OpenSSL library functions to compare
    privKey->OpenSSL_SaveToFile(priFileName_ssl, crypto::PEM_);
    privKey->OpenSSL_SaveToFile(priFileName_ssl, crypto::DER_);

    pubKey->OpenSSL_SaveToFile(pubFileName_ssl, crypto::PEM_);
    pubKey->OpenSSL_SaveToFile(pubFileName_ssl, crypto::DER_);


    BOOST_CHECK_MESSAGE(std::ifstream(priFileName + ".pem", std::ifstream::in), "Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(priFileName + ".der", std::ifstream::in), "Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(pubFileName + ".pem", std::ifstream::in), "Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(pubFileName + ".der", std::ifstream::in), "Key file has not been generated.");

    BOOST_CHECK_MESSAGE(std::ifstream(priFileName_ssl + ".pem", std::ifstream::in), "SSL Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(priFileName_ssl + ".der", std::ifstream::in), "SSL Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(pubFileName_ssl + ".pem", std::ifstream::in), "SSL Key file has not been generated.");
    BOOST_CHECK_MESSAGE(std::ifstream(pubFileName_ssl + ".der", std::ifstream::in), "SSL Key file has not been generated.");

    //Check if my file is equal to OpenSSL generated file

    BOOST_CHECK_MESSAGE(::IsFilesEqual(priFileName + ".pem", priFileName_ssl + ".pem"), "Private pem file is not equal.");
    BOOST_CHECK_MESSAGE(::IsFilesEqual(priFileName + ".der", priFileName_ssl + ".der"), "Private der file is not equal.");

    BOOST_CHECK_MESSAGE(::IsFilesEqual(pubFileName + ".pem", pubFileName_ssl + ".pem"), "Public pem file is not equal.");
    BOOST_CHECK_MESSAGE(::IsFilesEqual(pubFileName + ".der", pubFileName_ssl + ".der"), "Public der file is not equal.");



    /*
    std::cout << "modulus: " << static_cast<CRSAPrivateKey*>(privKey)->n.GetHex() << endl;
    std::cout << "e: " << static_cast<CRSAPrivateKey*>(privKey)->e.GetHex() << endl;
    std::cout << "d: " << static_cast<CRSAPrivateKey*>(privKey)->d.GetHex() << endl;
    */

}


void TestRSAEncrypt_MyFunction(const std::string &message)
{

    std::vector<unsigned char> vCipher, vDecoded, vOpenSSLCipher, vOpenSSLDecoded;

    const std::vector<unsigned char> vMessage(message.begin(), message.end());// = *(new std::vector<unsigned char>(message.begin(), message.end()));

    // Test private-encrypt  -> public decrypt

    BOOST_TEST_MESSAGE("Test: private encrypt - public decrypt.");
    bool result = privKey->Encrypt(vMessage, vCipher);
    result &= privKey->OpenSSL_Encrypt(vMessage, vOpenSSLCipher);

    //cout << "My cipher: " << ::GetHex(vCipher) << std::endl;
    //cout << "OpenSSL cipher: " << ::GetHex(vOpenSSLCipher) << std::endl;

    //! Cross check with OpenSSL
    BOOST_CHECK(::GetHex(vCipher) == ::GetHex(vOpenSSLCipher));

    BOOST_CHECK_MESSAGE(result, "Encrypt failed.");

    if (result)
    {
        pubKey->Decrypt(vCipher, vDecoded);
        pubKey->OpenSSL_Decrypt(vCipher, vOpenSSLDecoded);

        //cout << "My decoded: " << ::GetHex(vDecoded) << std::endl;
        //cout << "OpenSSL decoded: " << ::GetHex(vOpenSSLDecoded) << std::endl;

        //! Cross check with OpenSSL
        BOOST_CHECK(::GetHex(vDecoded) == ::GetHex(vOpenSSLDecoded));

        //! Check the decrypted with original input
        BOOST_CHECK(message == string(vDecoded.begin(), vDecoded.end()));


    }

    // Test public-encrypt  -> private decrypt

    BOOST_TEST_MESSAGE("Test: public encrypt - private decrypt.");
    result = pubKey->Encrypt(vMessage, vCipher);

    BOOST_CHECK_MESSAGE(result, "Encrypt failed.");

    if (result)
    {
        privKey->Decrypt(vCipher, vDecoded);

        string strCipher = ::GetHex(vCipher);
        string strDecoded(vDecoded.begin(), vDecoded.end());

        BOOST_CHECK(message == strDecoded);

    }
}

void TestRSAEncrypt_OpenSSLFunction(std::string message)
{
    //Test the encrypt and decrypt wrapper function based on OpenSSL ---------------------------------------

    std::vector<unsigned char> vCipher, vDecoded;

    const std::vector<unsigned char> vMessage(message.begin(), message.end());// = *(new std::vector<unsigned char>(message.begin(), message.end()));


    // Test private-encrypt  -> public decrypt

    BOOST_TEST_MESSAGE("Test: private encrypt - public decrypt.");
    bool result = privKey->OpenSSL_Encrypt(vMessage, vCipher);

    BOOST_CHECK_MESSAGE(result, "Encrypt failed.");


    if (result)
    {
        pubKey->OpenSSL_Decrypt(vCipher, vDecoded);

        string strCipher = ::GetHex(vCipher);
        string strDecoded(vDecoded.begin(), vDecoded.end());

        BOOST_CHECK(message == strDecoded);

        /*std::cout << message << std::endl;
        std::cout << ::GetHex((char *)message.c_str(), message.size()) << std::endl;
        std::cout << strCipher << std::endl;
        std::cout << strDecoded << std::endl; */
    }

    // Test public-encrypt  -> private decrypt

    BOOST_TEST_MESSAGE("Test: public encrypt - private decrypt.");
    result = pubKey->OpenSSL_Encrypt(vMessage, vCipher);

    BOOST_CHECK_MESSAGE(result, "Encrypt failed.");

    if (result)
    {
        privKey->OpenSSL_Decrypt(vCipher, vDecoded);

        string strCipher = ::GetHex(vCipher);
        string strDecoded(vDecoded.begin(), vDecoded.end());

        BOOST_CHECK(message == strDecoded);

    }
}

void TestRSAEncrypt(int nKeySize)
{
    std::string message = "Hi!xxxxxxxxxxx";

    TestRSAEncrypt_MyFunction(message);
    TestRSAEncrypt_OpenSSLFunction(message);
}

void GenerateTestKeyFiles()
{
    int rc;

    RSA_ptr rsa(RSA_new(), ::RSA_free);
    BN_ptr bn(BN_new(), ::BN_free);

    BIO_FILE_ptr pem1(BIO_new_file("/tmp/rsa/rsa-public-1.pem", "w"), ::BIO_free);
    BIO_FILE_ptr pem2(BIO_new_file("/tmp/rsa/rsa-public-2.pem", "w"), ::BIO_free);
    BIO_FILE_ptr pem3(BIO_new_file("/tmp/rsa/rsa-private-1.pem", "w"), ::BIO_free);
    BIO_FILE_ptr pem4(BIO_new_file("/tmp/rsa/rsa-private-2.pem", "w"), ::BIO_free);
    BIO_FILE_ptr pem5(BIO_new_file("/tmp/rsa/rsa-private-3.pem", "w"), ::BIO_free);
    BIO_FILE_ptr der1(BIO_new_file("/tmp/rsa/rsa-public.der", "w"), ::BIO_free);
    BIO_FILE_ptr der2(BIO_new_file("/tmp/rsa/rsa-private.der", "w"), ::BIO_free);

    rc = BN_set_word(bn.get(), RSA_F4);
    ASSERT(rc == 1);

    // Generate key
    rc = RSA_generate_key_ex(rsa.get(), 2048, bn.get(), NULL);
    ASSERT(rc == 1);

    // Convert RSA to PKEY
    EVP_KEY_ptr pkey(EVP_PKEY_new(), ::EVP_PKEY_free);
    rc = EVP_PKEY_set1_RSA(pkey.get(), rsa.get());
    ASSERT(rc == 1);

    //////////

    // Write public key in ASN.1/DER
    rc = i2d_RSAPublicKey_bio(der1.get(), rsa.get());
    ASSERT(rc == 1);

    // Write public key in PKCS PEM
    rc = PEM_write_bio_RSAPublicKey(pem1.get(), rsa.get());
    ASSERT(rc == 1);

    // Write public key in Traditional PEM
    rc = PEM_write_bio_PUBKEY(pem2.get(), pkey.get());
    ASSERT(rc == 1);

    //////////

    // Write private key in ASN.1/DER
    rc = i2d_RSAPrivateKey_bio(der2.get(), rsa.get());
    ASSERT(rc == 1);

    // Write private key in PKCS PEM.
    rc = PEM_write_bio_PrivateKey(pem3.get(), pkey.get(), NULL, NULL, 0, NULL, NULL);
    ASSERT(rc == 1);

    // Write private key in PKCS PEM
    rc = PEM_write_bio_PKCS8PrivateKey(pem4.get(), pkey.get(), NULL, NULL, 0, NULL, NULL);
    ASSERT(rc == 1);

    // Write private key in Traditional PEM
    rc = PEM_write_bio_RSAPrivateKey(pem5.get(), rsa.get(), NULL, NULL, 0, NULL, NULL);
    ASSERT(rc == 1);
}

void TestLoadKeyFromFile_PEM()
{
    std::string privateFileName = "/tmp/rsa/rsa-private-1.pem";
    std::string publicFileName = "/tmp/rsa/rsa-public-1.pem";

    //CRSA::OpenSSL_LoadPrivateKeyFromFile()

    delete privKey;
    delete pubKey;
    privKey = CRSA::OpenSSL_LoadPrivateKeyFromFile(privateFileName, crypto::PEM_);
    pubKey = CRSA::OpenSSL_LoadPublicKeyFromFile(publicFileName, crypto::PEM_);

    std::string message("Hi Son.");

    TestRSAEncrypt_MyFunction(message);
    TestRSAEncrypt_OpenSSLFunction(message);


}

void TestLoadKeyFromFile_DER()
{
    std::string privateFileName = "/tmp/rsa/rsa-private.der";
    std::string publicFileName = "/tmp/rsa/rsa-public.der";

    delete privKey;
    delete pubKey;

    privKey = CRSA::OpenSSL_LoadPrivateKeyFromFile(privateFileName, crypto::DER_);
    pubKey = CRSA::OpenSSL_LoadPublicKeyFromFile(publicFileName, crypto::DER_);
    std::string message("Hi Son.");

    TestRSAEncrypt_MyFunction(message);
    TestRSAEncrypt_OpenSSLFunction(message);


}

void TestLoadKeyFromFile()
{
    GenerateTestKeyFiles();
    TestLoadKeyFromFile_PEM();
    TestLoadKeyFromFile_DER();
}

void Test_Sign_Verify_MyFunction(std::string message)
{
    std::string sign;
    const std::vector<unsigned char> vMessage(message.begin(), message.end());// = *(new std::vector<unsigned char>(message.begin(), message.end()));
    std::vector<unsigned char> vSign;

    BOOST_TEST_MESSAGE("Test: sign-verify");

    bool result = privKey->Sign(message, sign);
    BOOST_CHECK_MESSAGE(result, "Sign failed.");

    result = pubKey->Verify(message, sign);
    BOOST_CHECK_MESSAGE(result, "Verify failed.");

    result = privKey->Sign(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result, "Sign2 failed.");

    result = pubKey->Verify(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result, "Verify2 failed.");

    //! Negatie case: use another public key to verify

    CRSAPublicKey *newPub = NULL;
    CRSAPrivateKey *newPri = NULL;
    CRSA::OpenSSL_GenerateNewKey(2048, newPri, newPub);

    BOOST_TEST_MESSAGE( "Some error should be raised since the signature is invalid for the public key." );

    result = newPub->Verify(message, sign);
    BOOST_CHECK_MESSAGE(result == false, "Test negative sign failed.");

    result = newPub->Verify(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result == false, "Test negative sign2 failed.");

}

void Test_Sign_Verify_OpenSSLFunction(std::string message)
{
    std::string sign;
    const std::vector<unsigned char> vMessage(message.begin(), message.end());// = *(new std::vector<unsigned char>(message.begin(), message.end()));
    std::vector<unsigned char> vSign;

    BOOST_TEST_MESSAGE("Test: sign-verify");

    bool result = privKey->OpenSSL_Sign(message, sign);
    BOOST_CHECK_MESSAGE(result, "Sign failed.");

    result = pubKey->OpenSSL_Verify(message, sign);
    BOOST_CHECK_MESSAGE(result, "Verify failed.");

    result = privKey->OpenSSL_Sign(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result, "Sign2 failed.");

    result = pubKey->OpenSSL_Verify(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result, "Verify2 failed.");

    //! Negatie case: use another public key to verify

    CRSAPublicKey *newPub = NULL;
    CRSAPrivateKey *newPri = NULL;
    CRSA::OpenSSL_GenerateNewKey(2048, newPri, newPub);

    result = newPub->OpenSSL_Verify(message, sign);
    BOOST_CHECK_MESSAGE(result == false, "Test negative sign failed.");

    result = newPub->OpenSSL_Verify(vMessage, vSign);
    BOOST_CHECK_MESSAGE(result == false, "Test negative sign2 failed.");

}

void Test_Sign_Verify()
{
    std::string message = "This is the message i want to sign with my private key.";
    GenerateTestKeyFiles();
    Test_Sign_Verify_OpenSSLFunction(message);
    Test_Sign_Verify_MyFunction(message);
}


RSA_TEST_CASE(gen_key_test)
{

    for (int i=1; i < 2; i++)
    {
        //TestRSAGenKey(1024 * i);
    }
}

RSA_TEST_CASE(encrypt_test)
{

    for (int i=1; i < 2; i++)
    {
        //TestRSAEncrypt(1024*i);
    }
}

RSA_TEST_CASE(load_key_from_file_test)
{

   //TestLoadKeyFromFile();
}

RSA_TEST_CASE(sign_test)
{

   //Test_Sign_Verify();
}

} //! end of rsa_test_ns namespace

BOOST_AUTO_TEST_SUITE_END()
