#include <string>
#include <iostream>
#include <fstream>


#define ASSERT assert

#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <memory>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <cassert>

#include <boost/test/unit_test.hpp>

#include "util/encoding_util.h"
#include "crypto/key.h"
#include "util/common_util.h"
#include "crypto/ecdsa.h"

namespace ecdsa_test_ns
{

    CECDSAPrivateKey privKey;
    CECDSAPublicKey pubKey;
    std::string temp_folder = "/tmp/ecdsa";


    struct ecdsa_test_fixture_testsuite
    {

        ecdsa_test_fixture_testsuite() : i( 0 )
        {
            BOOST_TEST_MESSAGE( "---------------------- ecdsa_test setup -----------------------" );
            ::CreateFolderIfNotExists(temp_folder);
        }
        ~ecdsa_test_fixture_testsuite()
        {
            BOOST_TEST_MESSAGE( "---------------------- ecdsa_test tear down -------------------" );
        }

        int i;
    };

    struct ecdsa_test_fixture__per_testcase
    {

        ecdsa_test_fixture__per_testcase() : i( 0 )
        {
            BOOST_TEST_MESSAGE( "--- start test case ---" + to_string(i));
            ::CreateFolderIfNotExists(temp_folder);
            CECDSA::ECC_Start();

        }
        ~ecdsa_test_fixture__per_testcase()
        {
            BOOST_TEST_MESSAGE( "--- end test case ---" );
            CECDSA::ECC_Stop();
        }

        int i;
    };

    #define BOOST_TEST_MODULE ecdsa_test

    #define ECDSA_TEST_CASE(name_) \
        BOOST_FIXTURE_TEST_CASE(ecdsa_##name_, ecdsa_test_fixture__per_testcase)

    BOOST_FIXTURE_TEST_SUITE(ecdsa_test, ecdsa_test_fixture_testsuite)



    void TestECDSAGenKey(int nKeySize)
    {
        privKey = CECDSA::GenerateNewKey(nKeySize, false);
        pubKey = privKey.GetPublicKey();

        std::string priFileName = string("/tmp/ecdsa/ecdsa_") + to_string(nKeySize) + ".key" ;
        std::string pubFileName = string("/tmp/ecdsa/ecdsa_") + to_string(nKeySize) + ".pub" ;

        std::string priFileName_ssl = string("/tmp/ecdsa/ecdsa_") + to_string(nKeySize) + ".key.ssl" ;
        std::string pubFileName_ssl = string("/tmp/ecdsa/ecdsa_") + to_string(nKeySize) + ".pub.ssl" ;

        //Using my functions. Each files in two format: PEM and DER
        privKey.SaveToFile(priFileName, crypto::PEM_);
        privKey.SaveToFile(priFileName, crypto::DER_);

        pubKey.SaveToFile(pubFileName, crypto::PEM_);
        pubKey.SaveToFile(pubFileName, crypto::DER_);

        BOOST_CHECK_MESSAGE(std::ifstream(priFileName + ".pem", std::ifstream::in), "Key file has not been generated.");
        BOOST_CHECK_MESSAGE(std::ifstream(priFileName + ".der", std::ifstream::in), "Key file has not been generated.");
        BOOST_CHECK_MESSAGE(std::ifstream(pubFileName + ".pem", std::ifstream::in), "Key file has not been generated.");
        BOOST_CHECK_MESSAGE(std::ifstream(pubFileName + ".der", std::ifstream::in), "Key file has not been generated.");
    }

    void TestLoadKeyFromFile_PEM()
    {
        std::string privateFileName = "/tmp/ecdsa/ecdsa-private-1.pem";
        std::string publicFileName = "/tmp/ecdsa/ecdsa-public-1.pem";

        //CECDSA::OpenSSL_LoadPrivateKeyFromFile()

        privKey = CECDSA::LoadPrivateKeyFromFile(privateFileName, crypto::PEM_);
        pubKey = CECDSA::LoadPublicKeyFromFile(publicFileName, crypto::PEM_);

        std::string message("Hi Son.");

    }

    void TestLoadKeyFromFile_DER()
    {
        std::string privateFileName = "/tmp/ecdsa/ecdsa-private.der";
        std::string publicFileName = "/tmp/ecdsa/ecdsa-public.der";

        privKey = CECDSA::LoadPrivateKeyFromFile(privateFileName, crypto::DER_);
        pubKey = CECDSA::LoadPublicKeyFromFile(publicFileName, crypto::DER_);

        BOOST_CHECK_MESSAGE(privKey.IsValid(), "Private key is not valid.");
        BOOST_CHECK_MESSAGE(pubKey.IsValid(), "Private key is not valid.");
    }

    void TestLoadKeyFromFile()
    {
        //GenerateTestKeyFiles();
        TestLoadKeyFromFile_PEM();
        TestLoadKeyFromFile_DER();
    }

    void Test_Sign_Verify_Function(std::string message)
    {
        privKey = CECDSA::GenerateNewKey(256, false);
        pubKey = privKey.GetPublicKey();

        ECCVerifyHandle verify;

        std::string sign;
        const std::vector<unsigned char> vMessage(message.begin(), message.end());// = *(new std::vector<unsigned char>(message.begin(), message.end()));
        std::vector<unsigned char> vSign;

        BOOST_TEST_MESSAGE("Test: sign-verify");

        bool result = privKey.Sign(message, sign);
        BOOST_CHECK_MESSAGE(result, "Sign failed.");

        result = pubKey.Verify(message, sign);
        BOOST_CHECK_MESSAGE(result, "Verify failed.");

        result = privKey.Sign(vMessage, vSign);
        BOOST_CHECK_MESSAGE(result, "Sign2 failed.");

        result = pubKey.Verify(vMessage, vSign);
        BOOST_CHECK_MESSAGE(result, "Verify2 failed.");

        //! Negatie case: use another public key to verify

        CECDSAPrivateKey newPri = CECDSA::GenerateNewKey(256, false);
        CECDSAPublicKey newPub = newPri.GetPublicKey();

        BOOST_TEST_MESSAGE( "Some error should be raised since the signature is invalid for the public key." );

        result = newPub.Verify(message, sign);
        BOOST_CHECK_MESSAGE(result == false, "Test negative sign failed.");

        result = newPub.Verify(vMessage, vSign);
        BOOST_CHECK_MESSAGE(result == false, "Test negative sign2 failed.");

    }

    void Test_Sign_Verify()
    {
        std::string message = "This is the message i want to sign with my private key.";
        //GenerateTestKeyFiles();
        Test_Sign_Verify_Function(message);
    }

    ECDSA_TEST_CASE(gen_key_test)
    {
        TestECDSAGenKey(256);
    }

    ECDSA_TEST_CASE(load_key_from_file_test)
    {
       //TestLoadKeyFromFile();
    }

    ECDSA_TEST_CASE(sign_test)
    {
       Test_Sign_Verify();
    }

}

BOOST_AUTO_TEST_SUITE_END()
