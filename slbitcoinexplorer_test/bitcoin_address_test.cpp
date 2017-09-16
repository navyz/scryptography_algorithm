#include <string>
#include <iostream>
#include <fstream>


#include <boost/test/unit_test.hpp>

#include "crypto/key.h"
#include "crypto/ecdsa.h"
#include "bitcoin/bitcoin_address.h"


//! Snippet code
#include "crypto/bitcoin/hash.h"
#include "crypto/base58.h"
#include "util/encoding_util.h"


namespace bitcoin_address_test_ns
{

    //std::string temp_folder = "/tmp/bitcoin_address";


    struct bitcoin_address_test_fixture_testsuite
    {

        bitcoin_address_test_fixture_testsuite() : i( 0 )
        {
            BOOST_TEST_MESSAGE( "---------------------- bitcoin_address_test setup -----------------------" );
            //::CreateFolderIfNotExists(temp_folder);
        }
        ~bitcoin_address_test_fixture_testsuite()
        {
            BOOST_TEST_MESSAGE( "---------------------- bitcoin_address_test tear down -------------------" );
        }

        int i;
    };

    struct bitcoin_address_test_fixture__per_testcase
    {

        bitcoin_address_test_fixture__per_testcase() : i( 0 )
        {
            BOOST_TEST_MESSAGE( "--- start test case ---" + std::to_string(i));
            //::CreateFolderIfNotExists(temp_folder);
            CECDSA::ECC_Stop();
            CECDSA::ECC_Start();

        }
        ~bitcoin_address_test_fixture__per_testcase()
        {
            BOOST_TEST_MESSAGE( "--- end test case ---" );
            CECDSA::ECC_Stop();
        }

        int i;
    };

    #define BOOST_TEST_MODULE bitcoin_address_test

    #define BITCOIN_ADDRESS_TEST_CASE(name_) \
        BOOST_FIXTURE_TEST_CASE(bitcoin_address_##name_, bitcoin_address_test_fixture__per_testcase)

    BOOST_FIXTURE_TEST_SUITE(bitcoin_address_test, bitcoin_address_test_fixture_testsuite)



    void TestBitcoinAddress()
    {

        CECDSAPrivateKey privKeyA = CECDSA::GenerateNewKey(256, false);
        CECDSAPublicKey pubKeyA1 = privKeyA.GetPublicKey('U');
        CECDSAPublicKey pubKeyA2 = privKeyA.GetPublicKey('C');

        /*CECDSAPrivateKey privKeyB = CECDSA::GenerateNewKey(256, true);
        CECDSAPublicKey pubKeyB1 = privKey2.GetPublicKey();
        CECDSAPublicKey pubKeyB2 = privKey2.GetPublicKey('U'); */

        std::string pubAddressA1 = CBitcoinAddress::PK2Address(pubKeyA1, address::P2PKH_PRE);
        std::string pubAddressA2 = CBitcoinAddress::PK2Address(pubKeyA2, address::P2PKH_PRE);
        std::string privAddressA1 = CBitcoinSecret::Priv2Address(privKeyA, address::PRIV_UN_PRE);
        std::string privAddressA2 = CBitcoinSecret::Priv2Address(privKeyA, address::PRIV_CO_PRE);

        CECDSAPrivateKey privKeyGenA = CBitcoinSecret::Address2PrivKey(privAddressA1);
        CECDSAPrivateKey privKeyGenB = CBitcoinSecret::Address2PrivKey(privAddressA2);

        BOOST_CHECK_MESSAGE(pubAddressA1.length() > 0, "PubAddressA1 len is invalid.");
        BOOST_CHECK_EQUAL(CBitcoinAddress::VerifyAddress(pubAddressA1), true);

        BOOST_CHECK_MESSAGE(pubAddressA1.length() > 0, "PubAddressA2 len is invalid.");
        BOOST_CHECK_EQUAL(CBitcoinAddress::VerifyAddress(pubAddressA2), true);

        BOOST_CHECK_MESSAGE(privAddressA1.length() > 0, "Private Address A1 len is invalid.");
        BOOST_CHECK_EQUAL(CBitcoinSecret::VerifyPrivAddress(privAddressA1), true);

        BOOST_CHECK_MESSAGE(privAddressA2.length() > 0, "Private Address A2 len is invalid.");
        BOOST_CHECK_EQUAL(CBitcoinSecret::VerifyPrivAddress(privAddressA2), true);

        BOOST_CHECK_MESSAGE(privKeyA == privKeyGenB, "The private key should be the same.");
        BOOST_CHECK_MESSAGE(!(privKeyA == privKeyGenA), "The private key should not be the same (compress level)");

        std::cout << privAddressA1 << " - " << pubAddressA1 << std::endl;
        std::cout << privAddressA2 << " - " << pubAddressA2 << std::endl;

        ofstream fpair, fpubonly, fprionly;
        fpair.open ("/tmp/pair.txt", ios::out | ios::app);
        fpubonly.open ("/tmp/address.txt", ios::out | ios::app);
        fprionly.open ("/tmp/private.txt", ios::out | ios::app);

        fpubonly << pubAddressA1 << std::endl;
        fprionly << privAddressA1 << std::endl;
        fpair << privAddressA1 << " - " << pubAddressA1 << " - " << privAddressA2 << " - " << pubAddressA2 << std::endl;

        fpair.close();
        fpubonly.close();
        fprionly.close();

    }

    void test_gen_pub_from_pri(std::string privAddress, std::string publicAddress, std::string publicAddressCompressed)
    {
        std::string genAddress0 = CBitcoinSecret::PriAdd2PubAdd(privAddress);
        std::string genAddressC = CBitcoinSecret::PriAdd2PubAdd(privAddress, 'C');
        std::string genAddressU = CBitcoinSecret::PriAdd2PubAdd(privAddress, 'U');

        BOOST_CHECK_MESSAGE((genAddress0 == publicAddress || genAddress0 == publicAddressCompressed), "Default address generated incorrectly");

        if (publicAddress.size() > 0)
        BOOST_CHECK_MESSAGE((genAddressU == publicAddress), "Uncompressed address generated incorrectly");

        if (publicAddressCompressed.size() > 0)
        BOOST_CHECK_MESSAGE((genAddressC == publicAddressCompressed), "Compressed address generated incorrectly");

    }

    BITCOIN_ADDRESS_TEST_CASE(generate_new_address)
    {
        for (int i=0; i<2000; i++)
            TestBitcoinAddress();

        std::string newAddress = "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm";
        BOOST_CHECK_EQUAL(CBitcoinAddress::VerifyAddress(newAddress), true);

    }

    BITCOIN_ADDRESS_TEST_CASE(private_address_to_public_address)
    {
        test_gen_pub_from_pri("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf", "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm", "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH");
        test_gen_pub_from_pri("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreFMSs18A", "1HGn3jxoSh8twi4mR3iaNmZr6pbHgjFJEg", "1EMxdcJsfN5jwtZRVRvztDns1LgquGUTwi");
        test_gen_pub_from_pri("5Khbqymcou2Rr11ey669ViPJNQxvrgVkzoaDQU6WLVuEM4XkVMj", "1Gp8SEndf9SdHJANLjPeHJw3xdtEC9o5zp", "1PGodFBYe5MvaKj48aSSh9ye2Tqn7QbvwC");
        test_gen_pub_from_pri("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5kwRQ3WoeD3jRVZuKR9H", "14mJM9N9KWFxJVigZ9QHub7RSUs1aSUz2Y", "12vdR9jM2YFJbnVHSymjxaZuZ8zsW4Yapr");
        test_gen_pub_from_pri("5HpHagT65TZzG1PH3CSuLivgxT3bLuqjRQMU5jnxksajXdMYCLf", "1NqmVDRqEsHvyptTUTj8HjjjtJBAqhFgbT", "1DZxvmTpdjNTi1Vt3i27sfuVzZ7Xr1xCWx");
    }
    BITCOIN_ADDRESS_TEST_CASE(create_sample_bitcoin_address_p2pkh)
    {
        std::string pubAddress = "1D54cppz4AcHqm3y2qopdCMH1yHGHXefDr";
        bool ret = CBitcoinAddress::VerifyAddress(pubAddress);
        assert(ret);
        std::string pubAddressHex = CBitcoinAddress::Address2Hex(pubAddress);
        BOOST_CHECK_EQUAL(pubAddressHex, "84663170d144fdb5213552ed8cdeca724f15e915");

        pubAddress = "1AjF81zSLg9nB3CQ1dhnMksSdtfJ4Fg7S3";
        ret = CBitcoinAddress::VerifyAddress(pubAddress);
        assert(ret);
        std::string pubScript = CBitcoinAddress::Address2Script(pubAddress);
        BOOST_CHECK_EQUAL(pubScript, "76a9146ab663da836f07d26c05fcb07186853133c1063688ac");


        std::cout << pubAddressHex << std::endl;


        return;

        //! Step 1: Having ECDSA public key 04.x.y
        std::string s0 = "0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6";
        std::vector<unsigned char> v0 = ::ParseHex(s0);

        unsigned char sha256[32], ripemd160[20];

        //! Step 2: Calculate SHA256 (1 time, not double hash)
        CSHA256().Write((unsigned char*)&v0[0], v0.size()).Finalize(sha256);

        //! Step 3: Calculate RIPEMD160 (1 time, not double hash)
        CRIPEMD160().Write(sha256, 32).Finalize(ripemd160);

        //! Step 4: Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
        std::string s1(ripemd160, ripemd160+20);
        s1.insert(s1.begin(), 1, 0);

        std::cout << "-------------------------------- my snippet ------------------------------------" << std::endl;
        std::cout << s0 << std::endl;
        std::cout << ::GetHex(v0) << std::endl;
        std::string t = ::GetHex((unsigned char*)sha256, 32);
        std::cout << t << std::endl;
        std::cout << ::GetHex((unsigned char*)ripemd160, 20) << std::endl;
        std::cout << ::GetHex(std::vector<unsigned char>(s1.begin(), s1.end())) << std::endl;


        unsigned char sha256_2[32];

        //! Step 5: Double hash step 4
        CHash256().Write((unsigned char*)s1.c_str(), 21).Finalize(sha256_2);

        //! Step 6: Get checksum = first 4 bytes of step 5
        std::string checksum(sha256_2, sha256_2+4);

        //! Step 7: Combine step 4 and step 6
        std::string finalbin = s1 + checksum;

        //! Step 8: Encode base58 for step 7
        std::string finalbase68 = ::EncodeBase58(std::vector<unsigned char>(finalbin.begin(), finalbin.end()));

        t = ::GetHex((unsigned char*)sha256_2, 32);
        std::cout << t << std::endl;
        std::cout << ::GetHex((unsigned char*)checksum.c_str(), 4) << std::endl;
        std::cout << ::GetHex((unsigned char*)finalbin.c_str(), 25) << std::endl;
        std::cout << finalbase68 << std::endl;

    }
}

BOOST_AUTO_TEST_SUITE_END()
