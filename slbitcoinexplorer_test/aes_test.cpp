#include <string>

#include <boost/test/unit_test.hpp>
#include "crypto/aes.h"
#include "util/encoding_util.h"


struct aes_test_fixture_testsuite
{

    aes_test_fixture_testsuite() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "---------------------- aes_test setup -----------------------" );

    }
    ~aes_test_fixture_testsuite()
    {
        BOOST_TEST_MESSAGE( "---------------------- aes_test tear down -------------------" );
    }

    int i;
};

struct aes_test_fixture__per_testcase
{

    aes_test_fixture__per_testcase() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "--- start test casex ---" );

    }
    ~aes_test_fixture__per_testcase()
    {
        BOOST_TEST_MESSAGE( "--- end test case ---" );
    }

    int i;
};


#define BOOST_TEST_MODULE aes_test

#define AES_TEST_CASE(name_) \
    BOOST_FIXTURE_TEST_CASE(aes_##name_, aes_test_fixture__per_testcase)

BOOST_FIXTURE_TEST_SUITE(aes_test, aes_test_fixture_testsuite);


void test_aes128(const std::string &key_hex, const std::string &input_hex, const std::string &expected_hex)
{
    std::vector<unsigned char> key = ParseHex(key_hex);
    std::vector<unsigned char> in = ParseHex(input_hex);
    std::vector<unsigned char> correctout = ParseHex(expected_hex);
    std::vector<unsigned char> buf, buf2;

    assert(key.size() == 16);
    assert(in.size() == 16);
    assert(correctout.size() == 16);

    buf.resize(correctout.size());
    buf2.resize(correctout.size());

    //encrypt
    AES128Encrypt enc(&key[0]);
    enc.Encrypt(&buf[0], &in[0]);
    BOOST_CHECK_EQUAL(HexStr(buf), HexStr(correctout));

    //decrypt
    AES128Decrypt dec(&key[0]);
    dec.Decrypt(&buf2[0], &buf[0]);
    BOOST_CHECK_EQUAL(HexStr(buf2), HexStr(in));
}

void test_aes256(const std::string &key_hex, const std::string &input_hex, const std::string &expected_hex)
{
    std::vector<unsigned char> key = ParseHex(key_hex);
    std::vector<unsigned char> in = ParseHex(input_hex);
    std::vector<unsigned char> correctout = ParseHex(expected_hex);
    std::vector<unsigned char> buf, buf2;

    assert(key.size() == 32);
    assert(in.size() == 16);
    assert(correctout.size() == 16);

    buf.resize(correctout.size());
    buf2.resize(correctout.size());

    //encrypt
    AES256Encrypt enc(&key[0]);
    enc.Encrypt(&buf[0], &in[0]);
    BOOST_CHECK_EQUAL(HexStr(buf), HexStr(correctout));

    //decrypt
    AES256Decrypt dec(&key[0]);
    dec.Decrypt(&buf2[0], &buf[0]);
    BOOST_CHECK_EQUAL(HexStr(buf2), HexStr(in));
}

void test_aes128_cbc(const std::string &key_hex, const std::string &iv_hex, bool pad, const std::string &input_hex, const std::string &expected_out_hex)
{
    std::vector<unsigned char> key = ParseHex(key_hex);
    std::vector<unsigned char> iv = ParseHex(iv_hex);
    std::vector<unsigned char> in = ParseHex(input_hex);
    std::vector<unsigned char> correctout = ParseHex(expected_out_hex);
    std::vector<unsigned char> realout(in.size() + AES_BLOCKSIZE);

    // Encrypt the plaintext and verify that it equals the cipher
    AES128CBCEncrypt enc(&key[0], &iv[0], pad);
    int size = enc.Encrypt(&in[0], in.size(), &realout[0]);
    realout.resize(size);
    BOOST_CHECK(realout.size() == correctout.size());
    BOOST_CHECK_MESSAGE(realout == correctout, HexStr(realout) + std::string(" != ") + expected_out_hex);

    // Decrypt the cipher and verify that it equals the plaintext
    std::vector<unsigned char> decrypted(correctout.size());
    AES128CBCDecrypt dec(&key[0], &iv[0], pad);
    size = dec.Decrypt(&correctout[0], correctout.size(), &decrypted[0]);
    decrypted.resize(size);
    BOOST_CHECK(decrypted.size() == in.size());
    BOOST_CHECK_MESSAGE(decrypted == in, HexStr(decrypted) + std::string(" != ") + input_hex);

    // Encrypt and re-decrypt substrings of the plaintext and verify that they equal each-other
    for(std::vector<unsigned char>::iterator i(in.begin()); i != in.end(); ++i)
    {
        std::vector<unsigned char> sub(i, in.end());
        std::vector<unsigned char> subout(sub.size() + AES_BLOCKSIZE);
        int size = enc.Encrypt(&sub[0], sub.size(), &subout[0]);
        if (size != 0)
        {
            subout.resize(size);
            std::vector<unsigned char> subdecrypted(subout.size());
            size = dec.Decrypt(&subout[0], subout.size(), &subdecrypted[0]);
            subdecrypted.resize(size);
            BOOST_CHECK(decrypted.size() == in.size());
            BOOST_CHECK_MESSAGE(subdecrypted == sub, HexStr(subdecrypted) + std::string(" != ") + HexStr(sub));
        }
    }
}


void test_aes256_cbc(const std::string &key_hex, const std::string &iv_hex, bool pad, const std::string &input_hex, const std::string &expected_out_hex)
{
    std::vector<unsigned char> key = ParseHex(key_hex);
    std::vector<unsigned char> iv = ParseHex(iv_hex);
    std::vector<unsigned char> in = ParseHex(input_hex);
    std::vector<unsigned char> correctout = ParseHex(expected_out_hex);
    std::vector<unsigned char> realout(in.size() + AES_BLOCKSIZE);

    // Encrypt the plaintext and verify that it equals the cipher
    AES256CBCEncrypt enc(&key[0], &iv[0], pad);
    int size = enc.Encrypt(&in[0], in.size(), &realout[0]);
    realout.resize(size);
    BOOST_CHECK(realout.size() == correctout.size());
    BOOST_CHECK_MESSAGE(realout == correctout, HexStr(realout) + std::string(" != ") + expected_out_hex);

    // Decrypt the cipher and verify that it equals the plaintext
    std::vector<unsigned char> decrypted(correctout.size());
    AES256CBCDecrypt dec(&key[0], &iv[0], pad);
    size = dec.Decrypt(&correctout[0], correctout.size(), &decrypted[0]);
    decrypted.resize(size);
    BOOST_CHECK(decrypted.size() == in.size());
    BOOST_CHECK_MESSAGE(decrypted == in, HexStr(decrypted) + std::string(" != ") + input_hex);

    // Encrypt and re-decrypt substrings of the plaintext and verify that they equal each-other
    for(std::vector<unsigned char>::iterator i(in.begin()); i != in.end(); ++i)
    {
        std::vector<unsigned char> sub(i, in.end());
        std::vector<unsigned char> subout(sub.size() + AES_BLOCKSIZE);
        int size = enc.Encrypt(&sub[0], sub.size(), &subout[0]);
        if (size != 0)
        {
            subout.resize(size);
            std::vector<unsigned char> subdecrypted(subout.size());
            size = dec.Decrypt(&subout[0], subout.size(), &subdecrypted[0]);
            subdecrypted.resize(size);
            BOOST_CHECK(decrypted.size() == in.size());
            BOOST_CHECK_MESSAGE(subdecrypted == sub, HexStr(subdecrypted) + std::string(" != ") + HexStr(sub));
        }
    }
}


AES_TEST_CASE(ecb_mode) {
    // AES test vectors from FIPS 197.
    test_aes128("000102030405060708090a0b0c0d0e0f", "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a");
    test_aes256("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089");

    // AES-ECB test vectors from NIST sp800-38a.
    test_aes128("2b7e151628aed2a6abf7158809cf4f3c", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97");
    test_aes128("2b7e151628aed2a6abf7158809cf4f3c", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf");
    test_aes128("2b7e151628aed2a6abf7158809cf4f3c", "30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688");
    test_aes128("2b7e151628aed2a6abf7158809cf4f3c", "f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4");
    test_aes256("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "6bc1bee22e409f96e93d7e117393172a", "f3eed1bdb5d2a03c064b5a7e3db181f8");
    test_aes256("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "ae2d8a571e03ac9c9eb76fac45af8e51", "591ccb10d410ed26dc5ba74a31362870");
    test_aes256("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "30c81c46a35ce411e5fbc1191a0a52ef", "b6ed21b99ca6f4f9f153e7b1beafed1d");
    test_aes256("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", "f69f2445df4f9b17ad2b417be66c3710", "23304b7a39f9f3ff067d8d8f9e24ecc7");
}


AES_TEST_CASE(cbc_mode) {

    // NIST AES CBC 128-bit encryption test-vectors
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F", false, \
                  "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", false, \
                  "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "5086cb9b507219ee95db113a917678b2", false, \
                  "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "73bed6b8e3c1743b7116e69e22229516", false, \
                  "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a7");

    // The same vectors with padding enabled
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F", true, \
                  "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d8964e0b149c10b7b682e6e39aaeb731c");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", true, \
                  "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b255e21d7100b988ffec32feeafaf23538");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "5086cb9b507219ee95db113a917678b2", true, \
                  "30c81c46a35ce411e5fbc1191a0a52ef", "73bed6b8e3c1743b7116e69e22229516f6eccda327bf8e5ec43718b0039adceb");
    test_aes128_cbc("2b7e151628aed2a6abf7158809cf4f3c", "73bed6b8e3c1743b7116e69e22229516", true, \
                  "f69f2445df4f9b17ad2b417be66c3710", "3ff1caa1681fac09120eca307586e1a78cb82807230e1321d3fae00d18cc2012");

    // NIST AES CBC 256-bit encryption test-vectors
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "000102030405060708090A0B0C0D0E0F", false, "6bc1bee22e409f96e93d7e117393172a", \
                  "f58c4c04d6e5f1ba779eabfb5f7bfbd6");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "F58C4C04D6E5F1BA779EABFB5F7BFBD6", false, "ae2d8a571e03ac9c9eb76fac45af8e51", \
                  "9cfc4e967edb808d679f777bc6702c7d");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "9CFC4E967EDB808D679F777BC6702C7D", false, "30c81c46a35ce411e5fbc1191a0a52ef",
                  "39f23369a9d9bacfa530e26304231461");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "39F23369A9D9BACFA530E26304231461", false, "f69f2445df4f9b17ad2b417be66c3710", \
                  "b2eb05e2c39be9fcda6c19078c6a9d1b");

    // The same vectors with padding enabled
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "000102030405060708090A0B0C0D0E0F", true, "6bc1bee22e409f96e93d7e117393172a", \
                  "f58c4c04d6e5f1ba779eabfb5f7bfbd6485a5c81519cf378fa36d42b8547edc0");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "F58C4C04D6E5F1BA779EABFB5F7BFBD6", true, "ae2d8a571e03ac9c9eb76fac45af8e51", \
                  "9cfc4e967edb808d679f777bc6702c7d3a3aa5e0213db1a9901f9036cf5102d2");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "9CFC4E967EDB808D679F777BC6702C7D", true, "30c81c46a35ce411e5fbc1191a0a52ef",
                  "39f23369a9d9bacfa530e263042314612f8da707643c90a6f732b3de1d3f5cee");
    test_aes256_cbc("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", \
                  "39F23369A9D9BACFA530E26304231461", true, "f69f2445df4f9b17ad2b417be66c3710", \
                  "b2eb05e2c39be9fcda6c19078c6a9d1b3f461796d6b0d6b2e0c2a72b4d80e644");
}



BOOST_AUTO_TEST_SUITE_END()

