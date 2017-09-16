#include <string>
#include <iostream>

#include <boost/test/unit_test.hpp>
#include "crypto/base58.h"
#include "util/encoding_util.h"


struct base58_test_fixture_testsuite
{

    base58_test_fixture_testsuite() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "---------------------- base58_test setup -----------------------" );

    }
    ~base58_test_fixture_testsuite()
    {
        BOOST_TEST_MESSAGE( "---------------------- base58_test tear down -------------------" );
    }

    int i;
};

struct base58_test_fixture__per_testcase
{

    base58_test_fixture__per_testcase() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "--- start test case ---" );

    }
    ~base58_test_fixture__per_testcase()
    {
        BOOST_TEST_MESSAGE( "--- end test case ---" );
    }

    int i;
};

#define BOOST_TEST_MODULE base58_test

#define BASE58_TEST_CASE(name_) \
    BOOST_FIXTURE_TEST_CASE(base58_##name_, base58_test_fixture__per_testcase)

BOOST_FIXTURE_TEST_SUITE(base58_test, base58_test_fixture_testsuite);


std::string test_data[][2] = {{"", ""},
                              {"61", "2g"},
                              {"626262", "a3gV"},
                              {"636363", "aPEr"},
                              {"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
                              {"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
                              {"516b6fcd0f", "ABnLTmg"},
                              {"bf4f89001e670274dd", "3SEo3LWLoPntC"},
                              {"572e4794", "3EFU7m"},
                              {"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
                              {"10c8511e", "Rt5zm"},
                              {"00000000000000000000", "1111111111"}
                             };


void EncodeBase58_Test(std::string input, std::string expected)
{
    std::vector<unsigned char> vch = ::ParseHex(input);
    std::string strEncoded(EncodeBase58(vch));

    BOOST_CHECK_MESSAGE(strEncoded == expected, "Encode base58 error");
}

void DecodeBase58_Test(std::string input, std::string expected)
{
    std::vector<unsigned char> ret;
    DecodeBase58(input, ret);
    std::string strDecoded = ::GetHex(ret);
    std::transform(strDecoded.begin(), strDecoded.end(), strDecoded.begin(), ::tolower);

    BOOST_CHECK_MESSAGE(strDecoded == expected, "Decode base58 error");

}

// Goal: test low-level base58 encoding functionality
BASE58_TEST_CASE(EncodeBase58)
{
    int len = sizeof(test_data)/sizeof(test_data[0]);
    for (int i=0; i<len; i++)
        EncodeBase58_Test(test_data[i][0], test_data[i][1]);

}

// Goal: test low-level base58 decoding functionality
BASE58_TEST_CASE(DecodeBase58)
{
    int len = sizeof(test_data)/sizeof(test_data[0]);
    for (int i=0; i<len; i++)
        DecodeBase58_Test(test_data[i][1], test_data[i][0]);
}



BOOST_AUTO_TEST_SUITE_END()

