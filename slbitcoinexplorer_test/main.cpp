
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE slmain
#define BOOST_TEST_LOG_LEVEL all

#include <boost/test/unit_test.hpp>
#include <sstream>

#include "util/common_util.h"

#define LITTLE_ENDIAN 0x78696E55UL
#define BIG_ENDIAN    0x556E6978UL
#define PDP_ENDIAN    0x6E557869UL
#define ENDIAN_ORDER  ('Unix')

#define GETRANDOM 1

    #if ENDIAN_ORDER==LITTLE_ENDIAN
        #define _H_ORDER "machine is little endian"
    #elif ENDIAN_ORDER==BIG_ENDIAN
        #define _H_ORDER "machine is big endian"
    #elif ENDIAN_ORDER==PDP_ENDIAN
        #define _H_ORDER "machine is PDP"
    #else
        #define _H_ORDER "What kind of hardware is this?!"
    #endif




struct test_fixture__global
{

    test_fixture__global() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "---------------------- test_fixture__global setup ----------------------" );

    }
    ~test_fixture__global()
    {
        BOOST_TEST_MESSAGE( "---------------------- test_fixture__global teardown ----------------------" );
    }

    int i;
};

BOOST_GLOBAL_FIXTURE( test_fixture__global );

BOOST_AUTO_TEST_CASE(main_fixure)
{

    BOOST_TEST_MESSAGE("----------- start testing ----------");
    BOOST_TEST_MESSAGE(_H_ORDER);
    BOOST_CHECK(true);

}

