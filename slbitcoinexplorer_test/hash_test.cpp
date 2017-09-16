#include <string>
#include <iostream>

#include <boost/test/unit_test.hpp>
#include "crypto/sha1.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "crypto/ripemd160.h"
#include "util/encoding_util.h"


struct hash_test_fixture_testsuite
{

    hash_test_fixture_testsuite() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "---------------------- hash_test setup -----------------------" );

    }
    ~hash_test_fixture_testsuite()
    {
        BOOST_TEST_MESSAGE( "---------------------- hash_test tear down -------------------" );
    }

    int i;
};

struct hash_test_fixture__per_testcase
{

    hash_test_fixture__per_testcase() : i( 0 )
    {
        BOOST_TEST_MESSAGE( "--- start test case ---" );

    }
    ~hash_test_fixture__per_testcase()
    {
        BOOST_TEST_MESSAGE( "--- end test case ---" );
    }

    int i;
};

#define BOOST_TEST_MODULE hash_test

#define HASH_TEST_CASE(name_) \
    BOOST_FIXTURE_TEST_CASE(hash_##name_, hash_test_fixture__per_testcase)

BOOST_FIXTURE_TEST_SUITE(hash_test, hash_test_fixture_testsuite);


std::string LongTestString(void) {
    std::string ret;
    for (int i=0; i<200000; i++) {
        ret += (unsigned char)(i);
        ret += (unsigned char)(i >> 4);
        ret += (unsigned char)(i >> 8);
        ret += (unsigned char)(i >> 12);
        ret += (unsigned char)(i >> 16);
    }
    return ret;
}

const std::string test1 = LongTestString();

template<typename Hasher>
void TestHash(Hasher sha, string input, string expected_hash)
{
    vector<unsigned char> hash;
    vector<unsigned char> out = ParseHex(expected_hash);

    hash.resize(out.size());

    sha.Write((unsigned char*)input.c_str(), input.length());
    sha.Finalize(&hash[0]);

    BOOST_CHECK(hash==out);
}

void TestSHA1(const std::string &in, const std::string &hexout) { TestHash(CSHA1(), in, hexout);}
void TestSHA256(const std::string &in, const std::string &hexout) { TestHash(CSHA256(), in, hexout);}
void TestSHA512(const std::string &in, const std::string &hexout) { TestHash(CSHA512(), in, hexout);}
void TestRIPEMD160(const std::string &in, const std::string &hexout) { TestHash(CRIPEMD160(), in, hexout);}

HASH_TEST_CASE(sha1_encode)
{
    TestSHA1("", "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    TestSHA1("0", "b6589fc6ab0dc82cf12099d1c2d40ab994e8410c");
    TestSHA1("a", "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
    TestSHA1("leminhson", "fc0a013e8573664e6b375cae8264c08547a2d094");

    TestSHA1("abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    TestSHA1("message digest", "c12252ceda8be8994d5fa0290a47231c1d16aae3");
    TestSHA1("secure hash algorithm", "d4d6d2f0ebe317513bbd8d967d89bac5819c2f60");
    TestSHA1("SHA1 is considered to be safe", "f2b6650569ad3a8720348dd6ea6c497dee3a842a");
    TestSHA1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
             "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    TestSHA1("For this sample, this 63-byte string will be used as input data",
             "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49");
    TestSHA1("This is exactly 64 bytes long, not counting the terminating byte",
             "fb679f23e7d1ce053313e66e127ab1b444397057");
    TestSHA1(std::string(1000000, 'a'), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    TestSHA1(test1, "b7755760681cbfd971451668f32af5774f4656b5");
}

HASH_TEST_CASE(sha256_encode)
{
    TestSHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TestSHA256("0", "5feceb66ffc86f38d952786c6d696c79c2dbc239dd4e91b46729d73a27fb57e9");
    TestSHA256("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb");
    TestSHA256("leminhson", "a4b5535fed8b45e4b6cd86151a7c32c9a2e12c651950feecb416ab4f31e74867");

    TestSHA256("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    TestSHA256("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    TestSHA256("message digest",
               "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650");
    TestSHA256("secure hash algorithm",
               "f30ceb2bb2829e79e4ca9753d35a8ecc00262d164cc077080295381cbd643f0d");
    TestSHA256("SHA256 is considered to be safe",
               "6819d915c73f4d1e77e4e1b52d1fa0f9cf9beaead3939f15874bd988e2a23630");
    TestSHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
               "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    TestSHA256("For this sample, this 63-byte string will be used as input data",
               "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342");
    TestSHA256("This is exactly 64 bytes long, not counting the terminating byte",
               "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8");
    TestSHA256("As Bitcoin relies on 80 byte header hashes, we want to have an example for that.",
               "7406e8de7d6e4fffc573daef05aefb8806e7790f55eab5576f31349743cca743");
    TestSHA256(std::string(1000000, 'a'),
               "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    TestSHA256(test1, "a316d55510b49662420f49d145d42fb83f31ef8dc016aa4e32df049991a91e26");
}


HASH_TEST_CASE(sha512_encode)
{
    TestSHA512("", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    TestSHA512("0", "31bca02094eb78126a517b206a88c73cfa9ec6f704c7030d18212cace820f025f00bf0ea68dbf3f3a5436ca63b53bf7bf80ad8d5de7d8359d0b7fed9dbc3ab99");
    TestSHA512("a", "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75");
    TestSHA512("leminhson", "dfb617271897c6b77526c158e6eb12298e866e7749b1bfbfc0d250d5f85140b3193d108633ffa901a1e54b1289852b72ef31ce20e58e38ac30bc49d354164606");

    TestSHA512("",
               "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    TestSHA512("abc",
               "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    TestSHA512("message digest",
               "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f33"
               "09e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c");
    TestSHA512("secure hash algorithm",
               "7746d91f3de30c68cec0dd693120a7e8b04d8073cb699bdce1a3f64127bca7a3"
               "d5db502e814bb63c063a7a5043b2df87c61133395f4ad1edca7fcf4b30c3236e");
    TestSHA512("SHA512 is considered to be safe",
               "099e6468d889e1c79092a89ae925a9499b5408e01b66cb5b0a3bd0dfa51a9964"
               "6b4a3901caab1318189f74cd8cf2e941829012f2449df52067d3dd5b978456c2");
    TestSHA512("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
               "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
               "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445");
    TestSHA512("For this sample, this 63-byte string will be used as input data",
               "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e"
               "6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766");
    TestSHA512("This is exactly 64 bytes long, not counting the terminating byte",
               "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a38"
               "7d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030");
    TestSHA512("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
               "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
               "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
               "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    TestSHA512(std::string(1000000, 'a'),
               "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
               "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");
    TestSHA512(test1,
               "40cac46c147e6131c5193dd5f34e9d8bb4951395f27b08c558c65ff4ba2de594"
               "37de8c3ef5459d76a52cedc02dc499a3c9ed9dedbfb3281afd9653b8a112fafc");
}


HASH_TEST_CASE(ripemd160_encode)
{
    TestRIPEMD160("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    TestRIPEMD160("0", "ba5ed015715da74cf1e87230ba73d4855edaf6f6");
    TestRIPEMD160("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    TestRIPEMD160("leminhson", "b04cc6641460a17b84b082f01815f13c70ab2cb2");

    TestRIPEMD160("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    TestRIPEMD160("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
    TestRIPEMD160("secure hash algorithm", "20397528223b6a5f4cbc2808aba0464e645544f9");
    TestRIPEMD160("RIPEMD160 is considered to be safe", "a7d78608c7af8a8e728778e81576870734122b66");
    TestRIPEMD160("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                     "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
    TestRIPEMD160("For this sample, this 63-byte string will be used as input data",
                     "de90dbfee14b63fb5abf27c2ad4a82aaa5f27a11");
    TestRIPEMD160("This is exactly 64 bytes long, not counting the terminating byte",
                     "eda31d51d3a623b81e19eb02e24ff65d27d67b37");
    TestRIPEMD160(std::string(1000000, 'a'), "52783243c1697bdbe16d37f97f68f08325dc1528");
    TestRIPEMD160(test1, "464243587bd146ea835cdf57bdae582f25ec45f1");

}


BOOST_AUTO_TEST_SUITE_END()

/*
0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6
600FFE422B4E00731A59557A5CCA46CC183944191006324A447BDB2D98D4B408
010966776006953D5567439E5E39F86A0D273BEE

0450863AD64A87AE8A2FE83C1AF1A8403CB53F53E486D8511DAD8A04887E5B23522CD470243453A299FA9E77237716103ABC11A1DF38855ED6F2EE187E9C582BA6
600FFFFFFFFE422B4E00731A59557A5CFFFFFFCA46FFFFFFCC183944191006324A447BFFFFFFDB2DFFFFFF98FFFFFFD4FFFFFFB408
*/
