#ifndef CKEYGENERATOR_H
#define CKEYGENERATOR_H

#include "key.h"


class CKeyGenerator
{

    //static CPrivateKey GenerateKey(ECryptoAlgorithmType keyType, size_t keySize);

public:
    CKeyGenerator(std::string keyType, size_t keySize);
    bool GenerateKey(CKey &key);

private:
    std::string keyType;
    size_t keySize;
};

class CKeyPairGenerator
{

    //static CKeyPair GenerateKeyPair(ECryptoAlgorithmType keyType, size_t keySize);

public:
    CKeyPairGenerator(std::string keyType, size_t keySize);

    CKeyPair* GenerateKeyPair();

private:
    std::string keyType;
    int keySize;

    CKeyPair* GenerateRSAKeyPair();
    CKeyPair* GenerateECKeyPair();
};


#endif // CKEYGENERATOR_H
