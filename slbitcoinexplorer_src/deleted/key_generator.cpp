#include <exception>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <iostream>

#include "key_generator.h"
#include "key.h"
#include "crypto/big_number.h"
#include "util/openssl_util.h"
#include "rsa.h"

//Common Utilities functions --------------------------------------------------
void FreeOpenSSLObjects(BIGNUM*& number)
{
    //RSA_free(rsa);
    BN_free(number);
}

//generate symetric key

CKeyGenerator::CKeyGenerator(std::string keyType, size_t keySize)
{
    this->keyType = keyType;
    this->keySize = keySize;
}


//generate public/private keypair ---------------------------------------------

CKeyPairGenerator::CKeyPairGenerator(std::string keyType, size_t keySize)
{
    this->keyType = keyType;
    this->keySize = keySize;
}

CKeyPair* CKeyPairGenerator::GenerateKeyPair()
{
    if (this->keyType == crypto::RSA_)
    {
        return GenerateRSAKeyPair();
    }
    else if (this->keyType == crypto::EC_)
    {
        return GenerateECKeyPair();
    }
    return NULL;

}

CKeyPair* CKeyPairGenerator::GenerateRSAKeyPair()
{
    int             ret = 0;
    RSA             *r = NULL;
    BIGNUM          *bne = NULL;

    int             bits = this->keySize;

    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        FreeOpenSSLObjects(bne);
        return NULL;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        FreeOpenSSLObjects(bne);
        return NULL;
    }

    // 2. Convert key to our format:

    CBigNumber n(this->keySize), e0(this->keySize), d(this->keySize), p(this->keySize), q(this->keySize), e1(this->keySize), e2(this->keySize), coefficient(this->keySize);

    int nByte = this->keySize/8;
    unsigned char* tempNumber = new unsigned char[nByte];

    int nByteCopied;

    nByteCopied = BN_bn2bin(r->n, tempNumber);
    n.SetBin(tempNumber, nByteCopied);

    e0.SetHex("0x10001");

    nByteCopied = BN_bn2bin(r->d, tempNumber);
    d.SetBin(tempNumber, nByteCopied);

    //std::cout << "d" << d.GetHex().c_str() << std::endl;

    nByteCopied = BN_bn2bin(r->p, tempNumber);
    p.SetBin(tempNumber, nByteCopied);


    nByteCopied = BN_bn2bin(r->q, tempNumber);
    q.SetBin(tempNumber, nByteCopied);

    nByteCopied = BN_bn2bin(r->dmp1, tempNumber);
    e1.SetBin(tempNumber, nByteCopied);

    nByteCopied = BN_bn2bin(r->dmq1, tempNumber);
    e2.SetBin(tempNumber, nByteCopied);

    nByteCopied = BN_bn2bin(r->iqmp, tempNumber);
    coefficient.SetBin(tempNumber, nByteCopied);

    std::string strPriPem, strPubPem;

    strPriPem = ::RSAToPem(r, crypto::PRIVATE_MODE);
    strPubPem = ::RSAToPem(r, crypto::PUBLIC_MODE);

    RSA_free(r);

    return new CKeyPair(new CRSAPrivateKey(strPriPem, n, e0, d, p, q, e1, e2, coefficient), new CRSAPublicKey(strPubPem, n, e0));
}

CKeyPair* CKeyPairGenerator::GenerateECKeyPair()
{
    //TODO
    return NULL;
}




