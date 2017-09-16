#ifndef CCIPHER_H
#define CCIPHER_H

#include <string>
#include <vector>

#include "key.h"
#include "rsa.h"

class CRSACipher;

class CCipher
{

public:

    static CCipher* GetInstance(std::string);

    virtual bool Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const = 0;
    virtual bool Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const = 0;
    virtual bool Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature) const = 0;

    std::string m_algorithm = crypto::RSA_;    //RSA or ECDSA
    std::string m_mode = crypto::PUBLIC_MODE;         //public or private
    uint32_t m_keyBit = 0;

};

class CRSACipher final: public CCipher
{
public:

    CRSAPrivateKey* m_pPrivateKey;
    CRSAPublicKey* m_pPublicKey;


    bool InitPrivateKey(CRSAPrivateKey* key)
    {
        m_pPrivateKey = key;

        m_mode = crypto::PRIVATE_MODE;
        m_keyBit = key->bitsize();

        return true;

    }

    bool InitPublicKey(CRSAPublicKey* key)
    {
        m_pPublicKey = key;

        m_mode = crypto::PUBLIC_MODE;
        m_keyBit = key->bitsize();

        return true;

    }
    bool Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const;
    bool Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const;
    bool Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature) const;

    bool OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const;
    bool OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const;
    bool OpenSSL_Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature) const;

};

#endif // CCIPHER_H
