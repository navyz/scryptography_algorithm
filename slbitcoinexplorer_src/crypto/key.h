#ifndef CKEY_H
#define CKEY_H

#include <string>
#include <vector>
#include <openssl/rsa.h>
#include <openssl/ecdsa.h>

#include "crypto/big_number.h"

namespace crypto
{
    const std::string RSA_ = "RSA";
    const std::string ECDSA = "ECDSA";

    const std::string PEM_ = "PEM";
    const std::string PER_ = "PER";
    const std::string DER_ = "DER";
    const std::string BITCOIN_ = "BITCOIN";

    const std::string PUBLIC_MODE = "PUBLIC";
    const std::string PRIVATE_MODE = "PRIVATE";

}


//----- CKey ------------------------------------------------------------------
class CKey
{
public:

    CKey(uint32_t keySize, std::string algorithm)
    {
        m_KeySize = keySize;
        m_Algorithm = algorithm;
    }
    std::string algorithm() const {return m_Algorithm;}
    uint32_t bitsize() const {return m_KeySize;}
    uint32_t bytesize() const {return m_KeySize/8;}

    virtual bool SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const = 0;

protected:
    std::string m_Algorithm;
    uint32_t m_KeySize;     //in bit, not byte


};

//----- CPrivateKey -----------------------------------------------------------
class CPrivateKey: public virtual CKey
{
    virtual bool Sign(const std::string &msg, std::string &sign) const = 0;
    virtual bool Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const =0;
};

//----- CPublicKey ------------------------------------------------------------

class CPublicKey: public virtual CKey
{
    virtual bool Verify(const std::string &msg, const std::string &sign) const =0;
    virtual bool Verify(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &sign) const =0;
};



/*

//----- CKeyPair --------------------------------------------------------------
class CKeyPair
{
public:

    CKeyPair(CPrivateKey* pri, CPublicKey* pub): privateKey(pri), publicKey(pub){}

    CPrivateKey* privateKey;
    CPublicKey* publicKey;
};

*/
#endif // CKEY_H
