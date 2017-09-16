#ifndef CRSA_H
#define CRSA_H

#include <fstream>
#include <string>

#include "crypto/key.h"
#include "crypto/big_number.h"

//----- CRSAKey ---------------------------------------------------------------

struct SRSAData
{
public:
    CBigNumber n;           //! Modulus: n = p*q
    CBigNumber e;           //! Public exponent
    CBigNumber d;           //! Private exponent
    CBigNumber p;           //! First prime number
    CBigNumber q;           //! Second prime number
    CBigNumber e1;          //! e1 = dp
    CBigNumber e2;          //! e2 = dq
    CBigNumber coefficient; //! Phi(n)

    SRSAData(RSA *r)
    {
        uint32_t byteSize = RSA_size(r);
        uint32_t bitSize = byteSize * 8;

        n.resize(bitSize);
        e.resize(bitSize);
        d.resize(bitSize);
        p.resize(bitSize);
        q.resize(bitSize);
        e1.resize(bitSize);
        e2.resize(bitSize);
        coefficient.resize(bitSize);

        unsigned char* tempNumber = new unsigned char[byteSize];

        int byteCopied;

        byteCopied = BN_bn2bin(r->n, tempNumber);
        n.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->e, tempNumber);
        e.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->d, tempNumber);
        d.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->p, tempNumber);
        p.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->q, tempNumber);
        q.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->dmp1, tempNumber);
        e1.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->dmq1, tempNumber);
        e2.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->iqmp, tempNumber);
        coefficient.SetBin(tempNumber, byteCopied);

        delete[] tempNumber;
    }
    SRSAData(uint32_t bitSize): n(bitSize), e(bitSize), d(bitSize), p(bitSize), q(bitSize), e1(bitSize), e2(bitSize), coefficient(bitSize) {}
};

struct SRSAPublicData
{
public:
    CBigNumber n;
    CBigNumber e;

    SRSAPublicData(RSA *r)
    {
        uint32_t byteSize = RSA_size(r);
        uint32_t bitSize = byteSize * 8;

        n.resize(bitSize);
        e.resize(bitSize);

        unsigned char* tempNumber = new unsigned char[byteSize];

        int byteCopied;

        byteCopied = BN_bn2bin(r->n, tempNumber);
        n.SetBin(tempNumber, byteCopied);

        byteCopied = BN_bn2bin(r->e, tempNumber);
        e.SetBin(tempNumber, byteCopied);

        delete[] tempNumber;
    }
    SRSAPublicData(uint32_t bitSize): n(bitSize), e(bitSize){}

};

class CRSAPrivateKey;
class CRSAPublicKey;

//! Class with all static functions to generate new RSA key pair or load RSA key from file.
class CRSA
{
    friend class CRSAPrivateKey;
    friend class CRSAPublicKey;

    static const uint32_t PEM_CHAR_PER_LINE = 64;

public:
    static bool OpenSSL_GenerateNewKey(uint32_t keyBit, CRSAPrivateKey *&privateKey, CRSAPublicKey *&publicKey);

    static CRSAPrivateKey* OpenSSL_LoadPrivateKeyFromFile(std::string fileName, std::string fileFormat, std::string password="") ;
    static CRSAPrivateKey* OpenSSL_LoadPrivateKeyFromStream(std::ifstream f, std::string fileFormat, std::string password="");
    static CRSAPrivateKey* OpenSSL_LoadPrivateKeyFromString(std::string strKey, std::string fileFormat, std::string password="");
    static CRSAPrivateKey* OpenSSL_LoadPrivateKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password="");
    static CRSAPrivateKey* OpenSSL_LoadPrivateKeyFromHexString(std::string strKey, std::string fileFormat, std::string password="");

    static CRSAPublicKey* OpenSSL_LoadPublicKeyFromFile(std::string fileName, std::string fileFormat, std::string password="") ;
    static CRSAPublicKey* OpenSSL_LoadPublicKeyFromStream(std::ifstream f, std::string fileFormat, std::string password="");
    static CRSAPublicKey* OpenSSL_LoadPublicKeyFromString(std::string strKey, std::string fileFormat, std::string password="");
    static CRSAPublicKey* OpenSSL_LoadPublicKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password="");
    static CRSAPublicKey* OpenSSL_LoadPublicKeyFromHexString(std::string strKey, std::string fileFormat, std::string password="");


private:
    //! Should move these function to somewhere private??
    static void WritePrivateDataInDerFormat(std::stringstream &ss, const SRSAData data, bool trimZero=true);
    static void WritePublicDataInDerFormat(std::stringstream &ss, const SRSAPublicData data, bool trimZero=true);

    static bool Encrypt_Decrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &input, std::vector<unsigned char> &output);
    static bool Decrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &cipher, std::vector<unsigned char> &msg);
    static bool Encrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &input, std::vector<unsigned char> &output);

    static bool GetPrivateDer(const SRSAData &data, std::string &der);
    static bool GetPublicDer(const SRSAPublicData data, std::string &der);

    static bool Der2Pem(const std::string &der, std::string &pem, const std::string &keyType, const uint32_t charPerLine=PEM_CHAR_PER_LINE);

    static bool GetPrivatePem(const SRSAData &data, std::string &pem, uint32_t charPerLine=PEM_CHAR_PER_LINE);
    static bool GetPublicPem(const SRSAPublicData data, std::string &pem,  uint32_t charPerLine=PEM_CHAR_PER_LINE);


};


///----- CRSAPrivateKey --------------------------------------------------------
class CRSAPrivateKey final: public CPrivateKey
{
private:
    SRSAData m_Data;
    //std::string m_strPem;
    //std::string m_strDer;

    //! Key have not been initalize
    bool m_isValid = false;


public:

    bool IsValid() const {return m_isValid;}

    //! TODO: Update these two functions to generate pem/der dymamically.
    std::string GetPemString(bool breakLine=true) const {
        std::string strPem;
        if (breakLine)
            CRSA::GetPrivatePem(m_Data, strPem);
        else
            CRSA::GetPrivatePem(m_Data, strPem, 0);

        return strPem;
    }
    std::string GetDerString() const
    {
        std::string strDer;
        CRSA::GetPrivateDer(m_Data, strDer);
        return strDer;
    }

    SRSAData GetData() const {return m_Data;}

    CRSAPrivateKey(const CRSAPrivateKey &key): CKey(key.bitsize(), key.algorithm()), m_Data(key.bitsize())
    {
        m_Data = key.m_Data;
        //m_strDer = key.m_strDer;
        //m_strPem = key.m_strPem;
        m_isValid = key.m_isValid;
    }

    CRSAPrivateKey(const SRSAData &data): CKey(data.n.bitsize(), crypto::RSA_), m_Data(data.n.bitsize())
    {
        m_Data = data;
        //m_strDer = der;
        //m_strPem = pem;

        //! For now, just simply verify if the key's len > 0 then it's valid.
        if (data.n.bitsize() > 0 && data.n.bitsize()%8 == 0)
            m_isValid = true;
    }

    bool SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;
    bool OpenSSL_SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;

    CRSAPublicKey* GetPublicKey() const;

    CRSAPrivateKey& operator=(const CRSAPrivateKey &key)
    {
        m_KeySize = key.m_KeySize;
        m_Algorithm = key.m_Algorithm;
        m_Data = key.m_Data;
        //m_strDer = key.m_strDer;
        //m_strPem = key.m_strPem;
        m_isValid = key.m_isValid;

        return *this;
    }
    bool Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;
    bool Decrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;
    bool Sign(const std::string &msg, std::string &sign) const;
    bool Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;

    bool OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const;
    bool OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const;
    bool OpenSSL_Sign(const std::string &msg, std::string &sign) const;
    bool OpenSSL_Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;

};


///----- CRSAPublicKey ---------------------------------------------------------
class CRSAPublicKey final: public CPublicKey
{

private:
    SRSAPublicData m_Data;

    //! Caution: these 2 values need to be manually sync with m_Data when there are any changing.
    //! The functions which convert from m_Data to string are available in CRSA class: Get[Private/Public][Der/Pem]
    //! Thinking about remove these variables. Generated when use only.
    //std::string m_strPem;
    //std::string m_strDer;

    //!Key have not been initalize
    bool m_isValid = false;

public:
    bool IsValid() const {return m_isValid;}

    //! TODO: Update these two functions to generate pem/der dymamically.
    std::string GetPemString(bool breakLine=true) const
    {
        std::string strPem;
        if (breakLine)
            CRSA::GetPublicPem(m_Data, strPem);
        else
            CRSA::GetPublicPem(m_Data, strPem, 0);
        return strPem;
    }
    std::string GetDerString() const
    {
        std::string strDer;
        CRSA::GetPublicDer(m_Data, strDer);
        return strDer;
    }

    SRSAPublicData GetData() const {return m_Data;}

    CRSAPublicKey(const CRSAPublicKey &key): CKey(key.bitsize(), key.algorithm()), m_Data(key.bitsize())
    {
        m_Data = key.m_Data;
        //m_strDer = key.m_strDer;
        //m_strPem = key.m_strPem;
        m_isValid = key.m_isValid;
    }

    CRSAPublicKey(const SRSAPublicData &data): CKey(data.n.bitsize(), crypto::RSA_), m_Data(data.n.bitsize())
    {
        m_Data = data;
        //m_strDer = der;
        //m_strPem = pem;

        //! For now, just simply verify if the key's len > 0 then it's valid.
        if (data.n.bitsize() > 0 && data.n.bitsize()%8 == 0)
            m_isValid = true;
    }

    bool SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;
    bool OpenSSL_SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;

    CRSAPublicKey& operator=(const CRSAPublicKey &key)
    {
        m_KeySize = key.m_KeySize;
        m_Algorithm = key.m_Algorithm;
        m_Data = key.m_Data;
        //m_strDer = key.m_strDer;
        //m_strPem = key.m_strPem;
        m_isValid = key.m_isValid;

        return *this;
    }


    bool Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;
    bool Decrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const;
    bool Verify(const std::string &msg, const std::string &sign) const;
    bool Verify(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &sign) const;

    bool OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const;
    bool OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const;
    bool OpenSSL_Verify(const std::string &msg, const std::string &sign) const;
    bool OpenSSL_Verify(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &sign) const;
};

#endif // CRSA_H
