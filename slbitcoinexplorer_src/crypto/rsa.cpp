#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <stdio.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "util/encoding_util.h"
#include "util/openssl_util.h"
#include "util/exception.h"
#include "util/common_util.h"

#include "crypto/key.h"
#include "crypto/rsa.h"


///----- CRSA class -----------------------------------------------------------

//! DER format can be found in X.690 specification
void CRSA::WritePrivateDataInDerFormat(std::stringstream &ss, const SRSAData data, bool trimZero)
{
    WriteNumberInDerFormat(ss, data.n, trimZero);
    WriteNumberInDerFormat(ss, data.e, trimZero);
    WriteNumberInDerFormat(ss, data.d, trimZero);
    WriteNumberInDerFormat(ss, data.p, trimZero);
    WriteNumberInDerFormat(ss, data.q, trimZero);
    WriteNumberInDerFormat(ss, data.e1, trimZero);
    WriteNumberInDerFormat(ss, data.e2, trimZero);
    WriteNumberInDerFormat(ss, data.coefficient, trimZero);
}

void CRSA::WritePublicDataInDerFormat(std::stringstream &ss, const SRSAPublicData data, bool trimZero)
{
    WriteNumberInDerFormat(ss, data.n, trimZero);
    WriteNumberInDerFormat(ss, data.e, trimZero);
}



bool CRSA::GetPrivateDer(const SRSAData &data, std::string &der)
{
    std::stringstream s0, s1;

    //! Write the body first, header this the size of this content
    //! - Write version first
    s1.put(0x02).put(0x01).put(0x00);

    //! - Then content
    WritePrivateDataInDerFormat(s1, data, true);

    //! - Then header last (because header need the content's size
    size_t nValueSize = s1.str().size();
    WriteHeader(s0, nValueSize);

    //! Combine header and content and return. Reuse the strHeader
    s0 << s1.str();

    der = s0.str();

    return true;
}
bool CRSA::GetPublicDer(const SRSAPublicData data, std::string &der)
{
    std::stringstream s0, s1;

    //! Write the body first, header need the size of this content

    //! - body
    WritePublicDataInDerFormat(s1, data, true);

    //! - header
    size_t nValueSize = s1.str().size();
    WriteHeader(s0, nValueSize);

    //! Combine header and content and return
    s0 << s1.str();

    der = s0.str();

    return true;
}

bool CRSA::Der2Pem(const std::string &der, std::string &pem, const std::string &keyType, const uint32_t charPerLine)
{
    std::stringstream ss;

    ss << "-----BEGIN RSA " << keyType << " KEY-----\n";
    if (charPerLine == 0)
        ss << ::EncodeBase64(der);
    else
    {
        ss << BreakLine(::EncodeBase64(der), charPerLine);
    }
    ss << "\n-----END RSA " << keyType << " KEY-----\n";
    pem = ss.str();
    return true;
}


//! Write privatekey into a string PEM format
//! lineChar: maximum number of character per line. Set lineChar=0 to write all data in 1 line.
bool CRSA::GetPrivatePem(const SRSAData &data, std::string &pem, uint32_t charPerLine)
{
    std::string der;
    if (GetPrivateDer(data, der))
    {
        CRSA::Der2Pem(der, pem, crypto::PRIVATE_MODE, charPerLine);
        return true;
    }
    else
        return false;
}

bool CRSA::GetPublicPem(const SRSAPublicData data, std::string &pem,  uint32_t charPerLine)
{
    std::string der;
    if (GetPublicDer(data, der))
    {
        CRSA::Der2Pem(der, pem, crypto::PUBLIC_MODE, charPerLine);
        return true;
    }
    else
        return false;
}


//! Generate a new RSA Key Pair, using OpenSSL library
//! Thinking about writing my own code... But not for now.
bool CRSA::OpenSSL_GenerateNewKey(uint32_t keyBit, CRSAPrivateKey *&privateKey, CRSAPublicKey *&publicKey)
{
    if (privateKey != NULL)
        delete privateKey;
    if (publicKey != NULL)
        delete publicKey;

    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;

    unsigned long   e = RSA_F4;

    // 1. generate rsa key
    bne = BN_new();
    ret = BN_set_word(bne,e);
    if(ret != 1){
        BN_free(bne);
        return false;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, keyBit, bne, NULL);
    if(ret != 1){
        BN_free(bne);
        return false;
    }

    // 2. Convert key to our format:

    SRSAData privateData(r);
    SRSAPublicData publicData(r);

    RSA_free(r);

    privateKey = new CRSAPrivateKey(privateData);
    publicKey = new CRSAPublicKey(publicData);

    return true;
}

//! Loading the private key from file
//! Two formats are support for now: PEM and DER
CRSAPrivateKey* CRSA::OpenSSL_LoadPrivateKeyFromFile(std::string fileName, std::string fileFormat, std::string password)
{
    RSA* rsa = NULL;
    FILE * fp;

    if(NULL != (fp= fopen(fileName.c_str(), "r")) )
    {
        if (fileFormat == crypto::PEM_)
            rsa = PEM_read_RSAPrivateKey(fp,NULL,NULL,NULL);
        else if (fileFormat ==crypto::DER_)
            rsa =  d2i_RSAPrivateKey_fp(fp, NULL);

        if(rsa==NULL)
        {
            throw logic_exception("Could NOT read RSA private key file");
        }
        else
        {
            SRSAData privateData(rsa);
            RSA_free(rsa);
            return new CRSAPrivateKey(privateData);
        }
    }
    throw new std::exception();
}

//! These functions are for convenience. Thus, they are not implemented yet.
CRSAPrivateKey* CRSA::OpenSSL_LoadPrivateKeyFromStream(std::ifstream f, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPrivateKey* CRSA::OpenSSL_LoadPrivateKeyFromString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPrivateKey* CRSA::OpenSSL_LoadPrivateKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPrivateKey* CRSA::OpenSSL_LoadPrivateKeyFromHexString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}


//! Loading the public key from file
//! Two formats are support for now: PEM and DER
CRSAPublicKey* CRSA::OpenSSL_LoadPublicKeyFromFile(std::string fileName, std::string fileFormat, std::string password)
{
    RSA* rsa = NULL;
    FILE * fp;

    if(NULL != (fp= fopen(fileName.c_str(), "r")) )
    {
        if (fileFormat == crypto::PEM_)
            rsa = PEM_read_RSAPublicKey(fp,NULL,NULL,NULL);
        else if (fileFormat ==crypto::DER_)
            rsa =  d2i_RSAPublicKey_fp(fp, NULL);

        if(rsa==NULL)
        {
            printf("\n\tCould NOT read RSA private key file");
        }
        else
        {
            SRSAPublicData publicData(rsa);

            /*
            std::string pubPem, pubDer;

            pubPem = ::RSAToPem(rsa, crypto::PUBLIC_MODE);
            pubDer = ::RSAToDer(rsa, crypto::PUBLIC_MODE);
            */
            RSA_free(rsa);

            return new CRSAPublicKey(publicData);
        }
    }
    throw new std::exception();
}


CRSAPublicKey* CRSA::OpenSSL_LoadPublicKeyFromStream(std::ifstream f, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPublicKey* CRSA::OpenSSL_LoadPublicKeyFromString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPublicKey* CRSA::OpenSSL_LoadPublicKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CRSAPublicKey* CRSA::OpenSSL_LoadPublicKeyFromHexString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}

/*
CRSAPublicKey* CRSA::OpenSSL_LoadPublicFromFile(std::string fileName, std::string fileFormat, std::string password)
{

    RSA* rsa = NULL;
    FILE * fp;

    if(NULL != (fp= fopen(fileName.c_str(), "r")) )
    {
        if (fileFormat == crypto::PEM_)
            rsa = PEM_read_RSAPublicKey(fp,NULL,NULL,NULL);
        else if (fileFormat ==crypto::DER_)
            rsa =  d2i_RSAPublicKey_fp(fp, NULL);

        if(rsa==NULL)
        {
            printf("\n\tCould NOT read RSA private key file");
        }
        else
        {
            int nByte = RSA_size(rsa);
            int keySize = nByte * 8;

            SRSAPublicData publicData(keyBit, r);

            std::string priPem, priDer, pubPem, pubDer;

            pubPem = ::RSAToPem(rsa, crypto::PUBLIC_MODE);
            pubDer = ::RSAToDer(rsa, crypto::PUBLIC_MODE);

            RSA_free(rsa);

            publicKey = new CRSAPublicKey(privateData, pubPem, pubDer);

            return publicKey;


        }
    }
}
*/

//! RSA encrypt and decrypt is using the same machenism. encryption: m^e mod n
//! This is the common function which is sharing for encrypting and decrypting.
//! The only different is that: when encrypt, we need to pad the message before calling this function.
bool CRSA::Encrypt_Decrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &input, std::vector<unsigned char> &output)
{
    assert(modulo.bitsize() > 0);
    assert(exponent.bitsize() > 0);

    std::cout << input.size() << std::endl;
    std::cout <<modulo.bytesize() << std::endl;
    assert(input.size() == modulo.bytesize());

    CBigNumber m(input, modulo.bitsize());

    m.exp_mod(exponent, modulo);
    std::vector<unsigned char> tempOutput = m.GetBin(true);

    output.clear();
    output.reserve(tempOutput.size());
    for (uint32_t i=0; i< tempOutput.size(); i++)
        output.push_back(tempOutput[i]);

    return true;
}

//! Based on the RSA' recommendation, we need to pad the message before encrypt to avoid the serious security issue.
//! There are many padding way, this function is hard coded the RSA Padding Type 1 which is mention in PKCS#1 version 1.5
//! The latest version at the time this code is written is 2.2 which add many ways (more secure) padding
bool CRSA::Encrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &input, std::vector<unsigned char> &output)
{
    std::vector<unsigned char> padded_msg(input);

    //Using PKCS1_padding type1
    RSAPaddingPKCS1(padded_msg, modulo.bytesize());

    return Encrypt_Decrypt(modulo, exponent, padded_msg, output);
}

//! After decrypting, the padding part must be removed before returning to caller.
//! Similar as encryption, this function is hard coded the padding method on PKCS#1 version 1.5
bool CRSA::Decrypt(const CBigNumber &modulo, const CBigNumber &exponent, const std::vector<unsigned char> &cipher, std::vector<unsigned char> &msg)
{
    clock_t tStart = clock();

    bool ret;

    ret = Encrypt_Decrypt(modulo, exponent, cipher, msg);

    if (ret)
    {
        // Remove padding PKCS1 type 1
        uint32_t i=1;
        while (msg[i] != 0 && i < msg.size()) i++;

        if (i < msg.size())
            msg.erase(msg.begin(), msg.begin()+i+1);

        printf("Time taken Encrypt/Decrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);
    }

    return ret;
}

///----- CRSAPrivateKey --------------------------------------------------------
//! Generate public key from private key
CRSAPublicKey* CRSAPrivateKey::GetPublicKey() const
{
    if (m_isValid)
    {
        SRSAPublicData publicData(bitsize());
        publicData.n = m_Data.n;
        publicData.e = m_Data.e;

        std::string strDer, strPem;

        CRSA::GetPublicDer(publicData, strDer);
        CRSA::Der2Pem(strDer, strPem, crypto::PUBLIC_MODE);

        return new CRSAPublicKey(publicData);
    }
    else
        return NULL;

}

//! fileName: name of file without extension.
//! Note extension will be appended automatically based on the format
//! - DER format: .der
//! - PEM format: .pem
bool CRSAPrivateKey::SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
{
    if (fileFormat == crypto::PEM_)
    {
        WriteFile(fileName + ".pem", this->GetPemString());

    }
    else if (fileFormat == crypto::DER_)
    {
        WriteFile(fileName + ".der", this->GetDerString());

        return true;
    }
    return false;
}



bool CRSAPrivateKey::Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const
{
    return CRSA::Encrypt(m_Data.n, m_Data.d, msg, sign);
}

bool CRSAPrivateKey::Decrypt(const std::vector<unsigned char> &cipher, std::vector<unsigned char> &text) const
{
    return CRSA::Decrypt(m_Data.n, m_Data.d, cipher, text);
}



bool CRSAPrivateKey::Sign(const std::string &msg, std::string &sign) const
{
    bool ret;
    std::vector<unsigned char> vSign;
    ret = CRSA::Encrypt(m_Data.n, m_Data.d, std::vector<unsigned char>(msg.begin(), msg.end()), vSign);
    sign = std::string(vSign.begin(), vSign.end());

    return ret;
}

//! Padding the message and then encrypt with RSA private key
bool CRSAPrivateKey::Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const
{
    return CRSA::Encrypt(m_Data.n, m_Data.d, msg, sign);
}

//! Padding the message and then encrypt with RSA private key, using SSL libray
bool CRSAPrivateKey::OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const
{
    clock_t tStart = clock();

    RSAEncrypt(this->GetDerString(), msg, cipher_text, crypto::PRIVATE_MODE);

    printf("Time taken OpenSSL_Encrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}

//! Decrypt the cipher and then remove the padding
bool CRSAPrivateKey::OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &output) const
{
    clock_t tStart = clock();

    bool ret = RSADecrypt(this->GetDerString(), cipher_text, output, crypto::PRIVATE_MODE);

    printf("Time taken OpenSSL_Decrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return ret;
}


bool CRSAPrivateKey::OpenSSL_Sign(const std::string &msg, std::string &sign) const
{
    bool ret;
    std::vector<unsigned char> vSign;
    ret = this->OpenSSL_Encrypt(std::vector<unsigned char>(msg.begin(), msg.end()), vSign);
    sign = std::string(vSign.begin(), vSign.end());

    return ret;
}

bool CRSAPrivateKey::OpenSSL_Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const
{
    return this->OpenSSL_Encrypt(msg, sign);
}


//! Save private key to file. Currenty, PEM and DER format are supported
bool CRSAPrivateKey::OpenSSL_SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
{
    int ret;
    if (fileFormat == crypto::PEM_)
    {

        BIO *bp_private = NULL;

        //! -- using openssl library to write to file
        bp_private = BIO_new_file((fileName + ".pem").c_str(), "w+");

        RSA *rsa = ::RSAFromDer(this->GetDerString(), crypto::PRIVATE_MODE);
        ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
        RSA_free(rsa);
        BIO_free_all(bp_private);
        return ret;
    }
    else if (fileFormat == crypto::DER_)
    {
        BIO *bp_private = NULL;

        // -- using openssl library to write to file
        bp_private = BIO_new_file((fileName + ".der").c_str(), "w+");
        RSA *rsa = ::RSAFromDer(this->GetDerString(), crypto::PRIVATE_MODE);
        ret = i2d_RSAPrivateKey_bio(bp_private, rsa);

        RSA_free(rsa);
        BIO_free_all(bp_private);

        return ret;
    }
    return false;
}

///----- CRSAPublicKey ---------------------------------------------------------
//! Save public key to file. Currenty, PEM and DER format are supported
bool CRSAPublicKey::SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
{
    std::string strContent;
    if (fileFormat == crypto::PEM_)
    {
        WriteFile(fileName + ".pem", this->GetPemString());

    }
    else if (fileFormat == crypto::DER_)
    {
        WriteFile(fileName + ".der", this->GetDerString());

        return true;
    }
    return false;
}

bool CRSAPublicKey::Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &sign) const
{
    return CRSA::Encrypt(m_Data.n, m_Data.e, msg, sign);
}

bool CRSAPublicKey::Decrypt(const std::vector<unsigned char> &cipher, std::vector<unsigned char> &text) const
{
    return CRSA::Decrypt(m_Data.n, m_Data.e, cipher, text);
}

bool CRSAPublicKey::Verify(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &sign) const
{

    if (sign.size() == 0)
        return false;

    std::vector<unsigned char> expected_msg;
    this->Decrypt(sign, expected_msg);

    if (msg.size() != expected_msg.size())
        return false;

    for (uint32_t i=0; i< expected_msg.size(); i++)
        if (msg[i] != expected_msg[i])
            return false;

    return true;

}

bool CRSAPublicKey::Verify(const std::string &msg, const std::string &sign) const
{
    return Verify(std::vector<unsigned char>(msg.begin(), msg.end()), std::vector<unsigned char>(sign.begin(), sign.end()));
}


bool CRSAPublicKey::OpenSSL_SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
{
    BIO *bp_public = NULL;
    int ret;
    if (fileFormat == crypto::PEM_)
    {
        // -- using openssl library to write to file
        bp_public = BIO_new_file((fileName + ".pem").c_str(), "w+");
        RSA* rsa = ::RSAFromDer(this->GetDerString(), crypto::PUBLIC_MODE);
        ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);

        RSA_free(rsa);
        BIO_free_all(bp_public);
        return ret;
    }
    else if (fileFormat == crypto::DER_)
    {
        // -- using openssl library to write to file
        bp_public = BIO_new_file((fileName + ".der").c_str(), "w+");
        RSA* rsa = ::RSAFromDer(this->GetDerString(), crypto::PUBLIC_MODE);
        ret = i2d_RSAPublicKey_bio(bp_public, rsa);

        RSA_free(rsa);
        BIO_free_all(bp_public);

        return ret;
    }
    return false;
}
bool CRSAPublicKey::OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const
{
    clock_t tStart = clock();

    RSAEncrypt(this->GetDerString(), msg, cipher_text, crypto::PUBLIC_MODE);

    printf("Time taken OpenSSL_Encrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}
bool CRSAPublicKey::OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &output) const
{
    clock_t tStart = clock();

    bool ret = RSADecrypt(this->GetDerString(), cipher_text, output, crypto::PUBLIC_MODE);

    printf("Time taken OpenSSL_Decrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return ret;
}

bool CRSAPublicKey::OpenSSL_Verify(const std::vector<unsigned char> &msg, const std::vector<unsigned char> &sign) const
{
    if (sign.size() == 0)
        return false;

    std::vector<unsigned char> expected_msg;
    this->OpenSSL_Decrypt(sign, expected_msg);

    if (msg.size() != expected_msg.size())
        return false;

    for (uint32_t i=0; i< expected_msg.size(); i++)
        if (msg[i] != expected_msg[i])
            return false;

    return true;

}

bool CRSAPublicKey::OpenSSL_Verify(const std::string &msg, const std::string &sign) const
{
    return OpenSSL_Verify(std::vector<unsigned char>(msg.begin(), msg.end()), std::vector<unsigned char>(sign.begin(), sign.end()));
}
