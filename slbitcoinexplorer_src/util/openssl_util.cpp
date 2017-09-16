#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <fstream>

#include <openssl/crypto.h>

#include "util/encoding_util.h"
#include "util/openssl_util.h"
#include "crypto/key.h"

void RSA_printLastError(char *msg)
{
    char * err = (char*)malloc(130);;
    ERR_load_crypto_strings();
    ERR_error_string(ERR_get_error(), err);
    printf("%s ERROR: %s\n",msg, err);
    free(err);
}


RSA* RSAFromDer(std::string der, std::string keyType)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(der.c_str(), der.size());
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(keyType == crypto::PUBLIC_MODE)
    {
        rsa = d2i_RSAPublicKey_bio(keybio, NULL);

    }
    else
    {
        rsa = d2i_RSAPrivateKey_bio(keybio, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    BIO_free_all(keybio);

    return rsa;
}

RSA* RSAFromPem(std::string pem, std::string keyType)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(pem.c_str(), -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(keyType == crypto::PUBLIC_MODE)
    {
        rsa = ::PEM_read_bio_RSAPublicKey(keybio, NULL,NULL, NULL);

    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL,NULL, NULL);
    }
    if(rsa == NULL)
    {
        printf( "Failed to create RSA");
    }

    BIO_free_all(keybio);

    return rsa;
}

std::string RSAToPem(RSA* rsa, std::string keyType)
{
    int keylen;
    char *pem_key;

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());

    if(keyType == crypto::PUBLIC_MODE)
        PEM_write_bio_RSAPublicKey(bio, rsa);
    if(keyType == crypto::PRIVATE_MODE)
        PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);

    keylen = BIO_pending(bio);
    pem_key = (char*)calloc(keylen+1, 1); /* Null-terminate */
    BIO_read(bio, pem_key, keylen);

    //printf("%s", pem_key);

    std::string result(pem_key);

    BIO_free_all(bio);
    free(pem_key);

    return result;
}

std::string RSAToDer(RSA* rsa, std::string keyType)
{
    int keylen;
    char *der_key;
    bool rc;

    /* To get the C-string PEM form: */
    BIO *bio = BIO_new(BIO_s_mem());

    if(keyType == crypto::PUBLIC_MODE)
    {
        rc = i2d_RSAPublicKey_bio(bio, rsa);
        assert(rc == 1);
    }
    if(keyType == crypto::PRIVATE_MODE)
    {
        rc = i2d_RSAPrivateKey_bio(bio, rsa);
        assert(rc == 1);
    }
    keylen = BIO_pending(bio);
    der_key = (char*)calloc(keylen, 1);
    BIO_read(bio, der_key, keylen);

    std::string result(der_key, keylen);

    BIO_free_all(bio);
    free(der_key);

    return result;
}

bool RSAEncrypt(const std::string &der, const std::vector<unsigned char> &input, std::vector<unsigned char> &output, std::string keyType)
{

     RSA* rsa = RSAFromDer(der, keyType);

    int keySize = RSA_size(rsa);

    unsigned char to[keySize+1];

    int outSize = 0;

    if (keyType == crypto::PRIVATE_MODE)
    {
        outSize = RSA_private_encrypt(input.size(), reinterpret_cast<const unsigned char*>(input.data()), to, rsa, RSA_PKCS1_PADDING);
        //RSA_private_encrypt(keySize, &input[0], to, rsa, 0);
    }
    else if (keyType == crypto::PUBLIC_MODE)
    {
        outSize = RSA_public_encrypt(input.size(), reinterpret_cast<const unsigned char*>(input.data()), to, rsa, RSA_PKCS1_PADDING );

    }

    if (outSize == -1)
    {
        RSA_printLastError((char*)"RSA Encryption error: ");
        return false;
    }


    output = std::vector<unsigned char>(to, to+outSize);

    return true;
}

bool RSADecrypt(const std::string &der, const std::vector<unsigned char> &input, std::vector<unsigned char> &output, std::string keyType)
{

    RSA* rsa = RSAFromDer(der, keyType);

   int keySize = RSA_size(rsa);

   unsigned char to[keySize+1];

   int outSize = 0;

   if (keyType == crypto::PRIVATE_MODE)
   {
       outSize = RSA_private_decrypt(input.size(), reinterpret_cast<const unsigned char*>(input.data()), to, rsa, RSA_PKCS1_PADDING);
       //RSA_private_encrypt(keySize, &input[0], to, rsa, 0);
   }
   else if (keyType == crypto::PUBLIC_MODE)
   {
       outSize = RSA_public_decrypt(input.size(), reinterpret_cast<const unsigned char*>(input.data()), to, rsa, RSA_PKCS1_PADDING);

   }

   if (outSize == -1)
   {
       RSA_printLastError((char*)"Can't decrypt the cipher. Possible reason is the cipher is wrong or key is not match. ");
       return false;
   }


   output = std::vector<unsigned char>(to, to+outSize);

   return true;
}

bool RSAPaddingPKCS1(std::vector<unsigned char> &msg, int keySize)
{
    unsigned char to[keySize];
    RSA_padding_add_PKCS1_type_1(to, keySize,reinterpret_cast<const unsigned char*>(msg.data()), msg.size());

    msg = std::vector<unsigned char>(to, to+keySize);
    return true;

}


//------------------ Common functions ---------------------------
void WriteHeader(std::stringstream &ssHeader, int nValueSize)
{

    char ch, ch1,  ch2;
    //1. Write sequence code
    ssHeader.put(0x30);

    if (nValueSize < 127)
    {
        ch = (unsigned char)nValueSize;
        ssHeader.put(ch);
    }
    else
    {
        //maximum 2 bytes to store number of byte of this sequence
        if (nValueSize <= 255)
        {
            ch = 0x81;
            ch1 = (unsigned char)(nValueSize & 0xFF);
            //ssHeader << ch << ch1;
            ssHeader.put(ch).put(ch1);
        }
        else
        {
            ch = 0x82;
            ch1 = (unsigned char)((nValueSize >> 8) & 0xFF);
            ch2 = (unsigned char)(nValueSize & 0xFF);
            ssHeader.put(ch).put(ch1).put(ch2);
        }
    }

}

//! Write a serie of numbers in DER format
//! If you want to study about DER format, these may be useful
//! - X.690 is an ITU-T standard specifying ASN.1 encoding formats
//! - Specification: ITU-T X.690, ISO/IEC 8825-1
void WriteNumberInDerFormat(std::stringstream &ss, const CBigNumber &n, bool trimZero)
{
    int nValueSize = 0;
    unsigned char ch, ch1, ch2;

    // - identifier: integer
    ss.put(0x02);

    // - length
    std::vector<unsigned char> nValue = n.GetBin(trimZero);

    //if the number is negative, insert 00 at beginning
    if (nValue[0] > (unsigned char)0x7F)
        nValue.insert(nValue.begin(), 0);

    nValueSize = nValue.size();

    if (nValueSize < 127)
    {
        ch = (unsigned char)nValueSize;
        ss.put(ch);
    }
    else
    {
        //maximum 2 bytes to store number of byte of this sequence
        if (nValueSize <= 255)
        {
            ch = 0x81;
            ch1 = (unsigned char)(nValueSize & 0xFF);
            ss.put(ch).put(ch1);
        }
        else
        {
            ch = 0x82;
            ch1 = (unsigned char)((nValueSize >> 8) & 0xFF);
            ch2 = (unsigned char)(nValueSize & 0xFF);
            ss.put(ch).put(ch1).put(ch2);
        }
    }
    // - write value
    for (std::vector<unsigned char>::const_iterator i = nValue.begin(); i != nValue.end(); ++i)
        ss << *i;

}

void WritePemFile(const std::string &fileName, const std::stringstream &ssHeader, const std::stringstream &ssContent, const std::string &strKeyType, std::string algorithm)
{
    std::string base64Content = ::EncodeBase64(ssHeader.str() + ssContent.str());

    std::ofstream pemFile(fileName + ".pem");


    pemFile << "-----BEGIN " << algorithm.c_str() << " " << strKeyType << " KEY-----\n";

    size_t writeSize = 0;
    size_t chunk = 64;
    while (writeSize < base64Content.size())
    {
        if (writeSize + chunk > base64Content.size())
            chunk = base64Content.size() - writeSize;

        pemFile.write(base64Content.c_str() + writeSize, chunk);

        if (writeSize + chunk < base64Content.size())
            pemFile << std::endl;

        writeSize += chunk;
    }
    pemFile << "\n-----END " << algorithm.c_str() << " " << strKeyType << " KEY-----\n";

    pemFile.close();

}

void memory_cleanse(void *ptr, size_t len)
{
    OPENSSL_cleanse(ptr, len);
}
