#include <vector>
#include <string>
#include <stdexcept>

#include "crypto/cipher.h"
#include "crypto/key.h"
#include "util/common_util.h"
#include "util/openssl_util.h"

//----- CCipher ---------------------------------------------------------
CCipher* CCipher::GetInstance(std::string transformation)
{
    std::vector<std::string> arrParam = Split(transformation, '/');

    if (arrParam.size() <=0)
        return 0;

    if (arrParam[0] == crypto::RSA_)
        return new CRSACipher();
    else
        return 0;
}

//----- CRSACipher ---------------------------------------------------------

bool CRSACipher::Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const
{

    clock_t tStart = clock();

    std::vector<unsigned char> padded_msg(msg);

    //Using PKCS1_padding type1
    RSAPaddingPKCS1(padded_msg, m_keyBit/8);

    if (m_keyBit == 0)
    {
        std::invalid_argument("Cipher has not been initalized.");
        return false;
    }
    //can only encrypt a text with less or equal to key_size;
    if (padded_msg.size() > m_keyBit/8)
    {
        std::cout << "Message too long to encrypt." << "[RSA] msgsize > keysize (" << padded_msg.size() << " > " << m_keyBit/8 << ")" << std::endl;
        //std::cout << "Trimmed!" << std::endl;
        return false;
    }
    const CBigNumber* modulus;
    const CBigNumber* exponent;

    if (m_mode == crypto::PRIVATE_MODE)
    {
        modulus = &m_pPrivateKey->n;
        exponent = &m_pPrivateKey->d;
    }
    else if (m_mode == crypto::PUBLIC_MODE)
    {
        modulus = &m_pPublicKey->n;
        exponent = &m_pPublicKey->e;
    }
    else
        return false;

    CBigNumber cihper(m_keyBit);

    cihper.SetBin(padded_msg);
    cihper.ExpMod(*exponent, *modulus);
    cipher_text = cihper.GetBin(true);

    printf("Time taken Encrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}

bool CRSACipher::Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const
{
    clock_t tStart = clock();

    if (m_keyBit == 0)
    {
        std::invalid_argument("Cipher has not been initalized.");
        return false;
    }
    //can only encrypt a text with less or equal to key_size;
    if (cipher_text.size() != m_keyBit/8)
    {
        std::cout << "Cipher text length is invalid." << "[RSA] ciphersize != keysize (" << cipher_text.size() << " > " << m_keyBit/8 << ")" << std::endl;
        return false;
    }
    const CBigNumber* modulus;
    const CBigNumber* exponent;

    if (m_mode == crypto::PRIVATE_MODE)
    {
        modulus = &m_pPrivateKey->n;
        exponent = &m_pPrivateKey->d;
    }
    else if (m_mode == crypto::PUBLIC_MODE)
    {
        modulus = &m_pPublicKey->n;
        exponent = &m_pPublicKey->e;
    }
    else
        return false;

    CBigNumber cihper(m_keyBit);

    cihper.SetBin(cipher_text);
    cihper.ExpMod(*exponent, *modulus);
    std::vector<unsigned char> strDecoded = cihper.GetBin(true);
    msg = cihper.GetBin(true);

    // Remove padding PKCS1 type 1
    uint32_t i=1;
    while (msg[i] != 0 && i < msg.size()) i++;

    if (i < strDecoded.size())
        msg.erase(msg.begin(), msg.begin()+i+1);

    printf("Time taken Decrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}
bool CRSACipher::Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature) const
{
    return false;
}

bool CRSACipher::OpenSSL_Encrypt(const std::vector<unsigned char> &msg, std::vector<unsigned char> &cipher_text) const
{
    clock_t tStart = clock();

    if (m_mode == crypto::PRIVATE_MODE)
        cipher_text = RSAEncrypt(this->m_pPrivateKey->m_pem, msg, m_mode);
    else if (m_mode == crypto::PUBLIC_MODE)
        cipher_text = RSAEncrypt(this->m_pPublicKey->m_pem, msg, m_mode);

    printf("Time taken OpenSSL_Encrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}
bool CRSACipher::OpenSSL_Decrypt(const std::vector<unsigned char> &cipher_text, std::vector<unsigned char> &msg) const
{
    clock_t tStart = clock();

    if (m_mode == crypto::PRIVATE_MODE)
        msg = RSADecrypt(this->m_pPrivateKey->m_pem, cipher_text, m_mode);
    else if (m_mode == crypto::PUBLIC_MODE)
        msg = RSADecrypt(this->m_pPublicKey->m_pem, cipher_text, m_mode);

    printf("Time taken OpenSSL_Decrypt: %.2fs\n", (double)(clock() - tStart)/CLOCKS_PER_SEC);

    return true;
}
bool CRSACipher::OpenSSL_Sign(const std::vector<unsigned char> &msg, std::vector<unsigned char> &signature) const
{
    return false;
}

