#ifndef CECDSA_H
#define CECDSA_H

#include "crypto/key.h"
#include "crypto/big_number.h"
#include "util/pagelocker.h"
#include "util/exception.h"
#include "secp256k1.h"

///----- CECDSA ---------------------------------------------------------------
//! For now, only curve secp256k1 is implemented

#define secp256k1_Gx "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
#define secp256k1_Gy "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"
#define secp256k1_n  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
#define  SECP256K1   "secp256k1"

class CECDSAPrivateKey;
class CECDSAPublicKey;
class CECDSA;

struct SECDSAParam
{
public:
    static CBigNumber Gx, Gy;
    static uint32_t a, b, h;
    static CBigNumber n;

    static std::string curve;
    static uint32_t bitSize;
};

struct SECDSAPrivateData
{
    CBigNumber n;
    SECDSAPrivateData(uint32_t bitSize): n(bitSize) {}
    SECDSAPrivateData(const CBigNumber &a): n(a) {}
    SECDSAPrivateData(unsigned char* vch, uint32_t len): n(vch, 256)
    {
        assert (len == 32);
    }
};
struct SECDSAPublicData
{
    CBigNumber x, y;
    SECDSAPublicData(uint32_t bitSize): x(bitSize), y(bitSize) {}
    SECDSAPublicData(const CBigNumber &a, const CBigNumber &b): x(a), y(b) {}
    SECDSAPublicData(const SECDSAPublicData &data): x(data.x), y(data.y) {}
    SECDSAPublicData(const CBigNumber &a);
    SECDSAPublicData(unsigned char* vch, uint32_t len): x(vch+1, 32), y(vch+33, 32)
    {
        assert (len == 65);
    }
};

///----- CECDSA --------------------------------------------------------
//! Contain all static function to process ECDSA
class CECDSA
{
    friend class CECDSAPrivateKey;
    friend class CECDSAPublicKey;

public:

    //! Generate a new private key using a cryptographic PRNG.
    static CECDSAPrivateKey GenerateNewKey(uint32_t keyBit, bool fCompressedIn);

    static CECDSAPrivateKey LoadPrivateKeyFromFile(std::string fileName, std::string fileFormat, std::string password="") ;
    static CECDSAPrivateKey LoadPrivateKeyFromStream(std::ifstream f, std::string fileFormat, std::string password="");
    static CECDSAPrivateKey LoadPrivateKeyFromString(std::string strKey, std::string fileFormat, std::string password="");
    static CECDSAPrivateKey LoadPrivateKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password="");
    static CECDSAPrivateKey LoadPrivateKeyFromHexString(std::string strKey, std::string fileFormat, std::string password="");

    static CECDSAPublicKey LoadPublicKeyFromFile(std::string fileName, std::string fileFormat, std::string password="") ;
    static CECDSAPublicKey LoadPublicKeyFromStream(std::ifstream f, std::string fileFormat, std::string password="");
    static CECDSAPublicKey LoadPublicKeyFromString(std::string strKey, std::string fileFormat, std::string password="");
    static CECDSAPublicKey LoadPublicKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password="");
    static CECDSAPublicKey LoadPublicKeyFromHexString(std::string strKey, std::string fileFormat, std::string password="");

    static CBigNumber GetY(const CBigNumber &a);

    //! Check whether the 32-byte array pointed to be vch is valid keydata.
    static bool Check(const unsigned char* vch);

    /** Initialize the elliptic curve support. May not be called twice without calling ECC_Stop first. */
    static void ECC_Start(void);

    /** Deinitialize the elliptic curve support. No-op if ECC_Start wasn't called first. */
    static void ECC_Stop(void);

    /** Check that required EC support is available at runtime. */
    static bool ECC_InitSanityCheck(void);

private:
    static const uint32_t PEM_CHAR_PER_LINE = 64;
    static int ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen);
    static int ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed);
    static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen);

    //! Should move these function to somewhere private??
    static void WritePrivateDataInDerFormat(std::stringstream &ss, const SECDSAPrivateData data, bool trimZero=true);
    static void WritePublicDataInDerFormat(std::stringstream &ss, const SECDSAPublicData data, bool trimZero=true);

    static bool GetPrivateDer(const SECDSAPrivateData &data, std::string &der);
    static bool GetPublicDer(const SECDSAPublicData data, std::string &der);

    static bool Der2Pem(const std::string &der, std::string &pem, const std::string &keyType, const uint32_t charPerLine=PEM_CHAR_PER_LINE);

    static bool GetPrivatePem(const SECDSAPrivateData &data, std::string &pem, uint32_t charPerLine=PEM_CHAR_PER_LINE);
    static bool GetPublicPem(const SECDSAPublicData data, std::string &pem,  uint32_t charPerLine=PEM_CHAR_PER_LINE);


};



///----- CECDSAPrivateKey --------------------------------------------------------
class CECDSAPrivateKey final: public CPrivateKey
{

    friend class CECDSA;
    friend class CECDSAPublicKey;

private:
    SECDSAPrivateData m_Data;

    //! This value must be identical with m_Data all the times
    //! The reason of this redundancy is for compatible with the library using
    unsigned char vch[32];

    //! Key have not been initalize
    bool m_isValid = false;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    //! When it's compress, on ly x value is stored. y value will be calculated dymamically.
    //! For our libray, it's only support the un-compressed form. So, this variable is for
    //!   library-compatible purpose only.
    bool fCompressed = false;



public:

    /// Constructor functions --------------------

    //! Default constructor, the key is invalid
    CECDSAPrivateKey(): CKey(256, crypto::ECDSA), m_Data(256)
    {
        fCompressed = false;
        m_isValid = false;
    }

    //! Construct a new Private key based on another key
    CECDSAPrivateKey(const CECDSAPrivateKey &key): CKey(key.bitsize(), key.algorithm()), m_Data(key.bitsize())
    {
        m_Data = key.m_Data;
        m_isValid = key.m_isValid;
        for (int i=0; i<32; i++)
            vch[i] = key.vch[i];
    }

    //! Construct a new private key based on data.
    //! The fCompressedIn should always be set to false.
    CECDSAPrivateKey(const SECDSAPrivateData &data, unsigned char* vchar, bool fCompressedIn=false): CKey(data.n.bitsize(), crypto::ECDSA), m_Data(data.n.bitsize())
    {
        m_Data = data;
        this->fCompressed = fCompressedIn;

        for (int i=0; i<32; i++)
            vch[i] = vchar[i];

        //! For now, just simply verify if the key's len > 0 then it's valid.
        if (data.n.bitsize() > 0 && data.n.bitsize()%8 == 0)
            m_isValid = true;
    }

    //! Construct a new private key based on data.
    //! The fCompressedIn should always be set to false.
    CECDSAPrivateKey(unsigned char* vchar, bool fCompressedIn=false): CKey(256, crypto::ECDSA), m_Data(256)
    {
        this->fCompressed = fCompressedIn;

        for (int i=0; i<32; i++)
            vch[i] = vchar[i];

        SyncData();

        m_isValid = true;
    }

    //! Convert the library format to our format.
    //! Only after the convention, the key is valid to use.
    bool SyncData()
    {
        m_Data.n.SetBin(vch, 32);
        m_isValid = true;
        return true;
    }


    /// Access information functions --------------------

    //! When using the default constructor, the key is first invalid.
    //! After the key is constructed, it always be valid.
    bool IsValid() const {return m_isValid;}

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    //! For our code, should always set this value to false;
    bool IsCompressed() const { return fCompressed; }

    /// This format does not compatible with bitcoin.
    /// Be carefull when using this.
    std::string GetPemString(bool breakLine=true) const {
        std::string strPem;
        if (breakLine)
            CECDSA::GetPrivatePem(m_Data, strPem);
        else
            CECDSA::GetPrivatePem(m_Data, strPem, 0);

        return strPem;
    }

    /// For bitcoin, this is the only format supported.
    /// The DER string here is already convert to Hexa number, not binary.
    std::string GetDerString() const
    {
        std::string strDer;
        CECDSA::GetPrivateDer(m_Data, strDer);
        return strDer;
    }
    std::string Serialize() const
    {
        if (m_isValid)
        {
            return std::string(vch, vch+32);
        }
        else
            return "";
    }
    SECDSAPrivateData GetData() const {return m_Data;}

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (m_isValid ? 32 : 0); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }


    /// Operation functions --------------------

    //! Save private key in PEM or DER format
    bool SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;

    //! Calculate the public key from private key
    //! When the private key is generated, public key is not yet calculated.
    //! This function is expensive. So, when you got the key, keep it for reusing
    //! - cCompress = '0': default using the fCompressed from PrivateKey
    //! - cCompress = 'C': return the compressed PublicKey. Update fCompressed of PrivateKey = true
    //! - cCompress = 'U': return the un-compressed PublicKey. Update fCompressed of PrivateKey = false
    CECDSAPublicKey GetPublicKey(char cCompress = '0') ;

    CECDSAPrivateKey& operator=(const CECDSAPrivateKey &key)
    {
        m_KeySize = key.m_KeySize;
        m_Algorithm = key.m_Algorithm;
        m_Data = key.m_Data;
        m_isValid = key.m_isValid;

        for (int i=0; i<32; i++)
            vch[i] = key.vch[i];


        return *this;
    }

    bool operator==(const CECDSAPrivateKey &key)
    {
        if (    this->m_Algorithm == key.m_Algorithm
                && this->m_KeySize == key.m_KeySize
                && this->m_isValid == key.m_isValid
                && this->fCompressed == key.fCompressed
                && this->Serialize() == key.Serialize()

           )
            return true;

        return false;
    }

    //! Sign a hash based on this private key.
    //! The hash size must be fixed 256 bits.
    //! Before calling this function, make sure to call SHA256 to hash the message first.
    //! The entropy param is optional. For now, always use default value = 0
    bool Sign(const std::vector<unsigned char> &vHash, std::vector<unsigned char> &vSign, uint32_t entropy) const;
    bool Sign(const std::string &hash, std::string &sign, uint32_t entropy) const;

    /**
     * Create a DER-serialized signature.
     * The test_case parameter tweaks the deterministic nonce.
     */
    bool Sign(const std::string& hash, std::vector<unsigned char>& vchSig, uint32_t entropy = 0) const;

    /**
     * Create a compact signature (65 bytes), which allows reconstructing the used public key.
     * The format is one header byte, followed by two times 32 bytes for the serialized r and s values.
     * The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
     *                  0x1D = second key with even y, 0x1E = second key with odd y,
     *                  add 0x04 for compressed keys.
     */
    bool SignCompact(const std::string& hash, std::vector<unsigned char>& vchSig) const;
    /**
     * Verify thoroughly whether a private key and a public key match.
     * This is done using a different mechanism than just regenerating it.
     */

    //! Implement the function from abstract class CPrivateKey
    bool Sign(const std::string &hash, std::string &sign) const;
    bool Sign(const std::vector<unsigned char> &vHash, std::vector<unsigned char> &vSign) const;


    bool VerifyPubKey(const CECDSAPublicKey& vchPubKey) const;
};


///----- CECDSAPublicKey ---------------------------------------------------------
class CECDSAPublicKey final: public CPublicKey
{
    friend class CECDSA;
    friend class CECDSAPrivateKey;

private:
    SECDSAPublicData m_Data;

    //! This value must be identical with m_Data all the times
    //! The reason of this redundancy is for compatible with the library using
    unsigned char vch[65];

    //!Key have not been initalize
    bool m_isValid = false;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    //! When it's compress, on ly x value is stored. y value will be calculated dymamically.
    //! For our libray, it's only support the un-compressed form. So, this variable is for
    //!   library-compatible purpose only.
    bool fCompressed = false;

public:

    /// Constructors ---------------------
    //! Default constructor, the key is invalid
    CECDSAPublicKey(): CKey(256, crypto::ECDSA), m_Data(256)
    {
        fCompressed = false;
        m_isValid = false;
    }
    CECDSAPublicKey(const CECDSAPublicKey &key): CKey(key.bitsize(), key.algorithm()), m_Data(key.bitsize())
    {
        m_Data = key.m_Data;
        m_isValid = key.m_isValid;
        fCompressed = key.fCompressed;

        for (int i=0; i<65; i++)
            vch[i] = key.vch[i];

    }

    CECDSAPublicKey(const SECDSAPublicData &data, unsigned char* vchar): CKey(data.x.bitsize(), crypto::ECDSA), m_Data(data.x.bitsize())
    {
        m_Data = data;

        for (int i=0; i<65; i++)
            vch[i] = vchar[i];

        //! For now, just simply verify if the key's len > 0 then it's valid.
        if (data.x.bitsize() > 0 && data.x.bitsize()%8 == 0)
            m_isValid = true;
    }

    //! The bitsize is hard-coded to 256 because the library is now only support 256 bit only.
    CECDSAPublicKey(unsigned char* vchar, uint32_t len): CKey(256, crypto::ECDSA), m_Data(vch, len)
    {
        //! Since we only support un-compressed form, the len much always be 65.
        assert (len == 65 || len ==33);

        memcpy(vch, vchar, len);

        this->SyncData();

        //! For now, just simply verify if the key's len > 0 then it's valid.
        if (m_Data.x.bitsize() > 0 && m_Data.x.bitsize()%8 == 0)
            m_isValid = true;
    }
    //! Convert the library format to our format.
    //! Only after the convention, the key is valid to use.
    //! That's why this function is grouped in constructor group
    bool SyncData()
    {
        m_Data.x.SetBin(vch+1, 32);
        if (!fCompressed)
            m_Data.y.SetBin(vch+33, 32);
        m_isValid = true;
        return true;
    }


    /// Get information functions ---------------------
    bool IsValid() const {return m_isValid;}

    std::string GetPemString(bool breakLine=true) const
    {
        std::string strPem;
        if (breakLine)
            CECDSA::GetPublicPem(m_Data, strPem);
        else
            CECDSA::GetPublicPem(m_Data, strPem, 0);
        return strPem;
    }
    std::string GetDerString() const
    {
        std::string strDer;
        CECDSA::GetPublicDer(m_Data, strDer);
        return strDer;
    }

    std::string Serialize() const
    {
        if (m_isValid)
        {
            if (fCompressed)
                return std::string(vch, vch+33);
            else
                return std::string(vch, vch+65);
        }
        else
            return "";
    }

    SECDSAPublicData GetData() const {return m_Data;}

    //! Check whether the public key corresponding to this private key is (to be) compressed.
    //! For our code, should always set this value to false;
    bool IsCompressed() const { return fCompressed; }

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (m_isValid ? 65 : 0); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }


    /// Operation functions ---------------------

    bool SaveToFile(std::string fileName, std::string fileFormat, std::string password="") const;

    CECDSAPublicKey& operator=(const CECDSAPublicKey &key)
    {
        m_KeySize = key.m_KeySize;
        m_Algorithm = key.m_Algorithm;
        m_Data = key.m_Data;
        m_isValid = key.m_isValid;

        for (int i=0; i<65; i++)
            vch[i] = key.vch[i];

        return *this;
    }

    bool operator==(const CECDSAPublicKey &key)
    {
        if (    this->m_Algorithm == key.m_Algorithm
                && this->m_KeySize == key.m_KeySize
                && this->m_isValid == key.m_isValid
                && this->fCompressed == key.fCompressed
                && this->Serialize() == key.Serialize()

           )
            return true;

        return false;
    }

    bool Verify(const std::string &hash, const std::vector<unsigned char> &vchSig) const;
    bool Verify(const std::string &hash, const std::string &sign) const;
    bool Verify(const std::vector<unsigned char> &vHash, const std::vector<unsigned char> &vSign) const;

};

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};


#endif // CECDSA_H
