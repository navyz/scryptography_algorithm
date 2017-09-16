#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iostream>
#include <stdio.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "util/encoding_util.h"
#include "util/openssl_util.h"
#include "util/encoding_util.h"
#include "util/random.h"
#include "util/exception.h"
#include "util/random.h"
#include "util/common_util.h"
#include "crypto/common.h"
#include "crypto/key.h"
#include "crypto/ecdsa.h"
#include "crypto/bitcoin/hash.h"


static secp256k1_context* secp256k1_context_sign = NULL;
static secp256k1_context* secp256k1_context_verify = NULL;

uint32_t SECDSAParam::a = 0;
uint32_t SECDSAParam::b = 7;
uint32_t SECDSAParam::h = 1;
CBigNumber SECDSAParam::Gx(secp256k1_Gx, 256, true);
CBigNumber SECDSAParam::Gy(secp256k1_Gy, 256, true);
CBigNumber SECDSAParam::n(secp256k1_n, 256, true);
std::string SECDSAParam::curve = SECP256K1;
uint32_t SECDSAParam::bitSize = 256;

///----- SECDSAPublicData --------------------------------------------------------

//! This function is move here, alone... Because it's refering to CECDSA.
//! Well, kind of nested loop
SECDSAPublicData::SECDSAPublicData(const CBigNumber &a): x(a), y(CECDSA::GetY(a)) {}


///----- CECDSA --------------------------------------------------------
/** These functions are taken from the libsecp256k1 distribution and are very ugly. */
int CECDSA::ec_privkey_import_der(const secp256k1_context* ctx, unsigned char *out32, const unsigned char *privkey, size_t privkeylen) {
    const unsigned char *end = privkey + privkeylen;
    int lenb = 0;
    int len = 0;
    memset(out32, 0, 32);
    /* sequence header */
    if (end < privkey+1 || *privkey != 0x30) {
        return 0;
    }
    privkey++;
    /* sequence length constructor */
    if (end < privkey+1 || !(*privkey & 0x80)) {
        return 0;
    }
    lenb = *privkey & ~0x80; privkey++;
    if (lenb < 1 || lenb > 2) {
        return 0;
    }
    if (end < privkey+lenb) {
        return 0;
    }
    /* sequence length */
    len = privkey[lenb-1] | (lenb > 1 ? privkey[lenb-2] << 8 : 0);
    privkey += lenb;
    if (end < privkey+len) {
        return 0;
    }
    /* sequence element 0: version number (=1) */
    if (end < privkey+3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01) {
        return 0;
    }
    privkey += 3;
    /* sequence element 1: octet string, up to 32 bytes */
    if (end < privkey+2 || privkey[0] != 0x04 || privkey[1] > 0x20 || end < privkey+2+privkey[1]) {
        return 0;
    }
    memcpy(out32 + 32 - privkey[1], privkey + 2, privkey[1]);
    if (!secp256k1_ec_seckey_verify(ctx, out32)) {
        memset(out32, 0, 32);
        return 0;
    }
    return 1;
}

int CECDSA::ec_privkey_export_der(const secp256k1_context *ctx, unsigned char *privkey, size_t *privkeylen, const unsigned char *key32, int compressed) {
    secp256k1_pubkey pubkey;
    size_t pubkeylen = 0;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, key32)) {
        *privkeylen = 0;
        return 0;
    }
    if (compressed) {
        static const unsigned char begin[] = {
            0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 33;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    } else {
        static const unsigned char begin[] = {
            0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20
        };
        static const unsigned char middle[] = {
            0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
        };
        unsigned char *ptr = privkey;
        memcpy(ptr, begin, sizeof(begin)); ptr += sizeof(begin);
        memcpy(ptr, key32, 32); ptr += 32;
        memcpy(ptr, middle, sizeof(middle)); ptr += sizeof(middle);
        pubkeylen = 65;
        secp256k1_ec_pubkey_serialize(ctx, ptr, &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
        ptr += pubkeylen;
        *privkeylen = ptr - privkey;
    }
    return 1;
}

/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
int CECDSA::ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;
    pos += slen;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}


//! Generate a new private key using a cryptographic PRNG.
CECDSAPrivateKey CECDSA::GenerateNewKey(uint32_t keyBit, bool fCompressedIn)
{
    CECDSAPrivateKey privateKey;
        do {
         GetStrongRandBytes(privateKey.vch, sizeof(privateKey.vch));
     } while (!Check(privateKey.vch));

     privateKey.SyncData();
    privateKey.fCompressed = fCompressedIn;
     return privateKey;
}

CECDSAPrivateKey CECDSA::LoadPrivateKeyFromFile(std::string fileName, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPrivateKey CECDSA::LoadPrivateKeyFromStream(std::ifstream f, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPrivateKey CECDSA::LoadPrivateKeyFromString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPrivateKey CECDSA::LoadPrivateKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPrivateKey CECDSA::LoadPrivateKeyFromHexString(std::string strKey, std::string fileFormat, std::string password)

{
    throw not_implemented_exception();
}
CECDSAPublicKey  CECDSA::LoadPublicKeyFromFile(std::string fileName, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPublicKey  CECDSA::LoadPublicKeyFromStream(std::ifstream f, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPublicKey  CECDSA::LoadPublicKeyFromString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPublicKey  CECDSA::LoadPublicKeyFromVector(std::vector<unsigned char> vkey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}
CECDSAPublicKey  CECDSA::LoadPublicKeyFromHexString(std::string strKey, std::string fileFormat, std::string password)
{
    throw not_implemented_exception();
}

CBigNumber CECDSA::GetY(const CBigNumber &a)
{
    throw not_implemented_exception();
}

bool CECDSA::Check(const unsigned char *vch) {
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}

void CECDSA::WritePrivateDataInDerFormat(std::stringstream &ss, const SECDSAPrivateData data, bool trimZero)
{
    WriteNumberInDerFormat(ss, data.n, trimZero);
}

void CECDSA::WritePublicDataInDerFormat(std::stringstream &ss, const SECDSAPublicData data, bool trimZero)
{
    WriteNumberInDerFormat(ss, data.x, trimZero);
    WriteNumberInDerFormat(ss, data.y, trimZero);
}

bool CECDSA::GetPrivateDer(const SECDSAPrivateData &data, std::string &der)
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
bool CECDSA::GetPublicDer(const SECDSAPublicData data, std::string &der)
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

bool CECDSA::Der2Pem(const std::string &der, std::string &pem, const std::string &keyType, const uint32_t charPerLine)
{
    std::stringstream ss;

    ss << "-----BEGIN EC " << keyType << " KEY-----\n";
    if (charPerLine == 0)
        ss << ::EncodeBase64(der);
    else
    {
        ss << BreakLine(::EncodeBase64(der), charPerLine);
    }
    ss << "\n-----END EC " << keyType << " KEY-----\n";
    pem = ss.str();
    return true;
}

bool CECDSA::GetPrivatePem(const SECDSAPrivateData &data, std::string &pem, uint32_t charPerLine)
{
    std::string der;
    if (GetPrivateDer(data, der))
    {
        CECDSA::Der2Pem(der, pem, crypto::PRIVATE_MODE, charPerLine);
        return true;
    }
    else
        return false;
}

bool CECDSA::GetPublicPem(const SECDSAPublicData data, std::string &pem,  uint32_t charPerLine)
{
    std::string der;
    if (GetPublicDer(data, der))
    {
        CECDSA::Der2Pem(der, pem, crypto::PUBLIC_MODE, charPerLine);
        return true;
    }
    else
        return false;
}


bool CECDSA::ECC_InitSanityCheck() {
    CECDSAPrivateKey privKey = GenerateNewKey(256, false);
    CECDSAPublicKey pubkey = privKey.GetPublicKey();
    bool ret = privKey.VerifyPubKey(pubkey);
    return ret;
}

void CECDSA::ECC_Start() {
    assert(secp256k1_context_sign == NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        unsigned char seed[32];
        LockObject(seed);
        GetRandBytes(seed, 32);
        bool ret = secp256k1_context_randomize(ctx, seed);
        assert(ret);
        UnlockObject(seed);
    }

    secp256k1_context_sign = ctx;
}

void CECDSA::ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = NULL;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}


/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle()
{
    if (refcount == 0) {
        assert(secp256k1_context_verify == NULL);
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        assert(secp256k1_context_verify != NULL);
    }
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle()
{
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_verify != NULL);
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = NULL;
    }
}

///----- CECDSAPrivateKey --------------------------------------------------------
bool CECDSAPrivateKey::SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
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

//! Note: this function may change the fCompressed of Private Key
CECDSAPublicKey CECDSAPrivateKey::GetPublicKey(char cCompress)
{
    assert(m_isValid);

    if (cCompress == 'C')
        fCompressed = true;
    else if (cCompress == 'U')
        fCompressed = false;

    CECDSAPublicKey publicKey;
    secp256k1_pubkey pubkey;
    size_t clen = 65;

    int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, vch);
    assert(ret);
    secp256k1_ec_pubkey_serialize(secp256k1_context_sign, publicKey.vch, &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

    publicKey.SyncData();
    publicKey.fCompressed = this->fCompressed;

    return publicKey;
}


bool CECDSAPrivateKey::Sign(const std::vector<unsigned char> &vHash, std::vector<unsigned char> &vSign, uint32_t entropy) const
{
    if (!m_isValid)
        return false;
    vSign.resize(72);
    size_t nSigLen = 72;
    unsigned char extra_entropy[32] = {0};
    WriteLE32(extra_entropy, entropy);
    secp256k1_ecdsa_signature sig;
    int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, (unsigned char*)&vHash[0], begin(), secp256k1_nonce_function_rfc6979, entropy ? extra_entropy : NULL);
    assert(ret);
    secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)&vSign[0], &nSigLen, &sig);
    vSign.resize(nSigLen);
    return true;
}

bool CECDSAPrivateKey::Sign(const std::string &hash, std::string &sign, uint32_t entropy) const
{
    std::vector<unsigned char> vHash(hash.begin(), hash.end());
    std::vector<unsigned char> vSign(sign.begin(), sign.end());
    bool ret;
    ret = Sign(vHash, vSign, entropy);
    sign = string(vSign.begin(), vSign.end());
    assert (ret);

    return true;
}

bool CECDSAPrivateKey::Sign(const std::string& hash, std::vector<unsigned char>& vchSig, uint32_t entropy) const
{
    return Sign(std::vector<unsigned char>(hash.begin(), hash.end()), vchSig, entropy);
}

bool CECDSAPrivateKey::Sign(const std::string &msg, std::string &sign) const
{
    return Sign(msg, sign, 0);
}
bool CECDSAPrivateKey::Sign(const std::vector<unsigned char> &vHash, std::vector<unsigned char> &vSign) const
{
    return Sign(vHash, vSign, 0);
}


bool CECDSAPrivateKey::SignCompact(const std::string& hash, std::vector<unsigned char>& vchSig) const
{
    if (!m_isValid)
        return false;
    vchSig.resize(65);
    int rec = -1;
    secp256k1_ecdsa_recoverable_signature sig;
    int ret = secp256k1_ecdsa_sign_recoverable(secp256k1_context_sign, &sig, (unsigned char*)&hash[0], begin(), secp256k1_nonce_function_rfc6979, NULL);
    assert(ret);
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_sign, (unsigned char*)&vchSig[1], &rec, &sig);
    assert(ret);
    assert(rec != -1);
    vchSig[0] = 27 + rec + (fCompressed ? 4 : 0);
    return true;
}

//! Use private key to sign, then public key to verify
bool CECDSAPrivateKey::VerifyPubKey(const CECDSAPublicKey& pubKey) const
{
    if (pubKey.IsCompressed() != fCompressed) {
        return false;
    }
    unsigned char rnd[8];
    std::string str = "Some data to sign\n";
    GetRandBytes(rnd, sizeof(rnd));
    unsigned char hash[32];
    CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash);
    std::vector<unsigned char> vchSig;
    Sign(std::vector<unsigned char>(hash, hash+32), vchSig);
    return pubKey.Verify(std::vector<unsigned char>(hash, hash+32), vchSig);
}

///----- CECDSAPublicKey ---------------------------------------------------------
bool CECDSAPublicKey::SaveToFile(std::string fileName, std::string fileFormat, std::string password) const
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

bool CECDSAPublicKey::Verify(const std::string &hash, const std::vector<unsigned char> &vchSig) const
{
    if (!IsValid())
        return false;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, vch, size())) {
        return false;
    }
    if (vchSig.size() == 0) {
        return false;
    }
    if (!CECDSA::ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size())) {
        return false;
    }
    /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
     * not historically been enforced in Bitcoin, so normalize them first. */
    secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
    return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, (unsigned char*)hash.c_str(), &pubkey);
}

bool CECDSAPublicKey::Verify(const std::string &hash, const std::string &sign) const
{
    return Verify(hash, std::vector<unsigned char>(sign.begin(), sign.end()));
}
bool CECDSAPublicKey::Verify(const std::vector<unsigned char> &vHash, const std::vector<unsigned char> &vSign) const
{
    return Verify(std::string(vHash.begin(), vHash.end()), vSign);
}
