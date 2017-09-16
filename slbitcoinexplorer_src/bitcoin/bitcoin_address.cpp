#include <string>
#include <vector>
#include "crypto/base58.h"
#include "bitcoin/bitcoin_address.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "crypto/bitcoin/hash.h"
#include "util/encoding_util.h"


CBitcoinAddress::CBitcoinAddress(std::string strAddress)
{
    //! Don't know what to do which this function. Should be deleted??
    throw not_implemented_exception();

    m_Type = strAddress.substr(0, 1);

    std::string s0, s1, s2;
    std::vector<unsigned char> vAddress;
    bool ret;
    ret = DecodeBase58(strAddress, vAddress);
    assert(ret);
    std::string type;
    type.push_back(vAddress[0]);

    assert (type == address::P2PKH_PRE || type==address::P2SH_PRE);

    //! Now, we validate this address
    if (type == address::P2PKH_PRE)
    {
        unsigned char sha256[32];
        std::string checksum(vAddress.end() -4, vAddress.end());
        std::string addresshash(vAddress.begin(), vAddress.end() - 3);
        CHash256().Write((const unsigned char*)addresshash.c_str(), addresshash.size()).Finalize(sha256);
        assert(memcmp(checksum.c_str(), sha256, 4) == 0);
    }
    else
        throw not_implemented_exception();
}

CBitcoinAddress::CBitcoinAddress(const CECDSAPublicKey &pubKey, std::string type)
{
    if (pubKey.IsValid())
    {
        if (type == address::P2PKH_PRE)
        {
            m_Type = type;
            std::string strKey = pubKey.Serialize();
            unsigned char sha256[32];
            unsigned char ripemd[25];   // prefix 1 byte + 20 byte ripemd + checksum 4 byte
            CSHA256().Write((const unsigned char*)strKey.c_str(), strKey.size()).Finalize(sha256);
            CRIPEMD160().Write(sha256, 32).Finalize(ripemd + 1);
            ripemd[0] = 0;
            CHash256().Write(ripemd, 21).Finalize(sha256);
            memcpy(ripemd+21, sha256, 4);
            m_Address = EncodeBase58(ripemd, ripemd+25);
            m_isValid = true;
        }
        else if (type == address::P2PKH_PRE)
        {
            throw not_implemented_exception();
        }
    }
}

std::string CBitcoinAddress::PK2Address(CECDSAPublicKey pubKey, std::string type)
{
    if (type != address::P2PKH_PRE)
        throw not_implemented_exception();

    CBitcoinAddress add(pubKey, type);

    if (add.IsValid())
        return add.GetAddress();
    else
        throw logic_exception("Can't generate address from this Address.");
}

bool CBitcoinAddress::VerifyAddress(std::string strAddress)
{
    std::string address_type = strAddress.substr(0, 1);

    if (address_type != address::P2PKH_PRE)
        return false;

    std::vector<unsigned char> vAddress;
    bool ret;
    ret = DecodeBase58(strAddress, vAddress);
    assert(ret);
    std::string strNetwork;
    strNetwork.push_back(vAddress[0]);

    //! Now, we validate this address
    if ((unsigned char)vAddress[0] == 0)        //main net
    {
        unsigned char sha256[32];
        std::string checksum(vAddress.end() -4, vAddress.end());
        std::string addresshash(vAddress.begin(), vAddress.end() - 4);
        CHash256().Write((const unsigned char*)addresshash.c_str(), addresshash.size()).Finalize(sha256);
        if (memcmp(checksum.c_str(), sha256, 4) == 0)
            return true;
    }

    return false;
}

std::string CBitcoinAddress::Address2Hex(std::string strAddress)
{
    std::string address_type = strAddress.substr(0, 1);

    assert (address_type == address::P2PKH_PRE);

    std::vector<unsigned char> vAddress;
    bool ret;
    ret = DecodeBase58(strAddress, vAddress);
    assert(ret);
    std::string strNetwork;
    strNetwork.push_back(vAddress[0]);

    //! Now, we validate this address
    if ((unsigned char)vAddress[0] == 0)        //main net
    {
        unsigned char sha256[32];
        std::string checksum(vAddress.end() -4, vAddress.end());
        std::string addresshash(vAddress.begin(), vAddress.end() - 4);
        CHash256().Write((const unsigned char*)addresshash.c_str(), addresshash.size()).Finalize(sha256);
        assert (memcmp(checksum.c_str(), sha256, 4) == 0);

        return ::GetHex(string(vAddress.begin()+1, vAddress.end()-4));

    }

    return "";
}


std::string CBitcoinAddress::Address2Script(std::string strAddress)
{
    std::string script = Address2Hex(strAddress);
    assert(script.size() > 20);

    script += "88ac";
    script = "76a914" + script;
    return script;
}

//----- CBitcoinSecret ------------------------------------------------------------------
CBitcoinSecret::CBitcoinSecret(std::string strAddress)
{
    //! Don't know what to do which this function. Should be deleted??
    throw not_implemented_exception();

}

CBitcoinSecret::CBitcoinSecret(const CECDSAPrivateKey &priKey, std::string type)
{
    if (priKey.IsValid())
    {
        if (type == address::PRIV_UN_PRE || address::PRIV_CO_PRE.find(type) != std::string::npos)
        {
            //extra byte for compress type
            uint32_t ex = 0;

            if (address::PRIV_CO_PRE.find(type) != std::string::npos)
                ex = 1;

            m_Type = type;
            //! Step 1: Serialize
            std::string strKey = priKey.Serialize();

            assert(strKey.size() == 32);
            std::vector<unsigned char> vKey;
            vKey.resize(37+ex);
            memcpy(&vKey[1], (const char*)strKey.c_str(), strKey.size());

            //! Step 2: insert 1 byte 0x80
            vKey[0] = 0x80;


            //! Step 3: - If compress type, add 1 more byte before the checksum
            if (ex > 0)
                vKey[33] = 0x01;

            //! Step 4: double SHA256
            unsigned char sha256[32];
            CHash256().Write((const unsigned char*)&vKey[0], 33+ex).Finalize(sha256);


            //! step 5: Add checksum (from step 4) to step 3
            memcpy(&vKey[33+ex], sha256, 4);

            //! Step 6: Encode Base58
            m_Address = EncodeBase58(vKey);
            m_isValid = true;
        }
        else
        {
            throw not_implemented_exception();
        }
    }
    else
        throw logic_exception("Private key is invalid.");
}

std::string CBitcoinSecret::Priv2Address(CECDSAPrivateKey priKey, std::string type)
{
    if (!(type == address::PRIV_UN_PRE || address::PRIV_CO_PRE.find(type) != std::string::npos))
        throw not_implemented_exception();

    CBitcoinSecret addr(priKey, type);

    if (addr.IsValid())
        return addr.GetAddress();
    else
        throw logic_exception("Can't generate address from this Address.");
}

bool CBitcoinSecret::VerifyPrivAddress(std::string strAddress)
{
    std::string address_type = strAddress.substr(0, 1);

    if (!(address_type == address::PRIV_UN_PRE || address::PRIV_CO_PRE.find(address_type) != std::string::npos))
        return false;

    //extra byte for compress type
    uint32_t ex = 0;

    if (address::PRIV_CO_PRE.find(address_type) != std::string::npos)
        ex = 1;

    std::vector<unsigned char> vAddress;
    bool ret;
    ret = DecodeBase58(strAddress, vAddress);
    assert(ret);
    std::string strNetwork;
    strNetwork.push_back(vAddress[0]);

    //! Now, we validate this address
    if ((unsigned char)vAddress[0] == 0x80)        //first byte always 80
    {
        unsigned char sha256[32];
        std::string checksum(vAddress.end() -4, vAddress.end());
        std::string addresshash(vAddress.begin(), vAddress.end()-4-ex);
        CHash256().Write((unsigned char*)&vAddress[0], 33+ex).Finalize(sha256);
        if (memcmp((const unsigned char*)&vAddress[vAddress.size()-4], sha256, 4) == 0)
            return true;
    }

    return false;
}

CECDSAPrivateKey CBitcoinSecret::Address2PrivKey(std::string strAddress)
{
    bool ret;
    ret = VerifyPrivAddress(strAddress);
    assert(ret);
    std::vector<unsigned char> vAddress;
    ret = DecodeBase58(strAddress, vAddress);
    assert(ret);

    bool fCompressed =false;
    if (address::PRIV_CO_PRE.find(strAddress[0]) != std::string::npos)
        fCompressed = true;

    CECDSAPrivateKey key(&vAddress[1], fCompressed);

    std::string type;
    type.resize(1);
    type[0] = strAddress[0];

    assert(strAddress == Priv2Address(key, type));

    return key;
}

std::string CBitcoinSecret::PriAdd2PubAdd(std::string strPriAddress, char fCompress)
{
    std::string pubAddress;
    bool chk;
    chk = VerifyPrivAddress(strPriAddress);
    assert(chk);
    CECDSAPrivateKey privKey = Address2PrivKey(strPriAddress);
    CECDSAPublicKey pubKey = privKey.GetPublicKey(fCompress);
    return CBitcoinAddress::PK2Address(pubKey, address::P2PKH_PRE);
}
