#ifndef BITCOINADDRESS_H
#define BITCOINADDRESS_H


#include <string>
#include <vector>

#include "crypto/base58.h"
#include "crypto/ecdsa.h"


namespace address
{
    const std::string P2PKH_PRE = "1";
    const std::string P2SH_PRE = "3";
    const std::string PRIV_UN_PRE = "5";
    const std::string PRIV_CO_PRE = "KL";   //K or L. One out of 2.
    const std::string XPUB_PRE = "xpub";
    const std::string XPRV_PRE = "xprv";
}

//----- CBitcoinAddress ------------------------------------------------------------------
class CBitcoinAddress  {

private:

    bool m_isValid = false;
    std::string m_Type = "";
    std::string m_Address;

public:
    CBitcoinAddress(std::string strAddress);
    CBitcoinAddress(const CECDSAPublicKey &pubKey, std::string type);
    std::string GetAddress() const {return m_Address;}
    std::string GetType() const {return m_Type;}
    bool IsValid() const {return m_isValid;}

    static std::string PK2Address(CECDSAPublicKey pubKey, std::string type);
    static bool VerifyAddress(std::string strAddress);
    static std::string Address2Hex(std::string strAddress);
    static std::string Address2Script(std::string strAddress);
};

//----- CBitcoinSecret ------------------------------------------------------------------
class CBitcoinSecret  {

private:

    bool m_isValid = false;
    std::string m_Type = "";
    std::string m_Address;

public:
    CBitcoinSecret(std::string strAddress);
    CBitcoinSecret(const CECDSAPrivateKey &pubKey, std::string type);
    std::string GetAddress() const {return m_Address;}
    std::string GetType() const {return m_Type;}
    bool IsValid() const {return m_isValid;}

    static std::string Priv2Address(CECDSAPrivateKey privKey, std::string type);
    static bool VerifyPrivAddress(std::string strAddress);
    static CECDSAPrivateKey Address2PrivKey(std::string strAddress);
    static std::string PriAdd2PubAdd(std::string strPriAddress, char fCompress='0');
};



#endif // BITCOINADDRESS_H
