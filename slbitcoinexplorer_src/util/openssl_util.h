#ifndef OPENSSL_UTIL_H
#define OPENSSL_UTIL_H

#include <openssl/rsa.h>
#include <string>
#include <vector>
#include <sstream>
#include "crypto/big_number.h"


RSA* RSAFromDer(std::string der, std::string keyType);
RSA* RSAFromPem(std::string pem, std::string keyType);
std::string RSAToPem(RSA* rsa, std::string keyType);
std::string RSAToDer(RSA* rsa, std::string keyType);


bool RSAEncrypt(const std::string &pem, const std::vector<unsigned char> &input, std::vector<unsigned char> &output, std::string keyType);
bool RSADecrypt(const std::string &pem, const std::vector<unsigned char> &input, std::vector<unsigned char> &output, std::string keyType);

bool RSAPaddingPKCS1(std::vector<unsigned char> &msg, int keySize);

void WritePemFile(const std::string &fileName, const std::stringstream &ssHeader, const std::stringstream &ssContent, const std::string &strKeyType, std::string algorithm = "RSA");
void WriteNumberInDerFormat(std::stringstream &ss, const CBigNumber &n, bool trimZero=true);
void WriteHeader(std::stringstream &ssHeader, int nValueSize);

void memory_cleanse(void *ptr, size_t len);

#endif // OPENSSL_UTIL_H
