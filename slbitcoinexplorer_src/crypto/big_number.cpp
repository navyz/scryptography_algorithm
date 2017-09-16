#include <stdio.h>
#include <string.h>

#include <iostream>

#include "crypto/big_number.h"
#include "crypto/common.h"
#include "util/encoding_util.h"



bool CBigNumber::IsZero()
{
    for (int i = 0; i < nWidth; i++)
        if (pn[i] != 0) return false;

    return true;
}

bool CBigNumber::IsOdd()
{
    return (pn[0] % 2 == 1);
}

bool CBigNumber::IsEven()
{
    return (pn[0] % 2 == 0);
}

CBigNumber& CBigNumber::operator<<=(unsigned int shift)
{
    CBigNumber a(*this);
    for (int i = 0; i < nWidth; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < nWidth; i++) {
        if (i + k + 1 < nWidth && shift != 0)
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < nWidth)
            pn[i + k] |= (a.pn[i] << shift);
    }
    return *this;
}

CBigNumber& CBigNumber::operator>>=(unsigned int shift)
{
    CBigNumber a(*this);
    for (int i = 0; i < nWidth; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < nWidth; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0)
            pn[i - k] |= (a.pn[i] >> shift);
    }
    return *this;
}


CBigNumber& CBigNumber::operator*=(uint32_t b32)
{
    uint64_t carry = 0;
    for (int i = 0; i < nWidth; i++) {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}


CBigNumber& CBigNumber::operator*=(const CBigNumber& b)
{
    CBigNumber a = *this;
    *this = 0;
    for (int j = 0; j < nWidth; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < nWidth; i++) {
            uint64_t n = carry + pn[i + j] + (uint64_t)a.pn[j] * b.pn[i];
            pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return *this;
}


CBigNumber& CBigNumber::operator/=(const CBigNumber& b)
{
    CBigNumber div = b;     // make a copy, so we can shift.
    CBigNumber num = *this; // make a copy, so we can subtract.
    *this = 0;                   // the quotient.
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits == 0)
        throw uint_error("Division by zero");
    if (div_bits > num_bits) // the result is certainly 0.
        return *this;
    int shift = num_bits - div_bits;
    div <<= shift; // shift so that div and num align.
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            pn[shift / 32] |= (1 << (shift & 31)); // set a bit of the result.
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}


int CBigNumber::CompareTo(const CBigNumber& b) const
{
    for (int i = nWidth - 1; i >= 0; i--) {
        if (pn[i] < b.pn[i])
            return -1;
        if (pn[i] > b.pn[i])
            return 1;
    }
    return 0;
}


bool CBigNumber::EqualTo(uint64_t b) const
{
    for (int i = nWidth - 1; i >= 2; i--) {
        if (pn[i])
            return false;
    }
    if (pn[1] != (b >> 32))
        return false;
    if (pn[0] != (b & 0xfffffffful))
        return false;
    return true;
}


double CBigNumber::getdouble() const
{
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < nWidth; i++) {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}


std::string CBigNumber::GetHex() const
{
    char psz[nByte*2 + 1];

    uint32_t x;

    for ( int i = 0; i < nWidth; i++)
    {
        sprintf(psz + i * 8, "%08x", pn[nWidth-i-1]);
        std::string xxx(psz, psz + (i+1)*8);
        x = pn[i];
    }
    return std::string(psz, nByte*2);
}

//! This function does not change the number's bitsize
//! To call this function, make sure to check the length of the pointer is equal to bitsize
void CBigNumber::SetHex(const char* psz)
{
    this->Reset();

    // skip leading spaces
    while (isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    const char* pbegin = psz;
    while (::HexDigit(*psz) != -1)
        psz++;
    psz--;

    //p1 is the variable to store 4 bytes block.
    unsigned char p1[4];

    int i=0, j=0;
    while (psz >= pbegin && j*32 < nBit) {

        p1[i] = ::HexDigit(*psz--);
        if (psz >= pbegin) {
            p1[i] |= ((unsigned char)::HexDigit(*psz) << 4);
        }

        i++;

        // if the block is full, or end of input hexstring, then convert this 4 bytes to uint32 and store it to pn array;
        if (i == 4 || psz <= pbegin)
        {
            pn[j] = ReadLE32(p1);
            i = 0;
            j++;
            p1[0] = p1[1] = p1[2] = p1[3] = 0;
        }
        psz--;
    }
}


void CBigNumber::SetBin(const unsigned char* psz, int bytelen)
{
    this->Reset();

    const unsigned char* pbegin = psz;
    psz += bytelen-1;

    //p1 is the variable to store 4 bytes block.
    unsigned char p1[4];

    int i=0, j=0;
    while (psz >= pbegin && j*32 < nBit) {

        p1[i] = *psz;

        i++;

        // if the block is full, or end of input hexstring, then convert this 4 bytes to uint32 and store it to pn array;
        if (i == 4 || psz == pbegin)
        {
            pn[j] = ReadLE32(p1);
            i = 0;
            j++;
            p1[0] = p1[1] = p1[2] = p1[3] = 0;
        }
        psz--;
    }
}

void CBigNumber::SetBin(const std::vector<unsigned char> &vBin)
{
    this->Reset();

    const unsigned char *psz = &vBin[0];
    int len = vBin.size();
    this->SetBin(psz, len);
}

std::vector<unsigned char> CBigNumber::GetBin(bool trimZero) const
{
    std::vector<unsigned char> result;

    unsigned char temp[8];
    for (int i = nWidth-1; i >= 0; i--)
    {
        WriteBE32(temp, this->pn[i]);
        for (int j=0; j<4; j++)
        {
            if (!trimZero || temp[j]!=0 || result.size() > 0)
                result.push_back(temp[j]);
        }
    }
    return result;
}


void CBigNumber::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}


std::string CBigNumber::ToString() const
{
    return (GetHex());
}


unsigned int CBigNumber::bits() const
{
    for (int pos = nWidth - 1; pos >= 0; pos--) {
        if (pn[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (pn[pos] & 1 << bits)
                    return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}



CBigNumber& CBigNumber::exp_mod(const CBigNumber &pExp, const CBigNumber &pMod)
{
    assert(nWidth == pExp.nWidth);
    assert(nWidth == pMod.nWidth);

    unsigned int nTempBit = nBit * 2;
    if (nTempBit < pMod.bitsize())
        nTempBit = pMod.bitsize();

    CBigNumber base(nTempBit), exp(nTempBit), modulus(nTempBit), result(nTempBit);

    base.AssignKeepSize(*this);
    exp.AssignKeepSize(pExp);
    modulus.AssignKeepSize(pMod);
    result = 1;

    while (!exp.IsZero())
    {
        if (exp.IsOdd())
        {
            //result = (result * base) % modulus;
            result *= base;
            result %= modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    this->AssignKeepSize(result);

    return *this;
}


CBigNumber& CBigNumber::operator%=(const CBigNumber& b)
{
    CBigNumber div = b;     // make a copy, so we can shift.
    CBigNumber num(this->nBit);  //the quotient.

    int this_bits = this->bits();
    int div_bits = div.bits();
    if (div_bits == 0)
        throw uint_error("Division by zero");
    if (div_bits > this_bits) // the result is certainly this itself
        return *this;

    int shift = this_bits - div_bits;
    div <<= shift; // shift so that div and num align.
    while (shift >= 0) {
        if (*this >= div) {
            *this -= div;
        }
        div >>= 1; // shift back.
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}
