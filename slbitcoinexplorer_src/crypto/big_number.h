#ifndef CBIGNUMBER_H
#define CBIGNUMBER_H

#include <assert.h>
#include <cstring>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <vector>

#include <iostream>


class uint_error : public std::runtime_error {
public:
    explicit uint_error(const std::string& str) : std::runtime_error(str) {}
};


/** Template base class for unsigned big integers. */
class CBigNumber
{
protected:
    uint32_t *pn;       //store number in little endian array
    int nBit;
    int nByte;
    int nWidth;
public:

    CBigNumber()
    {
        nBit = nByte = nWidth = 0;
        pn = NULL;
    }

    CBigNumber(int bit)
    {
        nBit = bit;
        nByte = bit/8;
        nWidth = bit/32;
        pn = new uint32_t[nWidth];
        Reset();
    }

    CBigNumber(const CBigNumber& big)
    {
        //std::cout << "No: " << big.nBit << " - " << big.GetHex()  << std::endl;

        nBit = big.nBit;
        nByte = big.nByte;
        nWidth = big.nWidth;

        pn = new uint32_t[nWidth];

        for (int i = 0; i < nWidth; i++)
            pn[i] = big.pn[i];


    }

    CBigNumber(const std::string& str, uint32_t bitSize, bool isHex=true)
    {
        nBit = bitSize;
        nByte = nBit/8;
        nWidth = nBit/32;
        pn = new uint32_t[nWidth];

        if (isHex)
            SetHex(str);
        else
            SetBin((const unsigned char*)str.c_str(), bitSize);
    }


    CBigNumber(unsigned char* vch, uint32_t bitSize, bool isHex=true)
    {
        nBit = bitSize;
        nByte = nBit/8;
        nWidth = nBit/32;
        pn = new uint32_t[nWidth];

        if (isHex)
            SetHex((const char *)vch);
        else
            SetBin(vch, bitSize);
    }

    CBigNumber(const std::vector<unsigned char> &input, uint32_t bitSize)
    {
        nBit = bitSize;
        nByte = nBit/8;
        nWidth = nBit/32;
        pn = new uint32_t[nWidth];

        SetBin(input);
    }

    ~CBigNumber()
    {
        if (pn != NULL)
        delete[] pn;
    }

/*
    CBigNumber(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < nWidth; i++)
            pn[i] = 0;
    }

*/

    void resize(int bit)
    {
        nBit = bit;
        nByte = bit/8;
        nWidth = bit/32;

        if (pn != NULL)
            delete[] pn;
        pn = new uint32_t[nWidth];
        Reset();
    }

    bool operator!() const
    {
        for (int i = 0; i < nWidth; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    const CBigNumber operator~() const
    {
        CBigNumber ret(nBit);
        for (int i = 0; i < nWidth; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const CBigNumber operator-() const
    {
        CBigNumber ret(nBit);
        for (int i = 0; i < nWidth; i++)
            ret.pn[i] = ~pn[i];
        ret++;
        return ret;
    }

    double getdouble() const;

    CBigNumber& operator=(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < nWidth; i++)
            pn[i] = 0;
        return *this;
    }

    CBigNumber& operator^=(const CBigNumber& b)
    {
        for (int i = 0; i < nWidth; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    CBigNumber& operator&=(const CBigNumber& b)
    {
        for (int i = 0; i < nWidth; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    CBigNumber& operator|=(const CBigNumber& b)
    {
        for (int i = 0; i < nWidth; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    CBigNumber& operator^=(uint64_t b)
    {
        pn[0] ^= (unsigned int)b;
        pn[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    CBigNumber& operator|=(uint64_t b)
    {
        pn[0] |= (unsigned int)b;
        pn[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    CBigNumber& operator<<=(unsigned int shift);
    CBigNumber& operator>>=(unsigned int shift);

    CBigNumber& operator+=(const CBigNumber& b)
    {
        uint64_t carry = 0;
        for (int i = 0; i < nWidth; i++)
        {
            uint64_t n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    CBigNumber& operator-=(const CBigNumber& b)
    {
        *this += -b;
        return *this;
    }

    CBigNumber& operator+=(uint64_t b64)
    {
        CBigNumber b(nBit);
        b = b64;
        *this += b;
        return *this;
    }

    CBigNumber& operator-=(uint64_t b64)
    {
        CBigNumber b(nBit);
        b = b64;
        *this += -b;
        return *this;
    }

    CBigNumber& operator*=(uint32_t b32);
    CBigNumber& operator*=(const CBigNumber& b);
    CBigNumber& operator/=(const CBigNumber& b);

    CBigNumber& operator++()
    {
        // prefix operator
        int i = 0;
        while (++pn[i] == 0 && i < nWidth-1)
            i++;
        return *this;
    }

    const CBigNumber operator++(int)
    {
        // postfix operator
        const CBigNumber ret = *this;
        ++(*this);
        return ret;
    }

    CBigNumber& operator--()
    {
        // prefix operator
        int i = 0;
        while (--pn[i] == (uint32_t)-1 && i < nWidth-1)
            i++;
        return *this;
    }

    const CBigNumber operator--(int)
    {
        // postfix operator
        const CBigNumber ret = *this;
        --(*this);
        return ret;
    }



    int CompareTo(const CBigNumber& b) const;
    bool EqualTo(uint64_t b) const;

    friend inline const CBigNumber operator+(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) += b; }
    friend inline const CBigNumber operator-(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) -= b; }
    friend inline const CBigNumber operator*(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) *= b; }
    friend inline const CBigNumber operator/(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) /= b; }
    friend inline const CBigNumber operator|(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) |= b; }
    friend inline const CBigNumber operator&(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) &= b; }
    friend inline const CBigNumber operator^(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) ^= b; }
    friend inline const CBigNumber operator>>(const CBigNumber& a, int shift) { return CBigNumber(a) >>= shift; }
    friend inline const CBigNumber operator<<(const CBigNumber& a, int shift) { return CBigNumber(a) <<= shift; }
    friend inline const CBigNumber operator*(const CBigNumber& a, uint32_t b) { return CBigNumber(a) *= b; }
    friend inline bool operator==(const CBigNumber& a, const CBigNumber& b) { return memcmp(a.pn, b.pn, a.nWidth * 4) == 0; }
    friend inline bool operator!=(const CBigNumber& a, const CBigNumber& b) { return memcmp(a.pn, b.pn, a.nWidth * 4) != 0; }
    friend inline bool operator>(const CBigNumber& a, const CBigNumber& b) { return a.CompareTo(b) > 0; }
    friend inline bool operator<(const CBigNumber& a, const CBigNumber& b) { return a.CompareTo(b) < 0; }
    friend inline bool operator>=(const CBigNumber& a, const CBigNumber& b) { return a.CompareTo(b) >= 0; }
    friend inline bool operator<=(const CBigNumber& a, const CBigNumber& b) { return a.CompareTo(b) <= 0; }
    friend inline bool operator==(const CBigNumber& a, uint64_t b) { return a.EqualTo(b); }
    friend inline bool operator!=(const CBigNumber& a, uint64_t b) { return !a.EqualTo(b); }


    //asign to zero
    void Reset()
    {
        for (int i = 0; i < nWidth; i++)
            pn[i] = 0;
    }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;

    void SetBin(const unsigned char* psz, int len);
    void SetBin(const std::vector<unsigned char> &vBin);
    std::vector<unsigned char> GetBin(bool trimZero=true) const;

    unsigned int bytesize() const
    {
        return nByte;
    }
    unsigned int bitsize() const
    {
        return nBit;
    }

    /**
     * Returns the position of the highest bit set plus one, or zero if the
     * value is zero.
     */
    unsigned int bits() const;

    uint64_t GetLow64() const
    {
        assert(nWidth >= 2);
        return pn[0] | (uint64_t)pn[1] << 32;
    }

    // my custom functions compare to Bitcoin Core

    CBigNumber& exp_mod(const CBigNumber &pExp, const CBigNumber &pMod);
    bool IsZero();
    bool IsOdd();
    bool IsEven();

    CBigNumber& operator=(const CBigNumber& big)
    {
        nBit = big.nBit;
        nByte = big.nByte;
        nWidth = big.nWidth;

        if (pn != NULL)
            delete[] pn;
        pn = new uint32_t[nWidth];

        for (int i = 0; i < nWidth; i++)
            pn[i] = big.pn[i];

        return *this;
    }

CBigNumber& operator%=(const CBigNumber& b);
friend inline const CBigNumber operator%(const CBigNumber& a, const CBigNumber& b) { return CBigNumber(a) %= b; }

const CBigNumber& Truncate(int newLen)
{
    if (newLen >= nBit)
        return *this;

    nBit = newLen;
    nByte = nBit/8;
    nWidth = nBit/32;

    uint32_t *temp = pn;
    pn = new uint32_t[nWidth];

    for (int i = 0; i < nWidth; i++)
        pn[i] = temp[i];

    delete temp;

    return *this;
}

// Don't change the size of this following big.Size
CBigNumber& AssignKeepSize(const CBigNumber& big)
{
    Reset();
    for (int i = 0; i < nWidth && i<big.nWidth; i++)
        pn[i] = big.pn[i];

    return *this;
}

};

#endif // CBIGNUMBER_H


