TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH += \
    /usr/local/include \
    /usr/local/Cellar/openssl/1.0.2h_1/include  \
    /var/git/bitcoin/src/secp256k1 \
    /var/git/bitcoin/src/secp256k1/include

 macx: LIBS +=   \
    -L/usr/local/Cellar/openssl/1.0.2h_1/lib -lcrypto -lssl \
    -L/usr/local/Cellar/boost/1.60.0_2/lib -lboost_filesystem -lboost_system -lboost_thread-mt


#    -L/usr/local/lib -lsecp256k1    \

SOURCES += main.cpp \
    crypto/sha1.cpp \
    crypto/aes.cpp \
    crypto/sha256.cpp \
    crypto/ripemd160.cpp \
    crypto/ctaes.c \
    crypto/hmac_sha256.cpp \
    crypto/hmac_sha512.cpp \
    crypto/key.cpp \
    util/encoding_util.cpp \
    crypto/big_number.cpp \
    util/common_util.cpp \
    util/openssl_util.cpp \
    crypto/base58.cpp \
    crypto/rsa.cpp \
    util/pagelocker.cpp \
    util/random.cpp \
    util/exception.cpp \
    crypto/ecdsa.cpp \
    crypto/sha512.cpp \
    bitcoin/bitcoin_address.cpp


SOURCES += /var/git/bitcoin/src/secp256k1/src/secp256k1.c


HEADERS += \
    compat/endian.h \
    crypto/common.h \
    crypto/sha1.h   \
    crypto/sha256.h \
    crypto/sha512.h \
    crypto/ripemd160.h \
    crypto/aes.h \
    crypto/ctaes.h \
    crypto/hmac_sha256.h \
    crypto/hmac_sha512.h \
    util/random.h \
    crypto/key.h \
    compat/byte_swap.h \
    util/encoding_util.h \
    crypto/cipher.h \
    crypto/big_number.h \
    util/common_util.h \
    util/openssl_util.h \
    crypto/base58.h \
    crypto/rsa.h \
    config/config.h \
    util/pagelocker.h \
    crypto/bitcoin/hash.h \
    util/exception.h \
    crypto/ecdsa.h \
    bitcoin/bitcoin_address.h \
    util/zeroafterfree.h



QMAKE_CXXFLAGS_WARN_OFF -= -Wunused-parameter
QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-parameter

DEFINES += HAVE_CONFIG_H
