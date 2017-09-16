#-------------------------------------------------
#
# Project created by QtCreator 2016-08-10T21:25:46
#
#-------------------------------------------------

QT       += testlib

QT       -= gui

TARGET = tst_cbitcoinexplorer_test
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


DEFINES += SRCDIR=\\\"$$PWD/\\\"

INCLUDEPATH += /usr/local/include \
    /usr/local/Cellar/openssl/1.0.2h_1/include \
    ../slbitcoinexplorer_src    \
    /var/git/bitcoin/src/secp256k1 \
    /var/git/bitcoin/src/secp256k1/include

macx: LIBS +=  -L/usr/local/Cellar/boost/1.60.0_2/lib -lboost_filesystem -lboost_thread-mt  \
        -lboost_program_options -lboost_system-mt -lboost_chrono  -lboost_unit_test_framework   \
        -L/usr/local/Cellar/openssl/1.0.2h_1/lib -lcrypto -lssl \
        -L/usr/local/lib -lsecp256k1



SOURCES +=  \
    ../slbitcoinexplorer_src/crypto/aes.cpp \
    ../slbitcoinexplorer_src/crypto/hmac_sha256.cpp \
    ../slbitcoinexplorer_src/crypto/hmac_sha512.cpp \
    ../slbitcoinexplorer_src/crypto/big_number.cpp \
    ../slbitcoinexplorer_src/crypto/key.cpp \
    ../slbitcoinexplorer_src/util/openssl_util.cpp \
    ../slbitcoinexplorer_src/crypto/base58.cpp \
    ../slbitcoinexplorer_src/crypto/rsa.cpp \
    ../slbitcoinexplorer_src/util/random.cpp \
    ../slbitcoinexplorer_src/util/exception.cpp \
    ../slbitcoinexplorer_src/util/pagelocker.cpp \
    ../slbitcoinexplorer_src/crypto/ecdsa.cpp   \
    base58_test.cpp \
    main.cpp \
    rsa_test.cpp \
    hash_test.cpp \
    hmac_test.cpp \
    aes_test.cpp \
    ecdsa_test.cpp \
    bitcoin_address_test.cpp \
    ../slbitcoinexplorer_src/bitcoin/bitcoin_address.cpp


SOURCES += /var/git/bitcoin/src/secp256k1/src/secp256k1.c


SOURCES +=  \
    ../slbitcoinexplorer_src/crypto/sha256.cpp      \
    ../slbitcoinexplorer_src/util/encoding_util.cpp  \
    ../slbitcoinexplorer_src/util/common_util.cpp  \
    ../slbitcoinexplorer_src/crypto/sha512.cpp     \
    ../slbitcoinexplorer_src/crypto/ripemd160.cpp   \
    ../slbitcoinexplorer_src/crypto/sha1.cpp        \
    ../slbitcoinexplorer_src/crypto/ctaes.c


HEADERS += \
    ../slbitcoinexplorer_src/config/config.h \
    ../slbitcoinexplorer_src/compat/byte_swap.h \
    ../slbitcoinexplorer_src/crypto/sha256.h \
    ../slbitcoinexplorer_src/compat/endian.h \
    ../slbitcoinexplorer_src/crypto/common.h    \
    ../slbitcoinexplorer_src/util/encoding_util.h \
    ../slbitcoinexplorer_src/util/random.h \
    ../slbitcoinexplorer_src/util/common_util.h \
    ../slbitcoinexplorer_src/crypto/sha512.h    \
    ../slbitcoinexplorer_src/crypto/ripemd160.h \
    ../slbitcoinexplorer_src/crypto/sha1.h \
    ../slbitcoinexplorer_src/crypto/ctaes.h \
    ../slbitcoinexplorer_src/crypto/aes.h \
    ../slbitcoinexplorer_src/crypto/hmac_sha256.h \
    ../slbitcoinexplorer_src/crypto/hmac_sha512.h \
    ../slbitcoinexplorer_src/crypto/chacha20_drng.h \
    ../slbitcoinexplorer_src/crypto/big_number.h \
    ../slbitcoinexplorer_src/crypto/key.h \
    ../slbitcoinexplorer_src/util/openssl_util.h \
    ../slbitcoinexplorer_src/crypto/base58.h \
    ../slbitcoinexplorer_src/crypto/rsa.h \
    ../slbitcoinexplorer_src/util/exception.h \
    ../slbitcoinexplorer_src/util/pagelocker.h \
    ../slbitcoinexplorer_src/crypto/ecdsa.h \
    ../slbitcoinexplorer_src/bitcoin/bitcoin_address.h




QMAKE_CXXFLAGS_WARN_OFF -= -Wunused-parameter
QMAKE_CXXFLAGS_WARN_ON += -Wno-unused-parameter

DEFINES += HAVE_CONFIG_H

MAKEFLAGS="-v"
