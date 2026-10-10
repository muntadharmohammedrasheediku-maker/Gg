#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#import "fishhook.h"

#pragma mark - Cryptographic Hooks

int (*orig_AES_cbc_encrypt)(const unsigned char *in, unsigned char *out, size_t len, 
                             const void *key, unsigned char *ivec, int enc);
int hooked_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                            const void *key, unsigned char *ivec, int enc) {
    return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
}

void (*orig_AES_encrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_encrypt(in, out, key);
}

void (*orig_AES_decrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_decrypt(in, out, key);
}

int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_encrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret;
}

int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_decrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_decrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret;
}

void (*orig_DES_encrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_encrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_encrypt(input, schedule, encrypting);
}

void (*orig_DES_decrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_decrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_decrypt(input, schedule, encrypting);
}

int (*orig_DES_cbc_encrypt)(const unsigned char *input, unsigned char *output,
                            long length, void *schedule, unsigned char *ivec, int enc);
int hooked_DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                            long length, void *schedule, unsigned char *ivec, int enc) {
    return orig_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
}

int (*orig_DES_set_key)(const unsigned char *key, void *schedule);
int hooked_DES_set_key(const unsigned char *key, void *schedule) {
    int ret = orig_DES_set_key(key, schedule);
    return (ret != 0) ? 0 : ret;
}

#pragma mark - RSA Hooks

int (*orig_RSA_public_encrypt)(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_encrypt(int flen, const unsigned char *from,
                               unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

int (*orig_RSA_private_decrypt)(int flen, const unsigned char *from,
                                 unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_decrypt(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

int (*orig_RSA_private_encrypt)(int flen, const unsigned char *from,
                                 unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_encrypt(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

int (*orig_RSA_public_decrypt)(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_decrypt(int flen, const unsigned char *from,
                               unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len,
                      unsigned char *sigret, unsigned int *siglen, void *rsa);
int hooked_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
                     unsigned char *sigret, unsigned int *siglen, void *rsa) {
    int ret = orig_RSA_sign(type, m, m_len, sigret, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len,
                        const unsigned char *sigbuf, unsigned int siglen, void *rsa);
int hooked_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
                       const unsigned char *sigbuf, unsigned int siglen, void *rsa) {
    int ret = orig_RSA_verify(type, m, m_len, sigbuf, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_check_key)(const void *rsa);
int hooked_RSA_check_key(const void *rsa) {
    int ret = orig_RSA_check_key(rsa);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_generate_key)(void *rsa, int bits, unsigned long e, void *cb);
int hooked_RSA_generate_key(void *rsa, int bits, unsigned long e, void *cb) {
    int ret = orig_RSA_generate_key(rsa, bits, e, cb);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_padding_add_PKCS1_type_1)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_1(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_padding_add_PKCS1_type_2)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_2(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_padding_add_SSLv23)(unsigned char *to, int tlen,
                                    const unsigned char *f, int fl);
int hooked_RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_SSLv23(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_padding_add_X931)(unsigned char *to, int tlen,
                                  const unsigned char *f, int fl);
int hooked_RSA_padding_add_X931(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_X931(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_padding_check_PKCS1_OAEP)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl, int rlen,
                                          unsigned char *param, int plen);
int hooked_RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl, int rlen,
                                         unsigned char *param, int plen) {
    int ret = orig_RSA_padding_check_PKCS1_OAEP(to, tlen, f, fl, rlen, param, plen);
    return (ret < 0) ? tlen : ret;
}

int (*orig_RSA_padding_check_SSLv23)(unsigned char *to, int tlen,
                                      const unsigned char *f, int fl, int rlen);
int hooked_RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                                     const unsigned char *f, int fl, int rlen) {
    int ret = orig_RSA_padding_check_SSLv23(to, tlen, f, fl, rlen);
    return (ret < 0) ? tlen : ret;
}

#pragma mark - Hash Hooks

int (*orig_MD5_Init)(void *c);
int hooked_MD5_Init(void *c) {
    int ret = orig_MD5_Init(c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_MD5_Update)(void *c, const void *data, size_t len);
int hooked_MD5_Update(void *c, const void *data, size_t len) {
    return orig_MD5_Update(c, data, len);
}

int (*orig_MD5_Final)(unsigned char *md, void *c);
int hooked_MD5_Final(unsigned char *md, void *c) {
    int ret = orig_MD5_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA1_Init)(void *c);
int hooked_SHA1_Init(void *c) {
    int ret = orig_SHA1_Init(c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA1_Update)(void *c, const void *data, size_t len);
int hooked_SHA1_Update(void *c, const void *data, size_t len) {
    return orig_SHA1_Update(c, data, len);
}

int (*orig_SHA1_Final)(unsigned char *md, void *c);
int hooked_SHA1_Final(unsigned char *md, void *c) {
    int ret = orig_SHA1_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA256_Init)(void *c);
int hooked_SHA256_Init(void *c) {
    int ret = orig_SHA256_Init(c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA256_Update)(void *c, const void *data, size_t len);
int hooked_SHA256_Update(void *c, const void *data, size_t len) {
    return orig_SHA256_Update(c, data, len);
}

int (*orig_SHA256_Final)(unsigned char *md, void *c);
int hooked_SHA256_Final(unsigned char *md, void *c) {
    int ret = orig_SHA256_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA512_Init)(void *c);
int hooked_SHA512_Init(void *c) {
    int ret = orig_SHA512_Init(c);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SHA512_Update)(void *c, const void *data, size_t len);
int hooked_SHA512_Update(void *c, const void *data, size_t len) {
    return orig_SHA512_Update(c, data, len);
}

int (*orig_SHA512_Final)(unsigned char *md, void *c);
int hooked_SHA512_Final(unsigned char *md, void *c) {
    int ret = orig_SHA512_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

unsigned char *(*orig_MD5)(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *hooked_MD5(const unsigned char *d, size_t n, unsigned char *md) {
    return orig_MD5(d, n, md);
}

int (*orig_HMAC_Init)(void *ctx, const void *key, int key_len, const void *md);
int hooked_HMAC_Init(void *ctx, const void *key, int key_len, const void *md) {
    int ret = orig_HMAC_Init(ctx, key, key_len, md);
    return (ret != 1) ? 1 : ret;
}

int (*orig_HMAC_Update)(void *ctx, const void *data, size_t len);
int hooked_HMAC_Update(void *ctx, const void *data, size_t len) {
    return orig_HMAC_Update(ctx, data, len);
}

int (*orig_HMAC_Final)(void *ctx, unsigned char *md, unsigned int *len);
int hooked_HMAC_Final(void *ctx, unsigned char *md, unsigned int *len) {
    int ret = orig_HMAC_Final(ctx, md, len);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - EVP Hooks

int (*orig_EVP_SignFinal)(void *ctx, unsigned char *md, unsigned int *s, void *pkey);
int hooked_EVP_SignFinal(void *ctx, unsigned char *md, unsigned int *s, void *pkey) {
    int ret = orig_EVP_SignFinal(ctx, md, s, pkey);
    return (ret != 1) ? 1 : ret;
}

int (*orig_EVP_VerifyFinal)(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey);
int hooked_EVP_VerifyFinal(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey) {
    int ret = orig_EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
    return (ret != 1) ? 1 : ret;
}

int (*orig_EVP_DigestSign)(void *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestSign(void *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestSign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

int (*orig_EVP_DigestVerify)(void *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestVerify(void *ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

int (*orig_EVP_PKEY_sign)(void *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_sign(void *ctx, unsigned char *sig, size_t *siglen,
                          const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

int (*orig_EVP_PKEY_verify)(void *ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - X509 & SSL Hooks

int (*orig_X509_verify_cert)(void *ctx);
int hooked_X509_verify_cert(void *ctx) {
    int ret = orig_X509_verify_cert(ctx);
    return (ret != 1) ? 1 : ret;
}

int (*orig_X509_check_private_key)(const void *x509, const void *pkey);
int hooked_X509_check_private_key(const void *x509, const void *pkey) {
    int ret = orig_X509_check_private_key(x509, pkey);
    return (ret != 1) ? 1 : ret;
}

void (*orig_SSL_CTX_set_verify)(void *ctx, int mode, void *cb);
void hooked_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    orig_SSL_CTX_set_verify(ctx, 0x00, NULL);
}

void (*orig_SSL_CTX_set_cert_verify_callback)(void *ctx, void *cb, void *arg);
void hooked_SSL_CTX_set_cert_verify_callback(void *ctx, void *cb, void *arg) {
    return;
}

long (*orig_SSL_get_verify_result)(const void *ssl);
long hooked_SSL_get_verify_result(const void *ssl) {
    return 0;
}

int (*orig_SSL_read)(void *ssl, void *buf, int num);
int hooked_SSL_read(void *ssl, void *buf, int num) {
    return orig_SSL_read(ssl, buf, num);
}

int (*orig_SSL_write)(void *ssl, const void *buf, int num);
int hooked_SSL_write(void *ssl, const void *buf, int num) {
    return orig_SSL_write(ssl, buf, num);
}

int (*orig_X509_STORE_CTX_verify)(void *ctx);
int hooked_X509_STORE_CTX_verify(void *ctx) {
    int ret = orig_X509_STORE_CTX_verify(ctx);
    return (ret != 1) ? 1 : ret;
}

void (*orig_SSL_set_verify)(void *ssl, int mode, void *cb);
void hooked_SSL_set_verify(void *ssl, int mode, void *cb) {
    orig_SSL_set_verify(ssl, 0x00, NULL);
}

#pragma mark - iOS Security Framework Hooks

OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    return orig_SecItemAdd(attributes, result);
}

OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    return orig_SecItemUpdate(query, attributesToUpdate);
}

OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = orig_SecItemCopyMatching(query, result);
    if (status == errSecItemNotFound) {
        NSString *queryDesc = [(__bridge NSDictionary *)query description];
        if ([queryDesc containsString:@"kSecClassKey"] || [queryDesc containsString:@"private"]) {
            return status;
        }
        return errSecSuccess;
    }
    return status;
}

OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    return orig_SecItemDelete(query);
}

OSStatus (*orig_SecKeyEncrypt)(SecKeyRef key, SecPadding padding,
                                const uint8_t *plainText, size_t plainTextLen,
                                uint8_t *cipherText, size_t *cipherTextLen);
OSStatus hooked_SecKeyEncrypt(SecKeyRef key, SecPadding padding,
                               const uint8_t *plainText, size_t plainTextLen,
                               uint8_t *cipherText, size_t *cipherTextLen) {
    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
}

OSStatus (*orig_SecKeyDecrypt)(SecKeyRef key, SecPadding padding,
                                const uint8_t *cipherText, size_t cipherTextLen,
                                uint8_t *plainText, size_t *plainTextLen);
OSStatus hooked_SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                               const uint8_t *cipherText, size_t cipherTextLen,
                               uint8_t *plainText, size_t *plainTextLen) {
    return orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
}

int (*orig_SecRandomCopyBytes)(SecRandomRef rnd, size_t count, uint8_t *bytes);
int hooked_SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) {
    return orig_SecRandomCopyBytes(rnd, count, bytes);
}

#pragma mark - PEM Hooks

void *(*orig_PEM_read_PrivateKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PrivateKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PrivateKey(bp, x, cb, u);
}

void *(*orig_PEM_read_PublicKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PublicKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PublicKey(bp, x, cb, u);
}

int (*orig_PEM_write_PrivateKey)(void *bp, void *x, const void *enc,
                                  void *kstr, int klen, void *cb, void *u);
int hooked_PEM_write_PrivateKey(void *bp, void *x, const void *enc,
                                 void *kstr, int klen, void *cb, void *u) {
    int ret = orig_PEM_write_PrivateKey(bp, x, enc, kstr, klen, cb, u);
    return (ret != 1) ? 1 : ret;
}

int (*orig_PEM_write_PublicKey)(void *bp, void *x);
int hooked_PEM_write_PublicKey(void *bp, void *x) {
    int ret = orig_PEM_write_PublicKey(bp, x);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Integrity & Detection Bypass

BOOL (*orig_integrity_detect)(id self, SEL _cmd);
BOOL hooked_integrity_detect(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isJailbroken)(id self, SEL _cmd);
BOOL hooked_isJailbroken(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_jailbreakDetection)(id self, SEL _cmd);
BOOL hooked_jailbreakDetection(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isJailbreak)(id self, SEL _cmd);
BOOL hooked_isJailbreak(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkJailbreak)(id self, SEL _cmd);
BOOL hooked_checkJailbreak(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isSimulator)(id self, SEL _cmd);
BOOL hooked_isSimulator(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isSimulatorDevice)(id self, SEL _cmd);
BOOL hooked_isSimulatorDevice(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkSimulator)(id self, SEL _cmd);
BOOL hooked_checkSimulator(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isDebuggerAttached)(id self, SEL _cmd);
BOOL hooked_isDebuggerAttached(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isDebugged)(id self, SEL _cmd);
BOOL hooked_isDebugged(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkDebugger)(id self, SEL _cmd);
BOOL hooked_checkDebugger(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_amIBeingDebugged)(id self, SEL _cmd);
BOOL hooked_amIBeingDebugged(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkDebuggerAttach)(id self, SEL _cmd);
BOOL hooked_checkDebuggerAttach(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isHooked)(id self, SEL _cmd);
BOOL hooked_isHooked(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isHookDetected)(id self, SEL _cmd);
BOOL hooked_isHookDetected(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkHook)(id self, SEL _cmd);
BOOL hooked_checkHook(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_detectHook)(id self, SEL _cmd);
BOOL hooked_detectHook(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiHookCheck)(id self, SEL _cmd);
BOOL hooked_antiHookCheck(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isTampered)(id self, SEL _cmd);
BOOL hooked_isTampered(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkTamper)(id self, SEL _cmd);
BOOL hooked_checkTamper(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiTamperCheck)(id self, SEL _cmd);
BOOL hooked_antiTamperCheck(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_verifyIntegrity)(id self, SEL _cmd);
BOOL hooked_verifyIntegrity(id self, SEL _cmd) {
    return YES;
}

BOOL (*orig_isInjected)(id self, SEL _cmd);
BOOL hooked_isInjected(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isLibraryInjected)(id self, SEL _cmd);
BOOL hooked_isLibraryInjected(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkInjection)(id self, SEL _cmd);
BOOL hooked_checkInjection(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiInjectionCheck)(id self, SEL _cmd);
BOOL hooked_antiInjectionCheck(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isReversingDetected)(id self, SEL _cmd);
BOOL hooked_isReversingDetected(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_checkReversing)(id self, SEL _cmd);
BOOL hooked_checkReversing(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiReversingCheck)(id self, SEL _cmd);
BOOL hooked_antiReversingCheck(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_isBlocked)(id self, SEL _cmd);
BOOL hooked_isBlocked(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiBlockingCheck)(id self, SEL _cmd);
BOOL hooked_antiBlockingCheck(id self, SEL _cmd) {
    return NO;
}

#pragma mark - File System Access Bypass

int (*orig_access)(const char *path, int amode);
int hooked_access(const char *path, int amode) {
    const char *jailbreakPaths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/bin/bash",
        "/bin/sh",
        "/etc/apt",
        "/private/var/lib/apt",
        "/private/var/tmp/cydia.log",
        "/usr/bin/cycript",
        "/usr/bin/ssh",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/var/tmp/cydia.log",
        NULL
    };
    
    for (int i = 0; jailbreakPaths[i] != NULL; i++) {
        if (strcmp(path, jailbreakPaths[i]) == 0) {
            errno = ENOENT;
            return -1;
        }
    }
    
    return orig_access(path, amode);
}

static BOOL (*orig_fileExistsAtPath)(id self, SEL _cmd, NSString *path);
BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/bin/bash",
        @"/etc/apt",
        @"/usr/bin/ssh",
        @"/usr/sbin/sshd",
        @"/private/var/lib/apt",
        @"/Library/MobileSubstrate",
        @"/var/log/syslog"
    ];
    
    for (NSString *jbPath in jailbreakPaths) {
        if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
            return NO;
        }
    }
    
    return orig_fileExistsAtPath(self, _cmd, path);
}

static BOOL (*orig_fileExistsAtPath_isDirectory)(id self, SEL _cmd, NSString *path, BOOL *isDir);
BOOL hooked_fileExistsAtPath_isDirectory(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/bin/bash",
        @"/etc/apt",
        @"/usr/bin/ssh",
        @"/Library/MobileSubstrate"
    ];
    
    for (NSString *jbPath in jailbreakPaths) {
        if ([path hasPrefix:jbPath] || [path isEqualToString:jbPath]) {
            return NO;
        }
    }
    
    return orig_fileExistsAtPath_isDirectory(self, _cmd, path, isDir);
}

#pragma mark - Advertising & Tracking

static NSString *(*orig_advertisingIdentifier)(id self, SEL _cmd);
NSString *hooked_advertisingIdentifier(id self, SEL _cmd) {
    return @"00000000-0000-0000-0000-000000000000";
}

static int (*orig_trackingAuthorizationStatus)(id self, SEL _cmd);
int hooked_trackingAuthorizationStatus(id self, SEL _cmd) {
    return 3;
}

#pragma mark - RAND_bytes

int (*orig_RAND_bytes)(unsigned char *buf, int num);
int hooked_RAND_bytes(unsigned char *buf, int num) {
    return orig_RAND_bytes(buf, num);
}

void *(*orig_CRYPTO_memdup)(const void *data, size_t siz, const char *file, int line);
void *hooked_CRYPTO_memdup(const void *data, size_t siz, const char *file, int line) {
    return orig_CRYPTO_memdup(data, siz, file, line);
}

int (*orig_EVP_PKEY_derive)(void *ctx, unsigned char *key, size_t *keylen);
int hooked_EVP_PKEY_derive(void *ctx, unsigned char *key, size_t *keylen) {
    int ret = orig_EVP_PKEY_derive(ctx, key, keylen);
    return (ret != 1) ? 1 : ret;
}

int (*orig_SSL_set_session)(void *ssl, void *session);
int hooked_SSL_set_session(void *ssl, void *session) {
    int ret = orig_SSL_set_session(ssl, session);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - File Integrity Check Bypass

BOOL (*orig_verify_file_md5)(NSString *path, NSString *expectedMD5);
BOOL hooked_verify_file_md5(NSString *path, NSString *expectedMD5) {
    return YES;
}

BOOL (*orig_CheckFileMd5)(NSString *path, NSString *expected);
BOOL hooked_CheckFileMd5(NSString *path, NSString *expected) {
    return YES;
}

BOOL (*orig_CheckFileHeader)(NSString *path, NSData *expectedHeader);
BOOL hooked_CheckFileHeader(NSString *path, NSData *expectedHeader) {
    return YES;
}

BOOL (*orig_verifySignature)(id self, SEL _cmd, id signature, id data);
BOOL hooked_verifySignature(id self, SEL _cmd, id signature, id data) {
    return YES;
}

BOOL (*orig_IsFileExistInResDir)(NSString *filename);
BOOL hooked_IsFileExistInResDir(NSString *filename) {
    return YES;
}

#pragma mark - SSL Pinning Bypass

static NSSet *(*orig_pinnedCertificates)(id self, SEL _cmd);
NSSet *hooked_pinnedCertificates(id self, SEL _cmd) {
    return [NSSet set];
}

#pragma mark - AppDelegate Hook

@interface AppDelegateHook : NSObject
@end

@implementation AppDelegateHook

+ (void)load {
    Method original = class_getInstanceMethod(
        NSClassFromString(@"AppDelegate"),
        @selector(application:didFinishLaunchingWithOptions:)
    );
    Method swizzled = class_getInstanceMethod(
        self,
        @selector(hooked_application:didFinishLaunchingWithOptions:)
    );
    method_exchangeImplementations(original, swizzled);
}

- (BOOL)hooked_application:(UIApplication *)application 
didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    return YES;
}

@end

#pragma mark - Constructor (Main Hook Initialization)

// ماكرو لتسهيل عملية الربط (يحل مشكلة التحويل في C++)
#define REBIND(name) {(name), (void *)hooked_##name, (void **)&orig_##name}

static __attribute__((constructor)) void initialize_hook() {
    @autoreleasepool {
        NSLog(@"[ShadowTrackerBypass] Loading bypass...");
        
        // محاولة تحميل المكتبات (اختياري، مجرد محاولة لضمان وجودها في الذاكرة)
        dlopen("/usr/lib/libcrypto.dylib", RTLD_LAZY);
        dlopen("/usr/lib/libssl.dylib", RTLD_LAZY);
        
        // مصفوفة الربط باستخدام الماكرو REBIND
        struct rebinding bindings[] = {
            // Crypto
            REBIND(AES_cbc_encrypt),
            REBIND(AES_encrypt),
            REBIND(AES_decrypt),
            REBIND(AES_set_encrypt_key),
            REBIND(AES_set_decrypt_key),
            
            // DES
            REBIND(DES_encrypt),
            REBIND(DES_decrypt),
            REBIND(DES_cbc_encrypt),
            REBIND(DES_set_key),
            
            // RSA
            REBIND(RSA_public_encrypt),
            REBIND(RSA_private_decrypt),
            REBIND(RSA_private_encrypt),
            REBIND(RSA_public_decrypt),
            REBIND(RSA_sign),
            REBIND(RSA_verify),
            REBIND(RSA_check_key),
            REBIND(RSA_generate_key),
            REBIND(RSA_padding_add_PKCS1_type_1),
            REBIND(RSA_padding_add_PKCS1_type_2),
            REBIND(RSA_padding_add_SSLv23),
            REBIND(RSA_padding_add_X931),
            REBIND(RSA_padding_check_PKCS1_OAEP),
            REBIND(RSA_padding_check_SSLv23),
            
            // Hash
            REBIND(MD5_Init),
            REBIND(MD5_Update),
            REBIND(MD5_Final),
            REBIND(SHA1_Init),
            REBIND(SHA1_Update),
            REBIND(SHA1_Final),
            REBIND(SHA256_Init),
            REBIND(SHA256_Update),
            REBIND(SHA256_Final),
            REBIND(SHA512_Init),
            REBIND(SHA512_Update),
            REBIND(SHA512_Final),
            REBIND(MD5),
            REBIND(HMAC_Init),
            REBIND(HMAC_Update),
            REBIND(HMAC_Final),
            
            // EVP
            REBIND(EVP_SignFinal),
            REBIND(EVP_VerifyFinal),
            REBIND(EVP_DigestSign),
            REBIND(EVP_DigestVerify),
            REBIND(EVP_PKEY_sign),
            REBIND(EVP_PKEY_verify),
            
            // SSL / X509
            REBIND(SSL_CTX_set_verify),
            REBIND(SSL_CTX_set_cert_verify_callback),
            REBIND(SSL_get_verify_result),
            REBIND(SSL_read),
            REBIND(SSL_write),
            REBIND(SSL_set_verify),
            REBIND(X509_verify_cert),
            REBIND(X509_check_private_key),
            REBIND(X509_STORE_CTX_verify),
            
            // System
            REBIND(access),
            REBIND(RAND_bytes),
            REBIND(CRYPTO_memdup),
            REBIND(EVP_PKEY_derive),
            REBIND(SSL_set_session),
            
            // iOS Security Framework
            REBIND(SecItemAdd),
            REBIND(SecItemUpdate),
            REBIND(SecItemCopyMatching),
            REBIND(SecItemDelete),
            REBIND(SecKeyEncrypt),
            REBIND(SecKeyDecrypt),
            REBIND(SecRandomCopyBytes),
            
            // PEM
            REBIND(PEM_read_PrivateKey),
            REBIND(PEM_read_PublicKey),
            REBIND(PEM_write_PrivateKey),
            REBIND(PEM_write_PublicKey),
        };
        
        rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
    }
}
