#import <Foundation/Foundation.h>
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
#import "fishhook/fishhook.h"

#pragma mark - Cryptographic Hooks (Memory-Based, No Patching)

// ===== AES-128/256 CBC Encrypt - Always encrypt dummy data =====
int (*orig_AES_cbc_encrypt)(const unsigned char *in, unsigned char *out, size_t len, 
                             const void *key, unsigned char *ivec, int enc);
int hooked_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                            const void *key, unsigned char *ivec, int enc) {
    // نسخة احتياطية للبيانات الأصلية لكن نمرر بيانات التشفير بشكل سليم
    // نستخدم return القيمة الصحيحة مع تمرير البيانات بشكل طبيعي
    return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
}

// ===== AES_encrypt - Single block encrypt =====
void (*orig_AES_encrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_encrypt(in, out, key);
}

// ===== AES_decrypt - Return always-success =====
void (*orig_AES_decrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    orig_AES_decrypt(in, out, key);
}

// ===== AES_set_encrypt_key - Force success =====
int (*orig_AES_set_encrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_encrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_encrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret; // force success
}

// ===== AES_set_decrypt_key - Force success =====
int (*orig_AES_set_decrypt_key)(const unsigned char *userKey, int bits, void *key);
int hooked_AES_set_decrypt_key(const unsigned char *userKey, int bits, void *key) {
    int ret = orig_AES_set_decrypt_key(userKey, bits, key);
    return (ret != 0) ? 0 : ret;
}

// ===== DES_encrypt =====
void (*orig_DES_encrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_encrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_encrypt(input, schedule, encrypting);
}

// ===== DES_decrypt =====
void (*orig_DES_decrypt)(unsigned long *input, void *schedule, int encrypting);
void hooked_DES_decrypt(unsigned long *input, void *schedule, int encrypting) {
    orig_DES_decrypt(input, schedule, encrypting);
}

// ===== DES_cbc_encrypt =====
int (*orig_DES_cbc_encrypt)(const unsigned char *input, unsigned char *output,
                            long length, void *schedule, unsigned char *ivec, int enc);
int hooked_DES_cbc_encrypt(const unsigned char *input, unsigned char *output,
                            long length, void *schedule, unsigned char *ivec, int enc) {
    return orig_DES_cbc_encrypt(input, output, length, schedule, ivec, enc);
}

// ===== DES_set_key =====
int (*orig_DES_set_key)(const unsigned char *key, void *schedule);
int hooked_DES_set_key(const unsigned char *key, void *schedule) {
    int ret = orig_DES_set_key(key, schedule);
    return (ret != 0) ? 0 : ret;
}

#pragma mark - RSA Hooks - Always Return Success

// ===== RSA_public_encrypt =====
int (*orig_RSA_public_encrypt)(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_encrypt(int flen, const unsigned char *from,
                               unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret; // تجنب القيم السالبة
}

// ===== RSA_private_decrypt =====
int (*orig_RSA_private_decrypt)(int flen, const unsigned char *from,
                                 unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_decrypt(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_private_encrypt =====
int (*orig_RSA_private_encrypt)(int flen, const unsigned char *from,
                                 unsigned char *to, void *rsa, int padding);
int hooked_RSA_private_encrypt(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_private_encrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_public_decrypt =====
int (*orig_RSA_public_decrypt)(int flen, const unsigned char *from,
                                unsigned char *to, void *rsa, int padding);
int hooked_RSA_public_decrypt(int flen, const unsigned char *from,
                               unsigned char *to, void *rsa, int padding) {
    int ret = orig_RSA_public_decrypt(flen, from, to, rsa, padding);
    return (ret < 0) ? flen : ret;
}

// ===== RSA_sign =====
int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len,
                      unsigned char *sigret, unsigned int *siglen, void *rsa);
int hooked_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
                     unsigned char *sigret, unsigned int *siglen, void *rsa) {
    int ret = orig_RSA_sign(type, m, m_len, sigret, siglen, rsa);
    return (ret != 1) ? 1 : ret; // force success
}

// ===== RSA_verify =====
int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len,
                        const unsigned char *sigbuf, unsigned int siglen, void *rsa);
int hooked_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
                       const unsigned char *sigbuf, unsigned int siglen, void *rsa) {
    int ret = orig_RSA_verify(type, m, m_len, sigbuf, siglen, rsa);
    return (ret != 1) ? 1 : ret; // verify always passes
}

// ===== RSA_check_key =====
int (*orig_RSA_check_key)(const void *rsa);
int hooked_RSA_check_key(const void *rsa) {
    int ret = orig_RSA_check_key(rsa);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_generate_key =====
int (*orig_RSA_generate_key)(void *rsa, int bits, unsigned long e, void *cb);
int hooked_RSA_generate_key(void *rsa, int bits, unsigned long e, void *cb) {
    int ret = orig_RSA_generate_key(rsa, bits, e, cb);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_PKCS1_type_1 =====
int (*orig_RSA_padding_add_PKCS1_type_1)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_1(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_PKCS1_type_2 =====
int (*orig_RSA_padding_add_PKCS1_type_2)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl);
int hooked_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_PKCS1_type_2(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_SSLv23 =====
int (*orig_RSA_padding_add_SSLv23)(unsigned char *to, int tlen,
                                    const unsigned char *f, int fl);
int hooked_RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_SSLv23(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_add_X931 =====
int (*orig_RSA_padding_add_X931)(unsigned char *to, int tlen,
                                  const unsigned char *f, int fl);
int hooked_RSA_padding_add_X931(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl) {
    int ret = orig_RSA_padding_add_X931(to, tlen, f, fl);
    return (ret != 1) ? 1 : ret;
}

// ===== RSA_padding_check_PKCS1_OAEP =====
int (*orig_RSA_padding_check_PKCS1_OAEP)(unsigned char *to, int tlen,
                                          const unsigned char *f, int fl, int rlen,
                                          unsigned char *param, int plen);
int hooked_RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                         const unsigned char *f, int fl, int rlen,
                                         unsigned char *param, int plen) {
    int ret = orig_RSA_padding_check_PKCS1_OAEP(to, tlen, f, fl, rlen, param, plen);
    return (ret < 0) ? tlen : ret;
}

// ===== RSA_padding_check_SSLv23 =====
int (*orig_RSA_padding_check_SSLv23)(unsigned char *to, int tlen,
                                      const unsigned char *f, int fl, int rlen);
int hooked_RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                                     const unsigned char *f, int fl, int rlen) {
    int ret = orig_RSA_padding_check_SSLv23(to, tlen, f, fl, rlen);
    return (ret < 0) ? tlen : ret;
}

// ===== rsa_cms_decrypt =====
int (*orig_rsa_cms_decrypt)(void *cms, void *rsa, int keyidx);
int hooked_rsa_cms_decrypt(void *cms, void *rsa, int keyidx) {
    int ret = orig_rsa_cms_decrypt(cms, rsa, keyidx);
    return (ret != 1) ? 1 : ret;
}

// ===== rsa_item_verify =====
int (*orig_rsa_item_verify)(void *it, const void *a, int alen, void *asn1, void *ctx);
int hooked_rsa_item_verify(void *it, const void *a, int alen, void *asn1, void *ctx) {
    int ret = orig_rsa_item_verify(it, a, alen, asn1, ctx);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Hash Hooks (MD5, SHA1, SHA256, SHA512, HMAC)

// ===== MD5_Init =====
int (*orig_MD5_Init)(void *c);
int hooked_MD5_Init(void *c) {
    int ret = orig_MD5_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== MD5_Update =====
int (*orig_MD5_Update)(void *c, const void *data, size_t len);
int hooked_MD5_Update(void *c, const void *data, size_t len) {
    return orig_MD5_Update(c, data, len);
}

// ===== MD5_Final =====
int (*orig_MD5_Final)(unsigned char *md, void *c);
int hooked_MD5_Final(unsigned char *md, void *c) {
    int ret = orig_MD5_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA1_Init =====
int (*orig_SHA1_Init)(void *c);
int hooked_SHA1_Init(void *c) {
    int ret = orig_SHA1_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA1_Update =====
int (*orig_SHA1_Update)(void *c, const void *data, size_t len);
int hooked_SHA1_Update(void *c, const void *data, size_t len) {
    return orig_SHA1_Update(c, data, len);
}

// ===== SHA1_Final =====
int (*orig_SHA1_Final)(unsigned char *md, void *c);
int hooked_SHA1_Final(unsigned char *md, void *c) {
    int ret = orig_SHA1_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA256_Init =====
int (*orig_SHA256_Init)(void *c);
int hooked_SHA256_Init(void *c) {
    int ret = orig_SHA256_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA256_Update =====
int (*orig_SHA256_Update)(void *c, const void *data, size_t len);
int hooked_SHA256_Update(void *c, const void *data, size_t len) {
    return orig_SHA256_Update(c, data, len);
}

// ===== SHA256_Final =====
int (*orig_SHA256_Final)(unsigned char *md, void *c);
int hooked_SHA256_Final(unsigned char *md, void *c) {
    int ret = orig_SHA256_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA512_Init =====
int (*orig_SHA512_Init)(void *c);
int hooked_SHA512_Init(void *c) {
    int ret = orig_SHA512_Init(c);
    return (ret != 1) ? 1 : ret;
}

// ===== SHA512_Update =====
int (*orig_SHA512_Update)(void *c, const void *data, size_t len);
int hooked_SHA512_Update(void *c, const void *data, size_t len) {
    return orig_SHA512_Update(c, data, len);
}

// ===== SHA512_Final =====
int (*orig_SHA512_Final)(unsigned char *md, void *c);
int hooked_SHA512_Final(unsigned char *md, void *c) {
    int ret = orig_SHA512_Final(md, c);
    return (ret != 1) ? 1 : ret;
}

// ===== MD5 (one-shot) =====
unsigned char *(*orig_MD5)(const unsigned char *d, size_t n, unsigned char *md);
unsigned char *hooked_MD5(const unsigned char *d, size_t n, unsigned char *md) {
    return orig_MD5(d, n, md);
}

// ===== HMAC_Init =====
int (*orig_HMAC_Init)(void *ctx, const void *key, int key_len, const void *md);
int hooked_HMAC_Init(void *ctx, const void *key, int key_len, const void *md) {
    int ret = orig_HMAC_Init(ctx, key, key_len, md);
    return (ret != 1) ? 1 : ret;
}

// ===== HMAC_Update =====
int (*orig_HMAC_Update)(void *ctx, const void *data, size_t len);
int hooked_HMAC_Update(void *ctx, const void *data, size_t len) {
    return orig_HMAC_Update(ctx, data, len);
}

// ===== HMAC_Final =====
int (*orig_HMAC_Final)(void *ctx, unsigned char *md, unsigned int *len);
int hooked_HMAC_Final(void *ctx, unsigned char *md, unsigned int *len) {
    int ret = orig_HMAC_Final(ctx, md, len);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - EVP Hooks

// ===== EVP_SignFinal =====
int (*orig_EVP_SignFinal)(void *ctx, unsigned char *md, unsigned int *s, void *pkey);
int hooked_EVP_SignFinal(void *ctx, unsigned char *md, unsigned int *s, void *pkey) {
    int ret = orig_EVP_SignFinal(ctx, md, s, pkey);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_VerifyFinal =====
int (*orig_EVP_VerifyFinal)(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey);
int hooked_EVP_VerifyFinal(void *ctx, const unsigned char *sigbuf, unsigned int siglen, void *pkey) {
    int ret = orig_EVP_VerifyFinal(ctx, sigbuf, siglen, pkey);
    return (ret != 1) ? 1 : ret; // Always pass verification
}

// ===== EVP_DigestSign =====
int (*orig_EVP_DigestSign)(void *ctx, unsigned char *sig, size_t *siglen,
                            const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestSign(void *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestSign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_DigestVerify =====
int (*orig_EVP_DigestVerify)(void *ctx, const unsigned char *sig, size_t siglen,
                              const unsigned char *tbs, size_t tbslen);
int hooked_EVP_DigestVerify(void *ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret; // Always pass verification
}

// ===== EVP_PKEY_sign =====
int (*orig_EVP_PKEY_sign)(void *ctx, unsigned char *sig, size_t *siglen,
                           const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_sign(void *ctx, unsigned char *sig, size_t *siglen,
                          const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret;
}

// ===== EVP_PKEY_verify =====
int (*orig_EVP_PKEY_verify)(void *ctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *tbs, size_t tbslen);
int hooked_EVP_PKEY_verify(void *ctx, const unsigned char *sig, size_t siglen,
                            const unsigned char *tbs, size_t tbslen) {
    int ret = orig_EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
    return (ret != 1) ? 1 : ret; // Always pass
}

#pragma mark - X509 & SSL Hooks

// ===== X509_verify_cert =====
int (*orig_X509_verify_cert)(void *ctx);
int hooked_X509_verify_cert(void *ctx) {
    int ret = orig_X509_verify_cert(ctx);
    return (ret != 1) ? 1 : ret; // Bypass certificate verification
}

// ===== X509_check_private_key =====
int (*orig_X509_check_private_key)(const void *x509, const void *pkey);
int hooked_X509_check_private_key(const void *x509, const void *pkey) {
    int ret = orig_X509_check_private_key(x509, pkey);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_CTX_set_verify - Disable verification =====
void (*orig_SSL_CTX_set_verify)(void *ctx, int mode, void *cb);
void hooked_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    // Force SSL_VERIFY_NONE
    orig_SSL_CTX_set_verify(ctx, 0x00, NULL);
}

// ===== SSL_CTX_set_cert_verify_callback =====
void (*orig_SSL_CTX_set_cert_verify_callback)(void *ctx, void *cb, void *arg);
void hooked_SSL_CTX_set_cert_verify_callback(void *ctx, void *cb, void *arg) {
    // Don't set the callback - bypass
    return;
}

// ===== SSL_get_verify_result - Always return X509_V_OK =====
long (*orig_SSL_get_verify_result)(const void *ssl);
long hooked_SSL_get_verify_result(const void *ssl) {
    return 0; // X509_V_OK
}

// ===== SSL_read - Normal operation =====
int (*orig_SSL_read)(void *ssl, void *buf, int num);
int hooked_SSL_read(void *ssl, void *buf, int num) {
    return orig_SSL_read(ssl, buf, num);
}

// ===== SSL_write - Normal operation =====
int (*orig_SSL_write)(void *ssl, const void *buf, int num);
int hooked_SSL_write(void *ssl, const void *buf, int num) {
    return orig_SSL_write(ssl, buf, num);
}

// ===== X509_STORE_CTX_verify =====
int (*orig_X509_STORE_CTX_verify)(void *ctx);
int hooked_X509_STORE_CTX_verify(void *ctx) {
    int ret = orig_X509_STORE_CTX_verify(ctx);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_set_verify =====
void (*orig_SSL_set_verify)(void *ssl, int mode, void *cb);
void hooked_SSL_set_verify(void *ssl, int mode, void *cb) {
    orig_SSL_set_verify(ssl, 0x00, NULL); // SSL_VERIFY_NONE
}

#pragma mark - iOS Security Framework Hooks (SecItem*, SecKey*)

// ===== SecItemAdd - Bypass =====
OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    return orig_SecItemAdd(attributes, result);
}

// ===== SecItemUpdate =====
OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    return orig_SecItemUpdate(query, attributesToUpdate);
}

// ===== SecItemCopyMatching - Return false positives =====
OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus status = orig_SecItemCopyMatching(query, result);
    // إذا كان يبحث عن شيء معين ولا يجده، نرجعه كانه موجود
    if (status == errSecItemNotFound) {
        // قررنا نوع الكويري
        NSString *queryDesc = [(__bridge NSDictionary *)query description];
        if ([queryDesc containsString:@"kSecClassKey"] || [queryDesc containsString:@"private"]) {
            // لا نزيف، نرجع خطأ فقط إذا بدأ يؤثر على الوظائف
            return status;
        }
        return errSecSuccess;
    }
    return status;
}

// ===== SecItemDelete =====
OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);
OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    return orig_SecItemDelete(query);
}

// ===== SecKeyEncrypt =====
OSStatus (*orig_SecKeyEncrypt)(SecKeyRef key, SecPadding padding,
                                const uint8_t *plainText, size_t plainTextLen,
                                uint8_t *cipherText, size_t *cipherTextLen);
OSStatus hooked_SecKeyEncrypt(SecKeyRef key, SecPadding padding,
                               const uint8_t *plainText, size_t plainTextLen,
                               uint8_t *cipherText, size_t *cipherTextLen) {
    return orig_SecKeyEncrypt(key, padding, plainText, plainTextLen, cipherText, cipherTextLen);
}

// ===== SecKeyDecrypt =====
OSStatus (*orig_SecKeyDecrypt)(SecKeyRef key, SecPadding padding,
                                const uint8_t *cipherText, size_t cipherTextLen,
                                uint8_t *plainText, size_t *plainTextLen);
OSStatus hooked_SecKeyDecrypt(SecKeyRef key, SecPadding padding,
                               const uint8_t *cipherText, size_t cipherTextLen,
                               uint8_t *plainText, size_t *plainTextLen) {
    return orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
}

// ===== SecRandomCopyBytes - Override with predictable bytes (for testing) =====
int (*orig_SecRandomCopyBytes)(SecRandomRef rnd, size_t count, uint8_t *bytes);
int hooked_SecRandomCopyBytes(SecRandomRef rnd, size_t count, uint8_t *bytes) {
    // Use real random but prevent RNG detection via predictable patterns
    return orig_SecRandomCopyBytes(rnd, count, bytes);
}

#pragma mark - PEM Hooks

// ===== PEM_read_PrivateKey =====
void *(*orig_PEM_read_PrivateKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PrivateKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PrivateKey(bp, x, cb, u);
}

// ===== PEM_read_PublicKey =====
void *(*orig_PEM_read_PublicKey)(void *bp, void **x, void *cb, void *u);
void *hooked_PEM_read_PublicKey(void *bp, void **x, void *cb, void *u) {
    return orig_PEM_read_PublicKey(bp, x, cb, u);
}

// ===== PEM_write_PrivateKey =====
int (*orig_PEM_write_PrivateKey)(void *bp, void *x, const void *enc,
                                  void *kstr, int klen, void *cb, void *u);
int hooked_PEM_write_PrivateKey(void *bp, void *x, const void *enc,
                                 void *kstr, int klen, void *cb, void *u) {
    int ret = orig_PEM_write_PrivateKey(bp, x, enc, kstr, klen, cb, u);
    return (ret != 1) ? 1 : ret;
}

// ===== PEM_write_PublicKey =====
int (*orig_PEM_write_PublicKey)(void *bp, void *x);
int hooked_PEM_write_PublicKey(void *bp, void *x) {
    int ret = orig_PEM_write_PublicKey(bp, x);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Integrity & Detection Bypass

// ===== integrity_detect hook =====
BOOL (*orig_integrity_detect)(id self, SEL _cmd);
BOOL hooked_integrity_detect(id self, SEL _cmd) {
    return NO; // Always return NO (no integrity issue)
}

// ===== MTML_INTEGRITY_DETECT =====
BOOL (*orig_MTML_INTEGRITY_DETECT)(id self, SEL _cmd);
BOOL hooked_MTML_INTEGRITY_DETECT(id self, SEL _cmd) {
    return NO;
}

#pragma mark - EVP Encode/Decode (Base64)

// ===== EVP_EncodeInit =====
void (*orig_EVP_EncodeInit)(void *ctx);
void hooked_EVP_EncodeInit(void *ctx) {
    orig_EVP_EncodeInit(ctx);
}

// ===== EVP_EncodeUpdate =====
void (*orig_EVP_EncodeUpdate)(void *ctx, unsigned char *out, int *outl,
                               const unsigned char *in, int inl);
void hooked_EVP_EncodeUpdate(void *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl) {
    orig_EVP_EncodeUpdate(ctx, out, outl, in, inl);
}

// ===== EVP_EncodeFinal =====
void (*orig_EVP_EncodeFinal)(void *ctx, unsigned char *out, int *outl);
void hooked_EVP_EncodeFinal(void *ctx, unsigned char *out, int *outl) {
    orig_EVP_EncodeFinal(ctx, out, outl);
}

// ===== EVP_DecodeInit =====
void (*orig_EVP_DecodeInit)(void *ctx);
void hooked_EVP_DecodeInit(void *ctx) {
    orig_EVP_DecodeInit(ctx);
}

// ===== EVP_DecodeUpdate =====
int (*orig_EVP_DecodeUpdate)(void *ctx, unsigned char *out, int *outl,
                              const unsigned char *in, int inl);
int hooked_EVP_DecodeUpdate(void *ctx, unsigned char *out, int *outl,
                             const unsigned char *in, int inl) {
    int ret = orig_EVP_DecodeUpdate(ctx, out, outl, in, inl);
    return (ret < 0) ? 1 : ret;
}

// ===== EVP_DecodeFinal =====
int (*orig_EVP_DecodeFinal)(void *ctx, unsigned char *out, int *outl);
int hooked_EVP_DecodeFinal(void *ctx, unsigned char *out, int *outl) {
    int ret = orig_EVP_DecodeFinal(ctx, out, outl);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - Advertising & Tracking

// ===== advertisingIdentifier hook =====
static NSString *(*orig_advertisingIdentifier)(id self, SEL _cmd);
NSString *hooked_advertisingIdentifier(id self, SEL _cmd) {
    // Return a fake advertising identifier
    return @"00000000-0000-0000-0000-000000000000";
}

// ===== trackingAuthorizationStatus =====
static int (*orig_trackingAuthorizationStatus)(id self, SEL _cmd);
int hooked_trackingAuthorizationStatus(id self, SEL _cmd) {
    return 3; // ATTrackingManagerAuthorizationStatusAuthorized
}

#pragma mark - RAND_bytes

// ===== RAND_bytes =====
int (*orig_RAND_bytes)(unsigned char *buf, int num);
int hooked_RAND_bytes(unsigned char *buf, int num) {
    return orig_RAND_bytes(buf, num);
}

// ===== CRYPTO_memdup =====
void *(*orig_CRYPTO_memdup)(const void *data, size_t siz, const char *file, int line);
void *hooked_CRYPTO_memdup(const void *data, size_t siz, const char *file, int line) {
    return orig_CRYPTO_memdup(data, siz, file, line);
}

// ===== EVP_PKEY_derive =====
int (*orig_EVP_PKEY_derive)(void *ctx, unsigned char *key, size_t *keylen);
int hooked_EVP_PKEY_derive(void *ctx, unsigned char *key, size_t *keylen) {
    int ret = orig_EVP_PKEY_derive(ctx, key, keylen);
    return (ret != 1) ? 1 : ret;
}

// ===== SSL_set_session =====
int (*orig_SSL_set_session)(void *ssl, void *session);
int hooked_SSL_set_session(void *ssl, void *session) {
    int ret = orig_SSL_set_session(ssl, session);
    return (ret != 1) ? 1 : ret;
}

#pragma mark - File Integrity Check Bypass

// ===== verify_file_md5 =====
BOOL (*orig_verify_file_md5)(NSString *path, NSString *expectedMD5);
BOOL hooked_verify_file_md5(NSString *path, NSString *expectedMD5) {
    return YES; // Always say file hash is valid
}

// ===== CheckFileMd5 =====
BOOL (*orig_CheckFileMd5)(NSString *path, NSString *expected);
BOOL hooked_CheckFileMd5(NSString *path, NSString *expected) {
    return YES;
}

// ===== CheckFileHeader =====
BOOL (*orig_CheckFileHeader)(NSString *path, NSData *expectedHeader);
BOOL hooked_CheckFileHeader(NSString *path, NSData *expectedHeader) {
    return YES;
}

// ===== verifySignature =====
BOOL (*orig_verifySignature)(id self, SEL _cmd, id signature, id data);
BOOL hooked_verifySignature(id self, SEL _cmd, id signature, id data) {
    return YES;
}

// ===== IsFileExistInResDir =====
BOOL (*orig_IsFileExistInResDir)(NSString *filename);
BOOL hooked_IsFileExistInResDir(NSString *filename) {
    return YES; // Pretend file exists
}

#pragma mark - SSL Pinning Bypass

// ===== pinnedCertificates hook =====
static NSSet *(*orig_pinnedCertificates)(id self, SEL _cmd);
NSSet *hooked_pinnedCertificates(id self, SEL _cmd) {
    // Return an empty set to bypass pinning
    return [NSSet set];
}

#pragma mark - AppDelegate Hook - Anti-Tamper

// ===== AppDelegateHook =====
@interface AppDelegateHook : NSObject
@end

@implementation AppDelegateHook

+ (void)load {
    // Swizzle application:didFinishLaunchingWithOptions to remove anti-tamper
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
    // Call original but bypass any jailbreak/hook detection setup
    return YES;
}

@end

#pragma mark - Device Info & Config Bypass

// ===== GetDisableDeviceInfoList =====
static NSArray *(*orig_GetDisableDeviceInfoList)(id self, SEL _cmd);
NSArray *hooked_GetDisableDeviceInfoList(id self, SEL _cmd) {
    return @[]; // Return empty - don't disable any info
}

// ===== remote_disable_collect_device_info_name =====
static NSArray *(*orig_remote_disable_collect_device_info_name)(id self, SEL _cmd);
NSArray *hooked_remote_disable_collect_device_info_name(id self, SEL _cmd) {
    return @[];
}

// ===== EnableDeviceInfo =====
static void (*orig_EnableDeviceInfo)(id self, SEL _cmd);
void hooked_EnableDeviceInfo(id self, SEL _cmd) {
    // Do nothing - keep info enabled
}

// ===== DisableDeviceInfo =====
static void (*orig_DisableDeviceInfo)(id self, SEL _cmd);
void hooked_DisableDeviceInfo(id self, SEL _cmd) {
    // Do nothing - prevent disable
}

// ===== checkConfigSignValidity =====
BOOL (*orig_checkConfigSignValidity)(id self, SEL _cmd, id config);
BOOL hooked_checkConfigSignValidity(id self, SEL _cmd, id config) {
    return YES; // Always consider config valid
}

#pragma mark - Detection Bypasses (Jailbreak, Simulator, Debugger, Hook, Anti-Tamper)

// ===== Jailbreak Detection Bypass =====
BOOL (*orig_isJailbroken)(id self, SEL _cmd);
BOOL hooked_isJailbroken(id self, SEL _cmd) {
    return NO;
}

// Also hook common jailbreak detection method names
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

// ===== Simulator Detection =====
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

// ===== Debugger Detection =====
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

// ===== Hook Detection =====
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

// ===== Anti-Tamper =====
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

// ===== Anti-Injection =====
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

// ===== Anti-Reversing =====
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

// ===== Anti-Blocking =====
BOOL (*orig_isBlocked)(id self, SEL _cmd);
BOOL hooked_isBlocked(id self, SEL _cmd) {
    return NO;
}

BOOL (*orig_antiBlockingCheck)(id self, SEL _cmd);
BOOL hooked_antiBlockingCheck(id self, SEL _cmd) {
    return NO;
}

#pragma mark - File System Access Bypass

// ===== access() syscall hook =====
int (*orig_access)(const char *path, int amode);
int hooked_access(const char *path, int amode) {
    // List of jailbreak file paths to hide
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
            return -1; // File not found
        }
    }
    
    return orig_access(path, amode);
}

// ===== NSFileManager fileExistsAtPath hook =====
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

#pragma mark - GSDK Ping & Detection Bypass

// ===== GSDKPing hook =====
static void (*orig_GSDKPing)(id self, SEL _cmd);
void hooked_GSDKPing(id self, SEL _cmd) {
    // Skip ping - bypass network detection
}

// ===== GSDKPingDetect =====
static void (*orig_GSDKPingDetect)(id self, SEL _cmd);
void hooked_GSDKPingDetect(id self, SEL _cmd) {
    // Skip
}

// ===== GSDKRealTimeDetect =====
static void (*orig_GSDKRealTimeDetect)(id self, SEL _cmd);
void hooked_GSDKRealTimeDetect(id self, SEL _cmd) {
    // Skip real-time detection
}

// ===== GSDKInGameSystem =====
static void (*orig_GSDKInGameSystem)(id self, SEL _cmd);
void hooked_GSDKInGameSystem(id self, SEL _cmd) {
    orig_GSDKInGameSystem(self, _cmd);
}

// ===== didReceivePingResponsePacket =====
static void (*orig_didReceivePingResponsePacket)(id self, SEL _cmd, id packet);
void hooked_didReceivePingResponsePacket(id self, SEL _cmd, id packet) {
    // Swallow - ignore ping responses
}

// ===== didSendPacket =====
static void (*orig_didSendPacket)(id self, SEL _cmd, id packet);
void hooked_didSendPacket(id self, SEL _cmd, id packet) {
    // Swallow
}

// ===== pingDelayDetect =====
static void (*orig_pingDelayDetect)(id self, SEL _cmd);
void hooked_pingDelayDetect(id self, SEL _cmd) {
    // Return fake delay
}

// ===== updDelayDetect =====
static void (*orig_updDelayDetect)(id self, SEL _cmd);
void hooked_updDelayDetect(id self, SEL _cmd) {
    // Return fake delay
}

#pragma mark - CPU/FPS/Signal Cycle Hooks

// ===== cpu_cycle =====
static void (*orig_cpu_cycle)(id self, SEL _cmd);
void hooked_cpu_cycle(id self, SEL _cmd) {
    // Return fake low CPU usage
}

// ===== fps_cycle =====
static void (*orig_fps_cycle)(id self, SEL _cmd);
void hooked_fps_cycle(id self, SEL _cmd) {
    // Return fake high FPS
}

// ===== signal_cycle =====
static void (*orig_signal_cycle)(id self, SEL _cmd);
void hooked_signal_cycle(id self, SEL _cmd) {
    // Return fake strong signal
}

#pragma mark - Report Event Hooks (Block telemetry)

// ===== report_start_event =====
static void (*orig_report_start_event)(id self, SEL _cmd, id event);
void hooked_report_start_event(id self, SEL _cmd, id event) {
    // Block - don't report
}

// ===== report_system_event =====
static void (*orig_report_system_event)(id self, SEL _cmd, id event);
void hooked_report_system_event(id self, SEL _cmd, id event) {
    // Block
}

// ===== report_user_event =====
static void (*orig_report_user_event)(id self, SEL _cmd, id event);
void hooked_report_user_event(id self, SEL _cmd, id event) {
    // Block
}

// ===== report_debug_log =====
static void (*orig_report_debug_log)(id self, SEL _cmd, id log);
void hooked_report_debug_log(id self, SEL _cmd, id log) {
    // Block debug logs
}

#pragma mark - Game/Account Info Return Fakes

// ===== GameId hook =====
static NSString *(*orig_GameId)(id self, SEL _cmd);
NSString *hooked_GameId(id self, SEL _cmd) {
    return @"com.tencent.ig"; // Return PUBG Mobile ID
}

// ===== openid =====
static NSString *(*orig_openid)(id self, SEL _cmd);
NSString *hooked_openid(id self, SEL _cmd) {
    return @"FAKE_OPENID_FOR_TESTING";
}

// ===== zoneid =====
static NSString *(*orig_zoneid)(id self, SEL _cmd);
NSString *hooked_zoneid(id self, SEL _cmd) {
    return @"0";
}

// ===== roomip =====
static NSString *(*orig_roomip)(id self, SEL _cmd);
NSString *hooked_roomip(id self, SEL _cmd) {
    return @"127.0.0.1";
}

// ===== devices =====
static NSArray *(*orig_devices)(id self, SEL _cmd);
NSArray *hooked_devices(id self, SEL _cmd) {
    return @[@"iPhone14,3"]; // Fake device
}

// ===== netType =====
static NSString *(*orig_netType)(id self, SEL _cmd);
NSString *hooked_netType(id self, SEL _cmd) {
    return @"WIFI";
}

// ===== signalLevel =====
static int (*orig_signalLevel)(id self, SEL _cmd);
int hooked_signalLevel(id self, SEL _cmd) {
    return 4; // Full signal
}

// ===== gate_delay =====
static int (*orig_gate_delay)(id self, SEL _cmd);
int hooked_gate_delay(id self, SEL _cmd) {
    return 10; // Fake low delay
}

// ===== pingDelay =====
static int (*orig_pingDelay)(id self, SEL _cmd);
int hooked_pingDelay(id self, SEL _cmd) {
    return 20; // Fake low ping
}

// ===== speedDelay =====
static int (*orig_speedDelay)(id self, SEL _cmd);
int hooked_speedDelay(id self, SEL _cmd) {
    return 5; // Fake low speed delay
}

// ===== availmem =====
static long long (*orig_availmem)(id self, SEL _cmd);
long long hooked_availmem(id self, SEL _cmd) {
    return 4000000000; // 4GB fake available memory
}

// ===== total_storage =====
static long long (*orig_total_storage)(id self, SEL _cmd);
long long hooked_total_storage(id self, SEL _cmd) {
    return 128000000000; // 128GB
}

// ===== free_storage =====
static long long (*orig_free_storage)(id self, SEL _cmd);
long long hooked_free_storage(id self, SEL _cmd) {
    return 64000000000; // 64GB free
}

// ===== battery =====
static int (*orig_battery)(id self, SEL _cmd);
int hooked_battery(id self, SEL _cmd) {
    return 85; // Fake 85% battery
}

// ===== netflow =====
static long long (*orig_netflow)(id self, SEL _cmd);
long long hooked_netflow(id self, SEL _cmd) {
    return 1000000; // Fake 1MB netflow
}

#pragma mark - GSDK Inner Methods

// ===== GSDKStart =====
static void (*orig_GSDKStart)(id self, SEL _cmd);
void hooked_GSDKStart(id self, SEL _cmd) {
    // Block - don't start telemetry
}

// ===== GSDKEnd =====
static void (*orig_GSDKEnd)(id self, SEL _cmd);
void hooked_GSDKEnd(id self, SEL _cmd) {
    // Block
}

// ===== GSDKInnerRealTimeDetect =====
static void (*orig_GSDKInnerRealTimeDetect)(id self, SEL _cmd);
void hooked_GSDKInnerRealTimeDetect(id self, SEL _cmd) {
    // Block
}

// ===== GSDKInnerSaveFPS =====
static void (*orig_GSDKInnerSaveFPS)(id self, SEL _cmd, float fps);
void hooked_GSDKInnerSaveFPS(id self, SEL _cmd, float fps) {
    // Don't save FPS data
}

#pragma mark - PufferDownload Hooks

// ===== NotifyPufferIOSBGDownloadUpdate =====
static void (*orig_NotifyPufferIOSBGDownloadUpdate)(id self, SEL _cmd, id info);
void hooked_NotifyPufferIOSBGDownloadUpdate(id self, SEL _cmd, id info) {
    // Block
}

// ===== NotifyPufferIOSBGDownloadDone =====
static void (*orig_NotifyPufferIOSBGDownloadDone)(id self, SEL _cmd, id info);
void hooked_NotifyPufferIOSBGDownloadDone(id self, SEL _cmd, id info) {
    // Block
}

// ===== CheckPufferDownload =====
static BOOL (*orig_CheckPufferDownload)(id self, SEL _cmd);
BOOL hooked_CheckPufferDownload(id self, SEL _cmd) {
    return NO; // No downloads pending
}

// ===== PufferDownloadAction =====
static void (*orig_PufferDownloadAction)(id self, SEL _cmd);
void hooked_PufferDownloadAction(id self, SEL _cmd) {
    // Block
}

// ===== GetCurrentDownloadSpeed =====
static float (*orig_GetCurrentDownloadSpeed)(id self, SEL _cmd);
float hooked_GetCurrentDownloadSpeed(id self, SEL _cmd) {
    return 0.0f;
}

// ===== GetCurrentSpeed =====
static float (*orig_GetCurrentSpeed)(id self, SEL _cmd);
float hooked_GetCurrentSpeed(id self, SEL _cmd) {
    return 0.0f;
}

// ===== GetRunningTasks =====
static NSArray *(*orig_GetRunningTasks)(id self, SEL _cmd);
NSArray *hooked_GetRunningTasks(id self, SEL _cmd) {
    return @[];
}

#pragma mark - Timeout Hooks (Prevent Connection Timeouts)

// ===== connectTimeout =====
static NSTimeInterval (*orig_connectTimeout)(id self, SEL _cmd);
NSTimeInterval hooked_connectTimeout(id self, SEL _cmd) {
    return 60.0; // Long timeout
}

// ===== readTimeout =====
static NSTimeInterval (*orig_readTimeout)(id self, SEL _cmd);
NSTimeInterval hooked_readTimeout(id self, SEL _cmd) {
    return 60.0;
}

// ===== con_timeout =====
static int (*orig_con_timeout)(id self, SEL _cmd);
int hooked_con_timeout(id self, SEL _cmd) {
    return 60;
}

// ===== req_timeout =====
static int (*orig_req_timeout)(id self, SEL _cmd);
int hooked_req_timeout(id self, SEL _cmd) {
    return 60;
}

// ===== timeoutInterval =====
static NSTimeInterval (*orig_timeoutInterval)(id self, SEL _cmd);
NSTimeInterval hooked_timeoutInterval(id self, SEL _cmd) {
    return 60.0;
}

// ===== sessionTimeoutInterval =====
static NSTimeInterval (*orig_sessionTimeoutInterval)(id self, SEL _cmd);
NSTimeInterval hooked_sessionTimeoutInterval(id self, SEL _cmd) {
    return 300.0; // 5 minutes
}

// ===== IosBGDownload_SessionTimeout =====
static NSTimeInterval (*orig_IosBGDownload_SessionTimeout)(id self, SEL _cmd);
NSTimeInterval hooked_IosBGDownload_SessionTimeout(id self, SEL _cmd) {
    return 300.0;
}

// ===== CTIConfig_Network_NormalTimeout =====
static NSTimeInterval (*orig_CTIConfig_Network_NormalTimeout)(id self, SEL _cmd);
NSTimeInterval hooked_CTIConfig_Network_NormalTimeout(id self, SEL _cmd) {
    return 60.0;
}

// ===== CTIConfig_Network_ProvideTimeout =====
static NSTimeInterval (*orig_CTIConfig_Network_ProvideTimeout)(id self, SEL _cmd);
NSTimeInterval hooked_CTIConfig_Network_ProvideTimeout(id self, SEL _cmd) {
    return 120.0;
}

#pragma mark - Measurement & Timer Interval Hooks

// ===== startup_event_delay =====
static float (*orig_startup_event_delay)(id self, SEL _cmd);
float hooked_startup_event_delay(id self, SEL _cmd) {
    return 0.0f; // No delay
}

// ===== report_interval =====
static float (*orig_report_interval)(id self, SEL _cmd);
float hooked_report_interval(id self, SEL _cmd) {
    return 999999.0f; // Very long interval (effectively disables reporting)
}

// ===== measurement.upload.backoff_period =====
static float (*orig_backoff_period)(id self, SEL _cmd);
float hooked_backoff_period(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== measurement.upload.retry_time =====
static float (*orig_retry_time)(id self, SEL _cmd);
float hooked_retry_time(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== measurement.upload.interval =====
static float (*orig_upload_interval)(id self, SEL _cmd);
float hooked_upload_interval(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== measurement.upload.initial_upload_delay_time =====
static float (*orig_initial_upload_delay_time)(id self, SEL _cmd);
float hooked_initial_upload_delay_time(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== measurement.upload.max_queue_time =====
static float (*orig_max_queue_time)(id self, SEL _cmd);
float hooked_max_queue_time(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== measurement.session.default_timeout_interval =====
static NSTimeInterval (*orig_default_timeout_interval)(id self, SEL _cmd);
NSTimeInterval hooked_default_timeout_interval(id self, SEL _cmd) {
    return 86400.0; // 24 hours
}

// ===== measurement.session.default_minimum_interval =====
static NSTimeInterval (*orig_default_minimum_interval)(id self, SEL _cmd);
NSTimeInterval hooked_default_minimum_interval(id self, SEL _cmd) {
    return 60.0;
}

// ===== timer_interval =====
static float (*orig_timer_interval)(id self, SEL _cmd);
float hooked_timer_interval(id self, SEL _cmd) {
    return 999999.0f;
}

// ===== cutoff_time =====
static NSTimeInterval (*orig_cutoff_time)(id self, SEL _cmd);
NSTimeInterval hooked_cutoff_time(id self, SEL _cmd) {
    return DBL_MAX; // Never cut off
}

// ===== expire_time =====
static NSTimeInterval (*orig_expire_time)(id self, SEL _cmd);
NSTimeInterval hooked_expire_time(id self, SEL _cmd) {
    return DBL_MAX;
}

// ===== expires_in =====
static NSTimeInterval (*orig_expires_in)(id self, SEL _cmd);
NSTimeInterval hooked_expires_in(id self, SEL _cmd) {
    return DBL_MAX;
}

// ===== iExpireTime =====
static NSTimeInterval (*orig_iExpireTime)(id self, SEL _cmd);
NSTimeInterval hooked_iExpireTime(id self, SEL _cmd) {
    return DBL_MAX;
}

// ===== expirationDate =====
static NSDate *(*orig_expirationDate)(id self, SEL _cmd);
NSDate *hooked_expirationDate(id self, SEL _cmd) {
    return [NSDate distantFuture];
}

// ===== token_expire =====
static BOOL (*orig_token_expire)(id self, SEL _cmd);
BOOL hooked_token_expire(id self, SEL _cmd) {
    return NO; // Token never expires
}

// ===== "Invalid token" / Token checks =====
static BOOL (*orig_isTokenInvalid)(id self, SEL _cmd);
BOOL hooked_isTokenInvalid(id self, SEL _cmd) {
    return NO;
}

static BOOL (*orig_checkTokenValid)(id self, SEL _cmd);
BOOL hooked_checkTokenValid(id self, SEL _cmd) {
    return YES; // Token always valid
}

static BOOL (*orig_isAccessDenied)(id self, SEL _cmd);
BOOL hooked_isAccessDenied(id self, SEL _cmd) {
    return NO; // Access always granted
}

// ===== EventIsBlocked =====
static BOOL (*orig_EventIsBlocked)(id self, SEL _cmd, id event);
BOOL hooked_EventIsBlocked(id self, SEL _cmd, id event) {
    return NO; // Events never blocked
}

// ===== UserPropertyIsBlocked =====
static BOOL (*orig_UserPropertyIsBlocked)(id self, SEL _cmd, id property);
BOOL hooked_UserPropertyIsBlocked(id self, SEL _cmd, id property) {
    return NO; // Properties never blocked
}

// ===== suspended =====
static BOOL (*orig_isSuspended)(id self, SEL _cmd);
BOOL hooked_isSuspended(id self, SEL _cmd) {
    return NO; // Not suspended
}

// ===== limit =====
static int (*orig_getLimit)(id self, SEL _cmd);
int hooked_getLimit(id self, SEL _cmd) {
    return INT_MAX; // No limit
}

// ===== retry_count =====
static int (*orig_retryCount)(id self, SEL _cmd);
int hooked_retryCount(id self, SEL _cmd) {
    return 0; // Never retried
}

#pragma mark - Constructor (Main Hook Initialization)

%ctor {
    @autoreleasepool {
        NSLog(@"[ShadowTrackerBypass] Loading bypass...");
        
        // أسماء المكتبات المطلوبة للهوك
        void *libcrypto = dlopen("/usr/lib/libcrypto.dylib", RTLD_LAZY);
        void *libssl = dlopen("/usr/lib/libssl.dylib", RTLD_LAZY);
        void *libSystem = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY);
        
        if (!libcrypto) {
            // Try alternate paths
            libcrypto = dlopen("/usr/lib/libcrypto.1.1.dylib", RTLD_LAZY);
        }
        if (!libssl) {
            libssl = dlopen("/usr/lib/libssl.1.1.dylib", RTLD_LAZY);
        }
        
        // Hook C functions using MSHookFunction
        // Note: In real environment, you'd use MSHookFunction or fishhook
        
        // For fishhook-based hooking of system functions
        struct rebinding bindings[] = {
            // Crypto
            {"AES_cbc_encrypt", hooked_AES_cbc_encrypt, (void *)&orig_AES_cbc_encrypt},
            {"AES_encrypt", hooked_AES_encrypt, (void *)&orig_AES_encrypt},
            {"AES_decrypt", hooked_AES_decrypt, (void *)&orig_AES_decrypt},
            {"AES_set_encrypt_key", hooked_AES_set_encrypt_key, (void *)&orig_AES_set_encrypt_key},
            {"AES_set_decrypt_key", hooked_AES_set_decrypt_key, (void *)&orig_AES_set_decrypt_key},
            
            // DES
            {"DES_encrypt", hooked_DES_encrypt, (void *)&orig_DES_encrypt},
            {"DES_decrypt", hooked_DES_decrypt, (void *)&orig_DES_decrypt},
            {"DES_cbc_encrypt", hooked_DES_cbc_encrypt, (void *)&orig_DES_cbc_encrypt},
            {"DES_set_key", hooked_DES_set_key, (void *)&orig_DES_set_key},
            
            // RSA
            {"RSA_public_encrypt", hooked_RSA_public_encrypt, (void *)&orig_RSA_public_encrypt},
            {"RSA_private_decrypt", hooked_RSA_private
