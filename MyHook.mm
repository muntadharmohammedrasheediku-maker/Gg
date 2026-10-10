// ShadowBypassXK.m
// iOS arm64 / arm64e — deployment target 13.0+
// Inject via sideloaded dylib (TrollStore, Sideloadly + Theos, AltStore + LC_LOAD_DYLIB patch,
// atau MSHook/XPF pada non-jailbreak via CoreTrust exploit bundle).
//
// Build:
//   theos:          $THEOS/bin/logos.pl untuk keep %ctor; atau compile .m ini sebagai .dylib
//   clang -dynamiclib: clang -arch arm64e -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -miphoneos-version-min=13.0 -fobjc-arc -O2 -dynamiclib ShadowBypassXK.m \
//        -framework Foundation -framework UIKit -framework Security -framework AdSupport \
//        -o ShadowBypassXK.dylib
//
// fishhook: git submodule add https://github.com/facebook/fishhook deps/fishhook
//           sertakan fishhook.c dalam target compile.
//
// *fishhook cuma bisa rebind symbol yg di-resolve via lazy binding di __DATA,__la_symbol_ptr —
//  symbol yg di-resolve saat load (non-lazy) harus di-hook pakai method swizzle atau XPF/MSHook.*

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <sys/ptrace.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <stdint.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#import "fishhook.h"

#pragma mark =========================================================
#pragma mark 0. LOGGING + GUARD
#pragma mark =========================================================

#define SBXK_LOG(fmt, ...) do { \
    NSLog(@"[SBXK] " fmt, ##__VA_ARGS__); \
} while (0)

static inline BOOL SBXK_HasClass(const char *name) {
    return name && objc_getClass(name) != Nil;
}

static inline BOOL SBXK_HasMetaClass(const char *name) {
    return name && objc_getMetaClass(name) != Nil;
}

#pragma mark =========================================================
#pragma mark 1. SWIZZLE ENGINE (instance + class method)
#pragma mark =========================================================

// Pasang implementasi baru untuk instance method (selector tdk dipanggil dulu = aman).
static void SBXK_HookInstanceMethod(const char *className,
                                    const char *selectorName,
                                    IMP newImp)
{
    Class cls = objc_getClass(className);
    if (!cls) { SBXK_LOG(@"skip cls (instance): %s", className); return; }
    SEL sel = sel_registerName(selectorName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) { SBXK_LOG(@"skip sel (instance): -[%s %s]", className, selectorName); return; }
    class_replaceMethod(cls, sel, newImp, method_getTypeEncoding(m));
}

// Pasang untuk class method (+ ...).
static void SBXK_HookClassMethod(const char *className,
                                 const char *selectorName,
                                 IMP newImp)
{
    Class meta = objc_getMetaClass(className);
    if (!meta) { SBXK_LOG(@"skip cls (class): %s", className); return; }
    SEL sel = sel_registerName(selectorName);
    Method m = class_getClassMethod(objc_getClass(className), sel);
    if (!m) { SBXK_LOG(@"skip sel (class): +[%s %s]", className, selectorName); return; }
    class_replaceMethod(meta, sel, newImp, method_getTypeEncoding(m));
}

// Helper macro — supaya install block tetap ringkas.
#define SBXK_HOOK_I(cls, sel) SBXK_HookInstanceMethod(#cls, sel, (IMP)SBXK_##cls##_##sel)
#define SBXK_HOOK_C(cls, sel) SBXK_HookClassMethod(#cls, sel, (IMP)SBXK_##cls##_##sel)

#pragma mark =========================================================
#pragma mark 2. FISHHOOK BINDINGS (lazy-bound C symbols)
#pragma mark =========================================================

// Kalau game compile pakai dlopen+RTLD_LAZY, fishhook kena. Kalau flat-linked di pre-main,
// fishhook miss → tetap ada swizzle fallback di atas.
// Semua original disimpan sebagai pointer.

// --- RSA ---
static int (*orig_RSA_public_encrypt)(int, const unsigned char *, unsigned char *, void *, int);
static int (*orig_RSA_private_decrypt)(int, const unsigned char *, unsigned char *, void *, int);
static int (*orig_RSA_private_encrypt)(int, const unsigned char *, unsigned char *, void *, int);
static int (*orig_RSA_public_decrypt)(int, const unsigned char *, unsigned char *, void *, int);
static int (*orig_RSA_sign)(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, void *);
static int (*orig_RSA_verify)(int, const unsigned char *, unsigned int, const unsigned char *, unsigned int, void *);
static int (*orig_RSA_check_key)(const void *);
static int (*orig_RSA_generate_key)(void *, int, unsigned long, void *);
static int (*orig_RSA_padding_add_PKCS1_type_1)(unsigned char *, int, const unsigned char *, int);
static int (*orig_RSA_padding_add_PKCS1_type_2)(unsigned char *, int, const unsigned char *, int);

// --- AES / DES ---
static int  (*orig_AES_set_encrypt_key)(const unsigned char *, int, void *);
static int  (*orig_AES_set_decrypt_key)(const unsigned char *, int, void *);
static void (*orig_AES_encrypt)(const unsigned char *, unsigned char *, const void *);
static void (*orig_AES_decrypt)(const unsigned char *, unsigned char *, const void *);
static int  (*orig_AES_cbc_encrypt)(const unsigned char *, unsigned char *, size_t, const void *, unsigned char *, int);
static void (*orig_DES_encrypt)(unsigned long *, void *, int);
static void (*orig_DES_decrypt)(unsigned long *, void *, int);
static int  (*orig_DES_cbc_encrypt)(const unsigned char *, unsigned char *, long, void *, unsigned char *, int);
static int  (*orig_DES_set_key)(const unsigned char *, void *);

// --- HASH (nama lama OpenSSL — masih ada symbol-nya di libcrypto) ---
static int  (*orig_MD5_Init)(void *);
static int  (*orig_MD5_Update)(void *, const void *, size_t);
static int  (*orig_MD5_Final)(unsigned char *, void *);
static int  (*orig_SHA1_Init)(void *);
static int  (*orig_SHA1_Update)(void *, const void *, size_t);
static int  (*orig_SHA1_Final)(unsigned char *, void *);
static int  (*orig_SHA256_Init)(void *);
static int  (*orig_SHA256_Update)(void *, const void *, size_t);
static int  (*orig_SHA256_Final)(unsigned char *, void *);
static int  (*orig_SHA512_Init)(void *);
static int  (*orig_SHA512_Update)(void *, const void *, size_t);
static int  (*orig_SHA512_Final)(unsigned char *, void *);
static int  (*orig_HMAC_Init)(void *, const void *, int, const void *);
static int  (*orig_HMAC_Update)(void *, const void *, size_t);
static int  (*orig_HMAC_Final)(void *, unsigned char *, unsigned int *);

// --- EVP / SSL / X509 ---
static int  (*orig_EVP_SignFinal)(void *, unsigned char *, unsigned int *, void *);
static int  (*orig_EVP_VerifyFinal)(void *, const unsigned char *, unsigned int, void *);
static int  (*orig_EVP_DigestSign)(void *, unsigned char *, size_t *, const unsigned char *, size_t);
static int  (*orig_EVP_DigestVerify)(void *, const unsigned char *, size_t, const unsigned char *, size_t);
static int  (*orig_X509_verify_cert)(void *);
static long (*orig_SSL_get_verify_result)(const void *);
static int  (*orig_SSL_CTX_set_verify)(void *, int, void *); // return type mungkin void di beberapa versi — kita panggil dgn aman
static void (*orig_SSL_set_verify)(void *, int, void *);

// --- RAND ---
static int (*orig_RAND_bytes)(unsigned char *, int);

#pragma mark =========================================================
#pragma mark 3. HOOK IMPLEMENTATIONS — CRYPTO
#pragma mark =========================================================

// Semua hook "succeed-always" pakai policy: jangan pernah mengembalikan kode error,
// jangan pernah menandai signature invalid, jangan pernah drop token.
// Ini yang bikin game lolos client-side verification tanpa balik ke server.

#define SBXK_FORCE_TRUE_I(fn)  int fn(__VA_ARGS__)

static int SBXK_RSA_public_encrypt(int flen, const unsigned char *from,
                                   unsigned char *to, void *rsa, int pad) {
    int r = orig_RSA_public_encrypt ? orig_RSA_public_encrypt(flen, from, to, rsa, pad) : flen;
    return (r < 0) ? flen : r;
}
static int SBXK_RSA_private_decrypt(int flen, const unsigned char *from,
                                    unsigned char *to, void *rsa, int pad) {
    int r = orig_RSA_private_decrypt ? orig_RSA_private_decrypt(flen, from, to, rsa, pad) : flen;
    return (r < 0) ? flen : r;
}
static int SBXK_RSA_private_encrypt(int flen, const unsigned char *from,
                                    unsigned char *to, void *rsa, int pad) {
    int r = orig_RSA_private_encrypt ? orig_RSA_private_encrypt(flen, from, to, rsa, pad) : flen;
    return (r < 0) ? flen : r;
}
static int SBXK_RSA_public_decrypt(int flen, const unsigned char *from,
                                   unsigned char *to, void *rsa, int pad) {
    int r = orig_RSA_public_decrypt ? orig_RSA_public_decrypt(flen, from, to, rsa, pad) : flen;
    return (r < 0) ? flen : r;
}
static int SBXK_RSA_sign(int type, const unsigned char *m, unsigned int m_len,
                         unsigned char *sig, unsigned int *siglen, void *rsa) {
    int r = orig_RSA_sign ? orig_RSA_sign(type, m, m_len, sig, siglen, rsa) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_verify(int type, const unsigned char *m, unsigned int m_len,
                           const unsigned char *sig, unsigned int siglen, void *rsa) {
    (void)orig_RSA_verify; // selalu pass
    return 1;
}
static int SBXK_RSA_check_key(const void *rsa) { (void)orig_RSA_check_key; (void)rsa; return 1; }
static int SBXK_RSA_generate_key(void *rsa, int bits, unsigned long e, void *cb) {
    int r = orig_RSA_generate_key ? orig_RSA_generate_key(rsa, bits, e, cb) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
                                              const unsigned char *f, int fl) {
    int r = orig_RSA_padding_add_PKCS1_type_1 ? orig_RSA_padding_add_PKCS1_type_1(to, tlen, f, fl) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
                                              const unsigned char *f, int fl) {
    int r = orig_RSA_padding_add_PKCS1_type_2 ? orig_RSA_padding_add_PKCS1_type_2(to, tlen, f, fl) : 1;
    return (r != 1) ? 1 : r;
}

static int SBXK_AES_set_encrypt_key(const unsigned char *k, int bits, void *key) {
    int r = orig_AES_set_encrypt_key ? orig_AES_set_encrypt_key(k, bits, key) : 0;
    return (r != 0) ? 0 : r;
}
static int SBXK_AES_set_decrypt_key(const unsigned char *k, int bits, void *key) {
    int r = orig_AES_set_decrypt_key ? orig_AES_set_decrypt_key(k, bits, key) : 0;
    return (r != 0) ? 0 : r;
}
static void SBXK_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (orig_AES_encrypt) orig_AES_encrypt(in, out, key);
    else memset(out, 0, 16);
}
static void SBXK_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (orig_AES_decrypt) orig_AES_decrypt(in, out, key);
    else memset(out, 0, 16);
}
static int SBXK_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                                const void *key, unsigned char *ivec, int enc) {
    if (orig_AES_cbc_encrypt) return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
    if (out && in && len) memcpy(out, in, len);
    return 1;
}
static void SBXK_DES_encrypt(unsigned long *in, void *sched, int enc) {
    if (orig_DES_encrypt) orig_DES_encrypt(in, sched, enc);
}
static void SBXK_DES_decrypt(unsigned long *in, void *sched, int enc) {
    if (orig_DES_decrypt) orig_DES_decrypt(in, sched, enc);
}
static int SBXK_DES_cbc_encrypt(const unsigned char *in, unsigned char *out, long len,
                                void *sched, unsigned char *ivec, int enc) {
    if (orig_DES_cbc_encrypt) return orig_DES_cbc_encrypt(in, out, len, sched, ivec, enc);
    if (out && in && len > 0) memcpy(out, in, (size_t)len);
    return 1;
}
static int SBXK_DES_set_key(const unsigned char *k, void *sched) {
    int r = orig_DES_set_key ? orig_DES_set_key(k, sched) : 0;
    return (r != 0) ? 0 : r;
}

static int SBXK_MD5_Init(void *c)    { int r = orig_MD5_Init ? orig_MD5_Init(c) : 1;             return (r != 1) ? 1 : r; }
static int SBXK_MD5_Update(void *c, const void *d, size_t n) { return orig_MD5_Update ? orig_MD5_Update(c, d, n) : 1; }
static int SBXK_MD5_Final(unsigned char *md, void *c) { int r = orig_MD5_Final ? orig_MD5_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA1_Init(void *c)   { int r = orig_SHA1_Init ? orig_SHA1_Init(c) : 1;           return (r != 1) ? 1 : r; }
static int SBXK_SHA1_Update(void *c, const void *d, size_t n) { return orig_SHA1_Update ? orig_SHA1_Update(c, d, n) : 1; }
static int SBXK_SHA1_Final(unsigned char *md, void *c) { int r = orig_SHA1_Final ? orig_SHA1_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA256_Init(void *c) { int r = orig_SHA256_Init ? orig_SHA256_Init(c) : 1;       return (r != 1) ? 1 : r; }
static int SBXK_SHA256_Update(void *c, const void *d, size_t n) { return orig_SHA256_Update ? orig_SHA256_Update(c, d, n) : 1; }
static int SBXK_SHA256_Final(unsigned char *md, void *c) { int r = orig_SHA256_Final ? orig_SHA256_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA512_Init(void *c) { int r = orig_SHA512_Init ? orig_SHA512_Init(c) : 1;       return (r != 1) ? 1 : r; }
static int SBXK_SHA512_Update(void *c, const void *d, size_t n) { return orig_SHA512_Update ? orig_SHA512_Update(c, d, n) : 1; }
static int SBXK_SHA512_Final(unsigned char *md, void *c) { int r = orig_SHA512_Final ? orig_SHA512_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_HMAC_Init(void *ctx, const void *k, int klen, const void *md) {
    int r = orig_HMAC_Init ? orig_HMAC_Init(ctx, k, klen, md) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_HMAC_Update(void *ctx, const void *d, size_t n) {
    return orig_HMAC_Update ? orig_HMAC_Update(ctx, d, n) : 1;
}
static int SBXK_HMAC_Final(void *ctx, unsigned char *md, unsigned int *len) {
    int r = orig_HMAC_Final ? orig_HMAC_Final(ctx, md, len) : 1;
    return (r != 1) ? 1 : r;
}

static int SBXK_EVP_SignFinal(void *ctx, unsigned char *md, unsigned int *s, void *pkey) {
    int r = orig_EVP_SignFinal ? orig_EVP_SignFinal(ctx, md, s, pkey) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_EVP_VerifyFinal(void *ctx, const unsigned char *sig, unsigned int siglen, void *pkey) {
    (void)ctx; (void)sig; (void)siglen; (void)pkey; (void)orig_EVP_VerifyFinal;
    return 1;
}
static int SBXK_EVP_DigestSign(void *ctx, unsigned char *sig, size_t *siglen,
                               const unsigned char *tbs, size_t tbslen) {
    int r = orig_EVP_DigestSign ? orig_EVP_DigestSign(ctx, sig, siglen, tbs, tbslen) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_EVP_DigestVerify(void *ctx, const unsigned char *sig, size_t siglen,
                                 const unsigned char *tbs, size_t tbslen) {
    (void)ctx; (void)sig; (void)siglen; (void)tbs; (void)tbslen; (void)orig_EVP_DigestVerify;
    return 1;
}

static int SBXK_X509_verify_cert(void *ctx) { (void)orig_X509_verify_cert; (void)ctx; return 1; }
static long SBXK_SSL_get_verify_result(const void *ssl) { (void)orig_SSL_get_verify_result; (void)ssl; return 0; /* X509_V_OK */ }

// SSL_CTX_set_verify return type di libssl iOS = int (0/1). Wrapper aman.
static int SBXK_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    (void)mode; (void)cb;
    if (orig_SSL_CTX_set_verify) return orig_SSL_CTX_set_verify(ctx, 0 /* SSL_VERIFY_NONE */, NULL);
    return 1;
}
static void SBXK_SSL_set_verify(void *ssl, int mode, void *cb) {
    (void)mode; (void)cb;
    if (orig_SSL_set_verify) orig_SSL_set_verify(ssl, 0, NULL);
}

static int SBXK_RAND_bytes(unsigned char *buf, int num) {
    return orig_RAND_bytes ? orig_RAND_bytes(buf, num) : 1;
}

#pragma mark =========================================================
#pragma mark 4. HOOK IMPLEMENTATIONS — INTEGRITY / JAILBREAK / DEBUG / HOOK DETECT
#pragma mark =========================================================

// Semua return "clean" — no jailbreak, no debug, no hook, integrity OK.
// Selector macam ini banyak di SDK security pihak ketiga (guard lib) & di kode game sendiri.

#define SBXK_BOOL_NO_IMPL(name) \
    static BOOL name(id self, SEL _cmd) { (void)self; (void)_cmd; return NO; }
#define SBXK_BOOL_YES_IMPL(name) \
    static BOOL name(id self, SEL _cmd) { (void)self; (void)_cmd; return YES; }

SBXK_BOOL_NO_IMPL(SBXK_isJailbroken)
SBXK_BOOL_NO_IMPL(SBXK_isJailbreak)
SBXK_BOOL_NO_IMPL(SBXK_checkJailbreak)
SBXK_BOOL_NO_IMPL(SBXK_jailbreakDetection)
SBXK_BOOL_NO_IMPL(SBXK_isSimulator)
SBXK_BOOL_NO_IMPL(SBXK_isSimulatorDevice)
SBXK_BOOL_NO_IMPL(SBXK_checkSimulator)
SBXK_BOOL_NO_IMPL(SBXK_isDebuggerAttached)
SBXK_BOOL_NO_IMPL(SBXK_isDebugged)
SBXK_BOOL_NO_IMPL(SBXK_checkDebugger)
SBXK_BOOL_NO_IMPL(SBXK_amIBeingDebugged)
SBXK_BOOL_NO_IMPL(SBXK_checkDebuggerAttach)
SBXK_BOOL_NO_IMPL(SBXK_isHooked)
SBXK_BOOL_NO_IMPL(SBXK_isHookDetected)
SBXK_BOOL_NO_IMPL(SBXK_checkHook)
SBXK_BOOL_NO_IMPL(SBXK_detectHook)
SBXK_BOOL_NO_IMPL(SBXK_antiHookCheck)
SBXK_BOOL_NO_IMPL(SBXK_isTampered)
SBXK_BOOL_NO_IMPL(SBXK_checkTamper)
SBXK_BOOL_NO_IMPL(SBXK_antiTamperCheck)
SBXK_BOOL_NO_IMPL(SBXK_isInjected)
SBXK_BOOL_NO_IMPL(SBXK_isLibraryInjected)
SBXK_BOOL_NO_IMPL(SBXK_checkInjection)
SBXK_BOOL_NO_IMPL(SBXK_antiInjectionCheck)
SBXK_BOOL_NO_IMPL(SBXK_isReversingDetected)
SBXK_BOOL_NO_IMPL(SBXK_checkReversing)
SBXK_BOOL_NO_IMPL(SBXK_antiReversingCheck)
SBXK_BOOL_NO_IMPL(SBXK_isBlocked)
SBXK_BOOL_NO_IMPL(SBXK_antiBlockingCheck)
SBXK_BOOL_NO_IMPL(SBXK_integrity_detect)
SBXK_BOOL_NO_IMPL(SBXK_MTML_INTEGRITY_DETECT)
SBXK_BOOL_NO_IMPL(SBXK_CheckPufferDownload)
SBXK_BOOL_NO_IMPL(SBXK_token_expire)
SBXK_BOOL_NO_IMPL(SBXK_isTokenInvalid)
SBXK_BOOL_NO_IMPL(SBXK_isAccessDenied)
SBXK_BOOL_NO_IMPL(SBXK_isSuspended)
SBXK_BOOL_NO_IMPL(SBXK_EventIsBlocked)
SBXK_BOOL_NO_IMPL(SBXK_UserPropertyIsBlocked)
SBXK_BOOL_NO_IMPL(SBXK_CheckDeviceMuteStat)

SBXK_BOOL_YES_IMPL(SBXK_verifyIntegrity)
SBXK_BOOL_YES_IMPL(SBXK_checkTokenValid)
SBXK_BOOL_YES_IMPL(SBXK_checkConfigSignValidity)
SBXK_BOOL_YES_IMPL(SBXK_verify_file_md5)
SBXK_BOOL_YES_IMPL(SBXK_CheckFileMd5)
SBXK_BOOL_YES_IMPL(SBXK_CheckFileHeader)
SBXK_BOOL_YES_IMPL(SBXK_IsFileExistInResDir)
SBXK_BOOL_YES_IMPL(SBXK_verifySignature)

#pragma mark =========================================================
#pragma mark 5. HOOK IMPLEMENTATIONS — GAME LOGIC (server-side mirror)
#pragma mark =========================================================

// Ini target di memori klien. Balik ke server tetap server yang putuskan.
// Yang kita lakukan: netralkan trigger client-side supaya flag "modded" tdk dikirim.

static id SBXK_WeaponProcessor_CalculateDamage(id self, SEL _cmd, id target, float distance) {
    (void)self; (void)_cmd; (void)target; (void)distance; return @(0);
}
static BOOL SBXK_CharacterMovement_IsSpeedExceeded(id self, SEL _cmd) {
    (void)self; (void)_cmd; return NO;
}
static id SBXK_BulletSimulator_CheckWallCollision(id self, SEL _cmd) {
    (void)self; (void)_cmd; return nil;
}
static void SBXK_NetworkManager_SendSecurityReport(id self, SEL _cmd, id report) {
    (void)self; (void)_cmd; (void)report; SBXK_LOG(@"suppressed SecurityReport");
}
static BOOL SBXK_SecurityChecker_IsFileSystemModified(id self, SEL _cmd) {
    (void)self; (void)_cmd; return NO;
}

#pragma mark =========================================================
#pragma mark 6. HOOK IMPLEMENTATIONS — GSDK (Tencent) / Ping / Voice / Ads / Firebase / QQ
#pragma mark =========================================================

// Zero-return hooks: kembalikan @(0) atau nil, cukup untuk mematikan telemetri klien.

#define SBXK_ZERO_ID(name) \
    static id name(id self, SEL _cmd) { (void)self; (void)_cmd; return @(0); }
#define SBXK_NIL_ID(name) \
    static id name(id self, SEL _cmd) { (void)self; (void)_cmd; return nil; }
#define SBXK_ZERO_ID_ARGS(name, ...) \
    static id name(id self, SEL _cmd, ##__VA_ARGS__) { (void)self; (void)_cmd; return @(0); }

SBXK_ZERO_ID(SBXK_GSDKCPU_getSystemCPUCircle)
SBXK_ZERO_ID(SBXK_GSDKMemory_getSystemAvailableMemory)
SBXK_ZERO_ID(SBXK_GSDKInGameManager_GSDKRealTimeDetect)
SBXK_ZERO_ID(SBXK_GSDKInGameSystem_GSDKInnerEnd)
SBXK_ZERO_ID(SBXK_GSDKInGameSystem_GSDKInnerRealTimeDetect)
SBXK_ZERO_ID(SBXK_GetCurrentDownloadSpeed)
SBXK_ZERO_ID(SBXK_GetCurrentSpeed)
SBXK_ZERO_ID(SBXK_GetRunningTasks)
SBXK_ZERO_ID(SBXK_GSDKPing_ping)
SBXK_ZERO_ID(SBXK_GSDKPingDetect_ping)
SBXK_ZERO_ID(SBXK_PingDelegate_pingTimer)
SBXK_ZERO_ID(SBXK_SimplePing_start)
SBXK_ZERO_ID(SBXK_SimplePing_startWithHostAddress)
SBXK_ZERO_ID(SBXK_SimplePing_readData)
SBXK_ZERO_ID(SBXK_GetMicLevel)
SBXK_ZERO_ID(SBXK_GetSpeakerLevel)
SBXK_ZERO_ID(SBXK_GetBGMLevel)
SBXK_ZERO_ID(SBXK_GetBGMFileTime)
SBXK_ZERO_ID(SBXK_GetBGMPlayTime)
SBXK_ZERO_ID(SBXK_GetRecordKaraokeTotalTime)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_GetMicLevel)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_GetSpeakerLevel)

SBXK_ZERO_ID_ARGS(SBXK_GSDKHttpRequest_requestControl_Openid_Acctype_Zoneid_Env_,
                  id a, id b, id c, id d)
SBXK_ZERO_ID_ARGS(SBXK_GSDKInGameSystem_GSDKInnerSaveFPS_FpsDots_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKInGameSystem_GSDKInnerStart_SceneID_RoomIP_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKInitManager_detectOperation_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKRealTimeDetect_pingDelayDetect_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKRealTimeDetect_updDelayDetect_Port_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKUdpDetect_isUDPConnect_Port_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKWIFI_ping_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKDetectPort_isConnection_Port_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPayEvent_GSDKPay_Tag_Status_Msg_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didFailToSendPacket_sequenceNumber_error_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didFailWithError_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didReceivePingResponsePacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didReceiveUnexpectedPacket_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didSendPacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPing_simplePing_didStartWithAddress_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didFailToSendPacket_sequenceNumber_error_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didFailWithError_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didReceivePingResponsePacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didReceiveUnexpectedPacket_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didSendPacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GSDKPingDetect_simplePing_didStartWithAddress_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_PingDelegate_simplePing_didFailToSendPacket_sequenceNumber_error_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_PingDelegate_simplePing_didSendPacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_SimplePing_didFailWithError_, id a)
SBXK_ZERO_ID_ARGS(SBXK_SimplePing_sendPingWithData_, id a)
SBXK_ZERO_ID_ARGS(SBXK_SimplePing_validatePingResponsePacket_sequenceNumber_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_SimplePing_pingPacketWithType_payload_requiresChecksum_, id a, id b, BOOL c)
SBXK_ZERO_ID_ARGS(SBXK_TDataMasterApplication_reportEventWithSrcID_eventName_AndEventKVArray_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_APMMonitor_handleEvent_, id a)
SBXK_ZERO_ID_ARGS(SBXK_APMMonitor_startMonitoring_, id a)
SBXK_ZERO_ID_ARGS(SBXK_APMDeviceInfoSupport_getBatteryState, id a)
SBXK_ZERO_ID_ARGS(SBXK_APMCollector_collectMetrics_, id a)
SBXK_ZERO_ID_ARGS(SBXK_TApmSceneMarker_markLoadLevel_, id a)
SBXK_ZERO_ID_ARGS(SBXK_TApmSceneMarker_postStepEvent_, id a)
SBXK_ZERO_ID_ARGS(SBXK_TApmSceneMarker_postStreamEvent_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudCoreRemoteConfig_updateConfig_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudCoreRemoteConfig_getConfig_, id a)
SBXK_ZERO_ID_ARGS(SBXK_FBAdMonitor_startMonitoringAd_, id a)
SBXK_ZERO_ID_ARGS(SBXK_FBAdEvent_logEvent_withParameters_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_FBAdLogger_logMessage_withLevel_, id a, int b)
SBXK_ZERO_ID_ARGS(SBXK_FIRMessaging_retrieveFCMTokenForSenderID_completion_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_FIRMessaging_setAPNSToken_withUserInfo_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_QQApiInterface_sendReq_resultBlock_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_TDataMasterApplication_handleOpenURL_, id a)
SBXK_ZERO_ID_ARGS(SBXK_TcApiTool_openUniversallinkIfNeed_, id a)

// --- GSDK dealloc / lifecycle (return void ideally, tapi kode asli return id → kita balik @(0) aman) ---
#define SBXK_NOOP_ID_ARGS(name, ...) \
    static id name(id self, SEL _cmd, ##__VA_ARGS__) { (void)self; (void)_cmd; return @(0); }

SBXK_NOOP_ID_ARGS(SBXK_GSDKHttpDnsResolver_dealloc)
SBXK_NOOP_ID_ARGS(SBXK_GSDKHttpRequest_dealloc)
SBXK_NOOP_ID_ARGS(SBXK_GSDKPing_dealloc)
SBXK_NOOP_ID_ARGS(SBXK_GSDKPingDetect_dealloc)
SBXK_NOOP_ID_ARGS(SBXK_SimplePing_dealloc)
SBXK_NOOP_ID_ARGS(SBXK_IMSDKCustomWebView_dealloc)

// --- Voice (Tencent GVoice) — semua no-op ---
#define SBXK_NOOP_VOID_ARGS(name, ...) \
    static void name(id self, SEL _cmd, ##__VA_ARGS__) { (void)self; (void)_cmd; }

SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_JoinTeamRoom_Scenes_roomName_timeout_, id a, id b, int c)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_QuitRoom_Scenes_timeout_, id a, int b)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_EnableMultiRoom_, BOOL a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_EnableRoomMicrophone_enable_, id a, BOOL b)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_EnableRoomSpeaker_enable_, id a, BOOL b)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_ApplyMessageKey_timestamp_timeout_, id a, int b, int c)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_StartRecording_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_UploadRecordedFile_timeout_fileProperty_, id a, int b, id c)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_DownloadRecordedFile_filePath_timeout_fileProperty_, id a, id b, int c, id d)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_EnableLog_, BOOL a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetLogCallBack_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetMicVolume_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetSpeakerVolume_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SpeechToText_token_timestamp_timeout_language_, id a, id b, int c, int d, id e)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_ForbidMemberVoice_enable_inRoom_, id a, int b, BOOL c)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetBGMPath_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetBitRate_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetDataFree_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetReportBufferTime_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudVoiceEngine_SetBGMPlayTime_, int a)
SBXK_NOOP_VOID_ARGS(SBXK_GVGCloudVoice_setAppInfo_withKey_andOpenID_, id a, id b, id c)
SBXK_NOOP_VOID_ARGS(SBXK_GVGCloudVoiceExtension_EnableKeyWordsDetect_, BOOL a)
SBXK_NOOP_VOID_ARGS(SBXK_GCloudUnityPlugin_SetGameObjectName_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_TikTokAuth_authorizeWithPermissions_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_TikTokAuth_handleOpenURL_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_VKAuth_authorizeWithPermissions_, id a)
SBXK_NOOP_VOID_ARGS(SBXK_SCSDKLoginClient_loginWithCompletion_, id a)

// --- Voice returns id (bukan void) untuk metode yang memang return id ---
SBXK_ZERO_ID(SBXK_GVGCloudVoice_openMic)
SBXK_ZERO_ID(SBXK_GVGCloudVoice_openSpeaker)
SBXK_ZERO_ID(SBXK_GVGCloudVoiceExtension_GetBGMPlayState)
SBXK_ZERO_ID(SBXK_GVGCloudVoiceExtension_GetMicState)
SBXK_ZERO_ID(SBXK_GVGCloudVoiceExtension_GetSpeakerState)
SBXK_ZERO_ID(SBXK_GVoiceMuteSwitch_detectMuteSwitch)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StartTve)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StopRecording)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_TestMic)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StartBGMPlay)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StopBGMPlay)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_PauseBGMPlay)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_ResumeBGMPlay)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_RSTSStopRecording)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_TextToStreamSpeechStop)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StartPreview)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_StopPreview)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_PauseKaraoke)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_ResumeKaraoke)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_GetBGMPlayTime)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_GetBGMFileTime)
SBXK_ZERO_ID(SBXK_GCloudVoiceEngine_GetRecordKaraokeTotalTime)
SBXK_ZERO_ID(SBXK_APMDeviceInfoSupport_getThermalState)
SBXK_ZERO_ID(SBXK_TApmSceneMarker_markLevelFin)
SBXK_ZERO_ID(SBXK_FBAdViewabilityValidator_stopMonitoring)
SBXK_ZERO_ID(SBXK_FBAdMonitor_stopMonitoring)
SBXK_ZERO_ID(SBXK_FIRMessaging_deleteFCMTokenForSenderID_completion)
SBXK_ZERO_ID(SBXK_FIRMessaging_subscribeToTopic_completion)
SBXK_ZERO_ID(SBXK_FIRMessaging_unsubscribeFromTopic_completion)
SBXK_ZERO_ID(SBXK_FIRMessaging_APNSToken)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendThirdAppBindGroupReq_resultBlock_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendThirdAppUnBindGroupReq_resultBlock_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendThirdAppJoinGroupReq_resultBlock_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendQueryQQGroupProInfo_resultBlock_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendMessageToQQAuthWithReq_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendMessageToQQAvatarWithReq_)
SBXK_ZERO_ID(SBXK_QQApiInterface_sendMessageToFaceCollectionWithReq_)
SBXK_ZERO_ID(SBXK_GCloudUnityPlugin_Initialize)
SBXK_ZERO_ID(SBXK_GCloudUnityPlugin_ReportEvent)
SBXK_ZERO_ID(SBXK_VKAuth_logout)
SBXK_ZERO_ID(SBXK_SCSDKLoginClient_logout)
SBXK_ZERO_ID(SBXK_IMSDKNoticeIMSDKManager_imsdkCoreKitNoticeImageFileHash_)

// --- Beberapa return id dengan argumen panjang (GCloud) ---
SBXK_ZERO_ID_ARGS(SBXK_IMSDKNoticeIMSDKManager_getImageCache_imagePath_imageHash_queue_completeHandle_, id a, id b, id c, id d)
SBXK_ZERO_ID_ARGS(SBXK_IMSDKStatAdjustManager_reportEvent_eventBody_isRealtime_, id a, id b, BOOL c)
SBXK_ZERO_ID_ARGS(SBXK_IMSDKStatAdjustManager_reportEvent_params_isRealtime_, id a, id b, BOOL c)
SBXK_ZERO_ID_ARGS(SBXK_IMSDKStatAdjustManager_reportPurchase_currentCode_expense_isRealTime_, id a, id b, id c, BOOL d)
SBXK_ZERO_ID_ARGS(SBXK_IMSDKStatAdjustManager_reportRevenue_currencyCode_revenueValue_params_extraJson_, id a, id b, id c, id d)
SBXK_ZERO_ID_ARGS(SBXK_INTLWebViewManager_openURL_observerID_baseParams_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_QQOpenApiUtility_cgiRequestGetSdkConfig_, id a)
SBXK_ZERO_ID_ARGS(SBXK_APMCollector_reportNow_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_GetFileParam_data_time_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_TextToStreamSpeechStart_voiceType_timeout_filePath_, id a, int b, int c, id d)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableTranslate_isEnable_lang_transType_, id a, BOOL b, id c, int d)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableMagicVoice_isEnable_, id a, BOOL b)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableRecvMagicVoice_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_RoomGeneralDataChannel_content_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_APITrace_callInfo_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetPlayerInfoAbroad_members_lang_count_, id a, id b, id c, int d)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableReportALL_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableReportALLAbroad_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableReportForAbroad_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_ReportFileForAbroad_bTranslate_bChangeVoice_time_, id a, BOOL b, BOOL c, int d)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableCivilFile_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableCivilVoice_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetCivilBinPath_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableEarBack_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_StartKaraokeRecording_accfile_orifile_, id a, id b, id c)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_EnableAccFilePlay_, BOOL a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetKaraokeVoiceVol_, int a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetKaraokeAccVol_, int a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetKaraokeVoiceDelay_, int a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SeekTimeMsForPreview_, int a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SeekTimeMsForAcc_, int a)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_SetReportedPlayerInfo_arg1_arg2_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_ReportPlayer_arg1_arg2_, id a, id b)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_RSTSStartRecording_targetLang_targetLangCnt_action_timeout_recordFilePath_, id a, int b, int c, int d, int e, id f)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_RSTSSpeechToSpeech_targetLang_targetLangCnt_dirPath_voiceType_voiceRate_volume_timeout_recordFilePath_, id a, int b, int c, id d, int e, float f, float g, int h, id i)
SBXK_ZERO_ID_ARGS(SBXK_GCloudVoiceEngine_RSTSSpeechToText_targetLang_targetLangCnt_timeout_recordFilePath_srcLangStr_extInfo_, id a, int b, int c, int d, id e, id f, id g)

// FB
SBXK_ZERO_ID_ARGS(SBXK_FBAdViewabilityValidator_checkViewability_, id a)
SBXK_ZERO_ID_ARGS(SBXK_FBAdNetworkResponseInfo_adUnitMapping, id a)

// GAD
SBXK_ZERO_ID(SBXK_GADMobileAds_initializationStatus)
SBXK_ZERO_ID(SBXK_GADAppOpenAd_responseInfo)
SBXK_ZERO_ID_ARGS(SBXK_GADAppOpenAd_adDidRecordClick_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GADAppOpenAd_adDidRecordImpression_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GADAppOpenAd_setPaidEventHandler_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GADAppOpenAd_adWillPresentFullScreenContent_, id a)
SBXK_ZERO_ID_ARGS(SBXK_GADAppOpenAd_adDidFailToPresentFullScreenContentWithError_, id a)

// GAD return BOOL
SBXK_BOOL_YES_IMPL(SBXK_GADAppOpenAd_adDidDismissFullScreenContent_)
SBXK_BOOL_YES_IMPL(SBXK_GADAppOpenAd_adWillDismissFullScreenContent_)

// GAD canPresent... returns BOOL
static BOOL SBXK_GADAppOpenAd_canPresentFromRootViewController_error_(id self, SEL _cmd, id vc, id *err) {
    (void)self; (void)_cmd; (void)vc; if (err) *err = nil; return YES;
}

// --- Advertising identifier spoof ---
static NSString *SBXK_ASIdentifierManager_advertisingIdentifier(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    return @"00000000-0000-0000-0000-000000000000";
}
static NSInteger SBXK_ATTrackingManager_trackingAuthorizationStatus(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    // ATTrackingManagerAuthorizationStatusAuthorized = 3
    return 3;
}

#pragma mark =========================================================
#pragma mark 7. POSIX HOOKS — access() & NSFileManager
#pragma mark =========================================================

// Fishhook untuk `access` di libSystem.
static int (*orig_access)(const char *, int);
static int SBXK_access(const char *path, int amode) {
    static const char *jbPaths[] = {
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
    if (path) {
        for (int i = 0; jbPaths[i]; i++) {
            if (strcmp(path, jbPaths[i]) == 0) {
                errno = ENOENT;
                return -1;
            }
        }
    }
    return orig_access ? orig_access(path, amode) : -1;
}

// Swizzle NSFileManager fileExistsAtPath: & fileExistsAtPath:isDirectory:
static NSArray<NSString *> *SBXK_JailbreakPrefixes(void) {
    static NSArray *arr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[
            @"/Applications/Cydia.app",
            @"/Applications/Sileo.app",
            @"/Applications/Zebra.app",
            @"/bin/bash",
            @"/bin/sh",
            @"/etc/apt",
            @"/usr/bin/ssh",
            @"/usr/sbin/sshd",
            @"/private/var/lib/apt",
            @"/Library/MobileSubstrate",
            @"/var/log/syslog"
        ];
    });
    return arr;
}

static BOOL SBXK_NSFileManager_fileExistsAtPath_(id self, SEL _cmd, NSString *path) {
    for (NSString *p in SBXK_JailbreakPrefixes()) {
        if ([path isEqualToString:p] || [path hasPrefix:p]) return NO;
    }
    // panggil original — kita sudah class_replaceMethod, jadi panggil via method_getImplementation
    IMP orig = class_getMethodImplementation([self class], @selector(SBXK_original_fileExistsAtPath:));
    if (orig) {
        BOOL (*fn)(id, SEL, NSString *) = (void *)orig;
        return fn(self, @selector(SBXK_original_fileExistsAtPath:), path);
    }
    return NO;
}
static BOOL SBXK_NSFileManager_fileExistsAtPath_isDirectory_(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    for (NSString *p in SBXK_JailbreakPrefixes()) {
        if ([path isEqualToString:p] || [path hasPrefix:p]) { if (isDir) *isDir = NO; return NO; }
    }
    IMP orig = class_getMethodImplementation([self class], @selector(SBXK_original_fileExistsAtPath:isDirectory:));
    if (orig) {
        BOOL (*fn)(id, SEL, NSString *, BOOL *) = (void *)orig;
        return fn(self, @selector(SBXK_original_fileExistsAtPath:isDirectory:), path, isDir);
    }
    return NO;
}

#pragma mark =========================================================
#pragma mark 8. APPDLEGATE — anti-tamper & alert
#pragma mark =========================================================

@interface SBXK_AppDelegateProxy : NSObject
@end

@implementation SBXK_AppDelegateProxy

+ (void)installIfPossible {
    Class AppDel = NSClassFromString(@"AppDelegate");
    if (!AppDel) return;

    SEL swz = @selector(application:didFinishLaunchingWithOptions:);
    Method m = class_getInstanceMethod(AppDel, swz);
    if (!m) return;

    IMP orig = method_getImplementation(m);
    IMP newI = imp_implementationWithBlock(^BOOL(id self, UIApplication *app, NSDictionary *opts) {
        // Panggil original via fungsi tersimpan.
        BOOL (*fn)(id, SEL, UIApplication *, NSDictionary *) = (void *)orig;
        BOOL r = fn(self, swz, app, opts);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [SBXK_AppDelegateProxy showBanner];
        });
        return r;
    });
    method_setImplementation(m, newI);
}

+ (void)showBanner {
    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive &&
                [s isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *win in ((UIWindowScene *)s).windows) {
                    if (win.isKeyWindow) { w = win; break; }
                }
                if (w) break;
            }
        }
    }
    if (!w) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
        w = [UIApplication sharedApplication].keyWindow;
#pragma clang diagnostic pop
    }
    if (!w || !w.rootViewController) return;

    UIAlertController *a = [UIAlertController alertControllerWithTitle:@"AMAR VIP 2026"
                                                               message:@"حماية عمار مفعلة 😎\nالحساب الآن تحت الحماية الشبحية."
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"استمرار" style:UIAlertActionStyleDefault handler:nil]];
    [w.rootViewController presentViewController:a animated:YES completion:nil];
}

@end

#pragma mark =========================================================
#pragma mark 9. FILE CLEANUP TIMER (setiap 30 detik)
#pragma mark =========================================================

static void SBXK_DeleteSensitiveFiles(void) {
    NSString *home = NSHomeDirectory();
    NSArray<NSString *> *paths = @[
        [home stringByAppendingPathComponent:@"Documents/ShadowTrackerExtra/Saved/Logs"],
        [home stringByAppendingPathComponent:@"Documents/ShadowTrackerExtra/Saved/MMKV"],
        [home stringByAppendingPathComponent:@"Documents/ShadowTrackerExtra/Saved/Gamelet"]
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in paths) {
        NSError *e = nil;
        [fm removeItemAtPath:p error:&e];
    }
}

static void SBXK_StartCleanupTimer(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSTimer scheduledTimerWithTimeInterval:30.0 repeats:YES block:^(NSTimer *t) {
            (void)t;
            SBXK_DeleteSensitiveFiles();
        }];
    });
}

#pragma mark =========================================================
#pragma mark 10. INSTALL SWIZZLES (safe — cek class/method dulu)
#pragma mark =========================================================

static void SBXK_InstallAllSwizzles(void) {

    // --- Integrity / detect (dipasang hanya kalau class-nya ada) ---
    SBXK_HOOK_I(IntegrityChecker, integrity_detect);
    SBXK_HOOK_I(IntegrityChecker, MTML_INTEGRITY_DETECT);
    SBXK_HOOK_I(JailbreakDetector, isJailbroken);
    SBXK_HOOK_I(JailbreakDetector, isJailbreak);
    SBXK_HOOK_I(JailbreakDetector, checkJailbreak);
    SBXK_HOOK_I(SecurityChecker, IsFileSystemModified);
    SBXK_HOOK_I(SecurityChecker, isDebuggerAttached);
    SBXK_HOOK_I(SecurityChecker, isHooked);
    SBXK_HOOK_I(SecurityChecker, isTampered);
    SBXK_HOOK_I(SecurityChecker, isInjected);

    // --- Game logic (biasanya di bundle game; nama class di-reflect) ---
    SBXK_HOOK_I(WeaponProcessor, CalculateDamage);
    SBXK_HOOK_I(CharacterMovement, IsSpeedExceeded);
    SBXK_HOOK_I(BulletSimulator, CheckWallCollision);
    SBXK_HOOK_I(NetworkManager, SendSecurityReport);

    // --- GSDK (Tencent) ---
    SBXK_HOOK_I(GSDKCPU, getSystemCPUCircle);
    SBXK_HOOK_I(GSDKMemory, getSystemAvailableMemory);
    SBXK_HOOK_I(GSDKInGameManager, GSDKRealTimeDetect);
    SBXK_HOOK_I(GSDKInGameSystem, GSDKInnerEnd);
    SBXK_HOOK_I(GSDKInGameSystem, GSDKInnerRealTimeDetect);
    SBXK_HOOK_I(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots_);
    SBXK_HOOK_I(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP_);
    SBXK_HOOK_I(GSDKInitManager, detectOperation_);
    SBXK_HOOK_I(GSDKPayEvent, GSDKPay_Tag_Status_Msg_);
    SBXK_HOOK_I(GSDKPing, dealloc);
    SBXK_HOOK_I(GSDKPing, ping);
    SBXK_HOOK_I(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error_);
    SBXK_HOOK_I(GSDKPing, simplePing_didFailWithError_);
    SBXK_HOOK_I(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber_);
    SBXK_HOOK_I(GSDKPing, simplePing_didReceiveUnexpectedPacket_);
    SBXK_HOOK_I(GSDKPing, simplePing_didSendPacket_sequenceNumber_);
    SBXK_HOOK_I(GSDKPing, simplePing_didStartWithAddress_);
    SBXK_HOOK_I(GSDKPing, stopPing);
    SBXK_HOOK_I(GSDKPingDetect, dealloc);
    SBXK_HOOK_I(GSDKPingDetect, ping);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didFailToSendPacket_sequenceNumber_error_);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didFailWithError_);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didReceivePingResponsePacket_sequenceNumber_);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didReceiveUnexpectedPacket_);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didSendPacket_sequenceNumber_);
    SBXK_HOOK_I(GSDKPingDetect, simplePing_didStartWithAddress_);
    SBXK_HOOK_I(GSDKRealTimeDetect, pingDelayDetect_);
    SBXK_HOOK_I(GSDKRealTimeDetect, updDelayDetect_Port_);
    SBXK_HOOK_I(GSDKUdpDetect, isUDPConnect_Port_);
    SBXK_HOOK_I(GSDKWIFI, ping_);
    SBXK_HOOK_I(GSDKHttpDnsResolver, dealloc);
    SBXK_HOOK_I(GSDKHttpRequest, dealloc);
    SBXK_HOOK_I(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env_);
    SBXK_HOOK_I(GSDKDetectPort, isConnection_Port_);

    // --- Ping / SimplePing ---
    SBXK_HOOK_I(PingDelegate, pingTimer);
    SBXK_HOOK_I(PingDelegate, simplePing_didFailToSendPacket_sequenceNumber_error_);
    SBXK_HOOK_I(PingDelegate, simplePing_didSendPacket_sequenceNumber_);
    SBXK_HOOK_I(SimplePing, dealloc);
    SBXK_HOOK_I(SimplePing, didFailWithError_);
    SBXK_HOOK_I(SimplePing, pingPacketWithType_payload_requiresChecksum_);
    SBXK_HOOK_I(SimplePing, readData);
    SBXK_HOOK_I(SimplePing, sendPingWithData_);
    SBXK_HOOK_I(SimplePing, start);
    SBXK_HOOK_I(SimplePing, startWithHostAddress);
    SBXK_HOOK_I(SimplePing, validatePingResponsePacket_sequenceNumber_);

    // --- Voice (GVoice) ---
    SBXK_HOOK_I(GVGCloudVoice, openMic);
    SBXK_HOOK_I(GVGCloudVoice, openSpeaker);
    SBXK_HOOK_I(GVGCloudVoice, setAppInfo_withKey_andOpenID_);
    SBXK_HOOK_I(GVGCloudVoiceExtension, CheckDeviceMuteStat);
    SBXK_HOOK_I(GVGCloudVoiceExtension, EnableKeyWordsDetect_);
    SBXK_HOOK_I(GVGCloudVoiceExtension, GetBGMPlayState);
    SBXK_HOOK_I(GVGCloudVoiceExtension, GetMicState);
    SBXK_HOOK_I(GVGCloudVoiceExtension, GetSpeakerState);
    SBXK_HOOK_I(GVoiceMuteSwitch, detectMuteSwitch);
    SBXK_HOOK_I(GCloudVoiceEngine, StartTve);
    SBXK_HOOK_I(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout_);
    SBXK_HOOK_I(GCloudVoiceEngine, QuitRoom_Scenes_timeout_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableMultiRoom_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableRoomMicrophone_enable_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableRoomSpeaker_enable_);
    SBXK_HOOK_I(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout_);
    SBXK_HOOK_I(GCloudVoiceEngine, StartRecording_);
    SBXK_HOOK_I(GCloudVoiceEngine, StopRecording);
    SBXK_HOOK_I(GCloudVoiceEngine, UploadRecordedFile_timeout_fileProperty_);
    SBXK_HOOK_I(GCloudVoiceEngine, DownloadRecordedFile_filePath_timeout_fileProperty_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableLog_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetLogCallBack_);
    SBXK_HOOK_I(GCloudVoiceEngine, GetMicLevel);
    SBXK_HOOK_I(GCloudVoiceEngine, GetSpeakerLevel);
    SBXK_HOOK_I(GCloudVoiceEngine, SetMicVolume_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetSpeakerVolume_);
    SBXK_HOOK_I(GCloudVoiceEngine, SpeechToText_token_timestamp_timeout_language_);
    SBXK_HOOK_I(GCloudVoiceEngine, ForbidMemberVoice_enable_inRoom_);
    SBXK_HOOK_I(GCloudVoiceEngine, TestMic);
    SBXK_HOOK_I(GCloudVoiceEngine, GetFileParam_data_time_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetBGMPath_);
    SBXK_HOOK_I(GCloudVoiceEngine, StartBGMPlay);
    SBXK_HOOK_I(GCloudVoiceEngine, StopBGMPlay);
    SBXK_HOOK_I(GCloudVoiceEngine, PauseBGMPlay);
    SBXK_HOOK_I(GCloudVoiceEngine, ResumeBGMPlay);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableNativeBGMPlay_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetBitRate_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetDataFree_);
    SBXK_HOOK_I(GCloudVoiceEngine, RSTSStartRecording_targetLang_targetLangCnt_action_timeout_recordFilePath_);
    SBXK_HOOK_I(GCloudVoiceEngine, RSTSSpeechToSpeech_targetLang_targetLangCnt_dirPath_voiceType_voiceRate_volume_timeout_recordFilePath_);
    SBXK_HOOK_I(GCloudVoiceEngine, RSTSSpeechToText_targetLang_targetLangCnt_timeout_recordFilePath_srcLangStr_extInfo_);
    SBXK_HOOK_I(GCloudVoiceEngine, RSTSStopRecording);
    SBXK_HOOK_I(GCloudVoiceEngine, TextToStreamSpeechStart_voiceType_timeout_filePath_);
    SBXK_HOOK_I(GCloudVoiceEngine, TextToStreamSpeechStop);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableTranslate_isEnable_lang_transType_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableMagicVoice_isEnable_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableRecvMagicVoice_);
    SBXK_HOOK_I(GCloudVoiceEngine, RoomGeneralDataChannel_content_);
    SBXK_HOOK_I(GCloudVoiceEngine, APITrace_callInfo_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetPlayerInfoAbroad_members_lang_count_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableReportALL_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableReportALLAbroad_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableReportForAbroad_);
    SBXK_HOOK_I(GCloudVoiceEngine, ReportFileForAbroad_bTranslate_bChangeVoice_time_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableCivilFile_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableCivilVoice_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetCivilBinPath_);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableEarBack_);
    SBXK_HOOK_I(GCloudVoiceEngine, StartKaraokeRecording_accfile_orifile_);
    SBXK_HOOK_I(GCloudVoiceEngine, StopKaraokeRecording);
    SBXK_HOOK_I(GCloudVoiceEngine, EnableAccFilePlay_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetKaraokeVoiceVol_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetKaraokeAccVol_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetKaraokeVoiceDelay_);
    SBXK_HOOK_I(GCloudVoiceEngine, StartPreview);
    SBXK_HOOK_I(GCloudVoiceEngine, StopPreview);
    SBXK_HOOK_I(GCloudVoiceEngine, SeekTimeMsForPreview_);
    SBXK_HOOK_I(GCloudVoiceEngine, SeekTimeMsForAcc_);
    SBXK_HOOK_I(GCloudVoiceEngine, PauseKaraoke);
    SBXK_HOOK_I(GCloudVoiceEngine, ResumeKaraoke);
    SBXK_HOOK_I(GCloudVoiceEngine, GetRecordKaraokeTotalTime);
    SBXK_HOOK_I(GCloudVoiceEngine, GetBGMLevel);
    SBXK_HOOK_I(GCloudVoiceEngine, SetReportedPlayerInfo_arg1_arg2_);
    SBXK_HOOK_I(GCloudVoiceEngine, ReportPlayer_arg1_arg2_);
    SBXK_HOOK_I(GCloudVoiceEngine, SetReportBufferTime_);
    SBXK_HOOK_I(GCloudVoiceEngine, GetBGMFileTime);
    SBXK_HOOK_I(GCloudVoiceEngine, GetBGMPlayTime);
    SBXK_HOOK_I(GCloudVoiceEngine, SetBGMPlayTime_);

    // --- GCloud core ---
    SBXK_HOOK_I(GCloudCoreRemoteConfig, updateConfig_);
    SBXK_HOOK_I(GCloudCoreRemoteConfig, getConfig_);
    SBXK_HOOK_I(GCloudUnityPlugin, Initialize);
    SBXK_HOOK_I(GCloudUnityPlugin, ReportEvent);
    SBXK_HOOK_I(GCloudUnityPlugin, SetGameObjectName_);

    // --- APM ---
    SBXK_HOOK_I(APMMonitor, handleEvent_);
    SBXK_HOOK_I(APMMonitor, startMonitoring_);
    SBXK_HOOK_I(APMDeviceInfoSupport, getBatteryState);
    SBXK_HOOK_I(APMDeviceInfoSupport, getThermalState);
    SBXK_HOOK_I(APMCollector, collectMetrics_);
    SBXK_HOOK_I(TApmSceneMarker, markLoadLevel_);
    SBXK_HOOK_I(TApmSceneMarker, markLevelFin);
    SBXK_HOOK_I(TApmSceneMarker, postStepEvent_);
    SBXK_HOOK_I(TApmSceneMarker, postStreamEvent_);

    // --- IMSDK / WebView / Stat ---
    SBXK_HOOK_I(IMSDKCustomWebView, dealloc);
    SBXK_HOOK_I(IMSDKNoticeIMSDKManager, getImageCache_imagePath_imageHash_queue_completeHandle_);
    SBXK_HOOK_I(IMSDKNoticeIMSDKManager, imsdkCoreKitNoticeImageFileHash_);
    SBXK_HOOK_I(IMSDKStatAdjustManager, reportEvent_eventBody_isRealtime_);
    SBXK_HOOK_I(IMSDKStatAdjustManager, reportEvent_params_isRealtime_);
    SBXK_HOOK_I(IMSDKStatAdjustManager, reportPurchase_currentCode_expense_isRealTime_);
    SBXK_HOOK_I(IMSDKStatAdjustManager, reportRevenue_currencyCode_revenueValue_params_extraJson_);
    SBXK_HOOK_I(INTLWebViewManager, openURL_observerID_baseParams_);

    // --- Firebase / GAD / FB ---
    SBXK_HOOK_I(FIRMessagingRmqManager, openDatabase);
    SBXK_HOOK_I(FIRMessaging, retrieveFCMTokenForSenderID_completion_);
    SBXK_HOOK_I(FIRMessaging, deleteFCMTokenForSenderID_completion_);
    SBXK_HOOK_I(FIRMessaging, subscribeToTopic_completion_);
    SBXK_HOOK_I(FIRMessaging, unsubscribeFromTopic_completion_);
    SBXK_HOOK_I(FIRMessaging, setAPNSToken_withUserInfo_);
    SBXK_HOOK_I(FIRMessaging, APNSToken);
    SBXK_HOOK_I(GADAdNetworkResponseInfo, adUnitMapping);
    SBXK_HOOK_I(GADAppOpenAd, didFailToPresentFullScreenContentWithError_);
    SBXK_HOOK_I(GADAppOpenAd, adDidDismissFullScreenContent_);
    SBXK_HOOK_I(GADAppOpenAd, adDidRecordClick_);
    SBXK_HOOK_I(GADAppOpenAd, adDidRecordImpression_);
    SBXK_HOOK_I(GADAppOpenAd, adWillDismissFullScreenContent_);
    SBXK_HOOK_I(GADAppOpenAd, adWillPresentFullScreenContent_);
    SBXK_HOOK_I(GADAppOpenAd, canPresentFromRootViewController_error_);
    SBXK_HOOK_I(GADAppOpenAd, responseInfo);
    SBXK_HOOK_I(GADAppOpenAd, setPaidEventHandler_);
    SBXK_HOOK_I(GADMobileAds, initializationStatus);
    SBXK_HOOK_I(FBAdViewabilityValidator, checkViewability_);
    SBXK_HOOK_I(FBAdViewabilityValidator, stopMonitoring);
    SBXK_HOOK_I(FBAdMonitor, startMonitoringAd_);
    SBXK_HOOK_I(FBAdMonitor, stopMonitoring);
    SBXK_HOOK_I(FBAdEvent, logEvent_withParameters_);
    SBXK_HOOK_I(FBAdLogger, logMessage_withLevel_);

    // --- QQ / Tencent SDK ---
    SBXK_HOOK_I(QQApiInterface, sendReq_resultBlock_);
    SBXK_HOOK_I(QQApiInterface, sendThirdAppBindGroupReq_resultBlock_);
    SBXK_HOOK_I(QQApiInterface, sendThirdAppUnBindGroupReq_resultBlock_);
    SBXK_HOOK_I(QQApiInterface, sendThirdAppJoinGroupReq_resultBlock_);
    SBXK_HOOK_I(QQApiInterface, sendQueryQQGroupProInfo_resultBlock_);
    SBXK_HOOK_I(QQApiInterface, sendMessageToQQAuthWithReq_);
    SBXK_HOOK_I(QQApiInterface, sendMessageToQQAvatarWithReq_);
    SBXK_HOOK_I(QQApiInterface, sendMessageToFaceCollectionWithReq_);
    SBXK_HOOK_I(QQOpenApiUtility, cgiRequestGetSdkConfig_);
    SBXK_HOOK_I(TDataMasterApplication, handleOpenURL_);
    SBXK_HOOK_I(TDataMasterApplication, reportEventWithSrcID_eventName_AndEventKVArray_);
    SBXK_HOOK_I(TcApiTool, openUniversallinkIfNeed_);
    SBXK_HOOK_I(GTMSessionFetcher, setSystemCompletionHandler_forSessionIdentifier_);

    // --- Reachability / Audio ---
    SBXK_HOOK_I(AReachability, isConnectionOnDemand);
    SBXK_HOOK_I(AReachability, isConnectionRequired);
    SBXK_HOOK_I(AudioDeviceMgr, GetAudioDeviceConnectState);
    SBXK_HOOK_I(AudioDeviceMgr, UpdateDeviceState_);
    SBXK_HOOK_I(serviceCommunication, getValueForKeypath);

    // --- TikTok / VK / Snap ---
    SBXK_HOOK_I(TikTokAuth, authorizeWithPermissions_);
    SBXK_HOOK_I(TikTokAuth, handleOpenURL_);
    SBXK_HOOK_I(VKAuth, authorizeWithPermissions_);
    SBXK_HOOK_I(VKAuth, logout);
    SBXK_HOOK_I(SCSDKLoginClient, loginWithCompletion_);
    SBXK_HOOK_I(SCSDKLoginClient, logout);

    // --- Advertising ---
    SBXK_HOOK_I(ASIdentifierManager, advertisingIdentifier);
    SBXK_HOOK_I(ATTrackingManager, trackingAuthorizationStatus);
}

#pragma mark =========================================================
#pragma mark 11. NSFileManager swizzle (aman, pakai exchange + alias)
#pragma mark =========================================================

static void SBXK_InstallFileManagerSwizzle(void) {
    Class fm = [NSFileManager class];

    Method m1 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
    if (m1) {
        // simpan original via alias
        class_addMethod(fm, @selector(SBXK_original_fileExistsAtPath:),
                        method_getImplementation(m1),
                        method_getTypeEncoding(m1));
        method_setImplementation(m1, (IMP)SBXK_NSFileManager_fileExistsAtPath_);
    }

    Method m2 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
    if (m2) {
        class_addMethod(fm, @selector(SBXK_original_fileExistsAtPath:isDirectory:),
                        method_getImplementation(m2),
                        method_getTypeEncoding(m2));
        method_setImplementation(m2, (IMP)SBXK_NSFileManager_fileExistsAtPath_isDirectory_);
    }
}

#pragma mark =========================================================
#pragma mark 12. FISHHOOK REBIND
#pragma mark =========================================================

static void SBXK_InstallFishhook(void) {
    // fopen: libcrypto pakai lazy loading via dyld → fishhook kena.
    // Kalau ternyata symbol tdk ada (game pakai BoringSSL statik), rebind akan return non-zero → aman.
    struct rebinding binds[] = {
        // RSA
        {"RSA_public_encrypt",  (void *)SBXK_RSA_public_encrypt,  (void **)&orig_RSA_public_encrypt},
        {"RSA_private_decrypt", (void *)SBXK_RSA_private_decrypt, (void **)&orig_RSA_private_decrypt},
        {"RSA_private_encrypt", (void *)SBXK_RSA_private_encrypt, (void **)&orig_RSA_private_encrypt},
        {"RSA_public_decrypt",  (void *)SBXK_RSA_public_decrypt,  (void **)&orig_RSA_public_decrypt},
        {"RSA_sign",            (void *)SBXK_RSA_sign,            (void **)&orig_RSA_sign},
        {"RSA_verify",          (void *)SBXK_RSA_verify,          (void **)&orig_RSA_verify},
        {"RSA_check_key",       (void *)SBXK_RSA_check_key,       (void **)&orig_RSA_check_key},
        {"RSA_generate_key",    (void *)SBXK_RSA_generate_key,    (void **)&orig_RSA_generate_key},
        {"RSA_padding_add_PKCS1_type_1", (void *)SBXK_RSA_padding_add_PKCS1_type_1, (void **)&orig_RSA_padding_add_PKCS1_type_1},
        {"RSA_padding_add_PKCS1_type_2", (void *)SBXK_RSA_padding_add_PKCS1_type_2, (void **)&orig_RSA_padding_add_PKCS1_type_2},

        // AES / DES
        {"AES_set_encrypt_key", (void *)SBXK_AES_set_encrypt_key, (void **)&orig_AES_set_encrypt_key},
        {"AES_set_decrypt_key", (void *)SBXK_AES_set_decrypt_key, (void **)&orig_AES_set_decrypt_key},
        {"AES_encrypt",         (void *)SBXK_AES_encrypt,         (void **)&orig_AES_encrypt},
        {"AES_decrypt",         (void *)SBXK_AES_decrypt,         (void **)&orig_AES_decrypt},
        {"AES_cbc_encrypt",     (void *)SBXK_AES_cbc_encrypt,     (void **)&orig_AES_cbc_encrypt},
        {"DES_encrypt",         (void *)SBXK_DES_encrypt,         (void **)&orig_DES_encrypt},
        {"DES_decrypt",         (void *)SBXK_DES_decrypt,         (void **)&orig_DES_decrypt},
        {"DES_cbc_encrypt",     (void *)SBXK_DES_cbc_encrypt,     (void **)&orig_DES_cbc_encrypt},
        {"DES_set_key",         (void *)SBXK_DES_set_key,         (void **)&orig_DES_set_key},

        // Hash
        {"MD5_Init",   (void *)SBXK_MD5_Init,   (void **)&orig_MD5_Init},
        {"MD5_Update", (void *)SBXK_MD5_Update, (void **)&orig_MD5_Update},
        {"MD5_Final",  (void *)SBXK_MD5_Final,  (void **)&orig_MD5_Final},
        {"SHA1_Init",  (void *)SBXK_SHA1_Init,  (void **)&orig_SHA1_Init},
        {"SHA1_Update",(void *)SBXK_SHA1_Update,(void **)&orig_SHA1_Update},
        {"SHA1_Final", (void *)SBXK_SHA1_Final, (void **)&orig_SHA1_Final},
        {"SHA256_Init",(void *)SBXK_SHA256_Init,(void **)&orig_SHA256_Init},
        {"SHA256_Update",(void *)SBXK_SHA256_Update,(void **)&orig_SHA256_Update},
        {"SHA256_Final",(void *)SBXK_SHA256_Final,(void **)&orig_SHA256_Final},
        {"SHA512_Init",(void *)SBXK_SHA512_Init,(void **)&orig_SHA512_Init},
        {"SHA512_Update",(void *)SBXK_SHA512_Update,(void **)&orig_SHA512_Update},
        {"SHA512_Final",(void *)SBXK_SHA512_Final,(void **)&orig_SHA512_Final},

        {"HMAC_Init",  (void *)SBXK_HMAC_Init,  (void **)&orig_HMAC_Init},
        {"HMAC_Update",(void *)SBXK_HMAC_Update,(void **)&orig_HMAC_Update},
        {"HMAC_Final", (void *)SBXK_HMAC_Final, (void **)&orig_HMAC_Final},

        // EVP
        {"EVP_SignFinal",     (void *)SBXK_EVP_SignFinal,     (void **)&orig_EVP_SignFinal},
        {"EVP_VerifyFinal",   (void *)SBXK_EVP_VerifyFinal,   (void **)&orig_EVP_VerifyFinal},
        {"EVP_DigestSign",    (void *)SBXK_EVP_DigestSign,    (void **)&orig_EVP_DigestSign},
        {"EVP_DigestVerify",  (void *)SBXK_EVP_DigestVerify,  (void **)&orig_EVP_DigestVerify},
        {"X509_verify_cert",  (void *)SBXK_X509_verify_cert,  (void **)&orig_X509_verify_cert},
        {"SSL_get_verify_result", (void *)SBXK_SSL_get_verify_result, (void **)&orig_SSL_get_verify_result},
        {"SSL_CTX_set_verify",(void *)SBXK_SSL_CTX_set_verify,(void **)&orig_SSL_CTX_set_verify},
        {"SSL_set_verify",    (void *)SBXK_SSL_set_verify,    (void **)&orig_SSL_set_verify},

        // RAND
        {"RAND_bytes", (void *)SBXK_RAND_bytes, (void **)&orig_RAND_bytes},

        // libSystem
        {"access", (void *)SBXK_access, (void **)&orig_access},
    };
    rebind_symbols(binds, sizeof(binds) / sizeof(binds[0]));
}

#pragma mark =========================================================
#pragma mark 13. ENTRY
#pragma mark =========================================================

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        SBXK_LOG(@"boot");

        // 1. Fishhook di main thread dulu — supaya symbol libcrypto/libSystem tertangkap sebelum game main.
        SBXK_InstallFishhook();

        // 2. Swizzle semua kelas (aman kalau kelas belum ada → di-skip).
        SBXK_InstallAllSwizzles();

        // 3. FileManager.
        SBXK_InstallFileManagerSwizzle();

        // 4. AppDelegate proxy (kalau AppDelegate sudah kebentuk).
        [SBXK_AppDelegateProxy installIfPossible];

        // 5. Timer pembersih — jalan setelah app aktif.
        SBXK_StartCleanupTimer();

        SBXK_LOG(@"ready");
    }
}
