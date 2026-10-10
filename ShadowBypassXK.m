// ============================================================================
// ShadowBypass XK v2 — single-file iOS arm64/arm64e implant (no jailbreak)
//
// Build (macOS + Xcode 15+):
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -arch arm64e \
//         -isysroot "$SDK" -miphoneos-version-min=13.0 \
//         -fobjc-arc -O2 -dynamiclib \
//         -Wno-incompatible-pointer-types \
//         -Wno-implicit-function-declaration \
//         -Wno-nullability-completeness \
//         ShadowBypassXK.m \
//         -framework Foundation -framework UIKit -framework Security \
//         -framework AdSupport -framework AppTrackingTransparency \
//         -o ShadowBypassXK.dylib
//
// Inject: sideload + LC_LOAD_DYLIB patch, TrollStore, atau CoreTrust bundle.
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach-o/getsect.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <unistd.h>
#import <errno.h>
#import <string.h>
#import <stdint.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <AdSupport/AdSupport.h>
#if __has_include(<AppTrackingTransparency/AppTrackingTransparency.h>)
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#endif

#pragma mark =========================================================
#pragma mark 0. LOGGING
#pragma mark =========================================================

#define SBXK_LOG(fmt, ...) NSLog(@"[SBXK] " fmt, ##__VA_ARGS__)

#pragma mark =========================================================
#pragma mark 1. INLINE SYMBOL REBINDING (compact fishhook)
#pragma mark =========================================================

typedef struct {
    const char *name;         // symbol asm name (no leading _)
    void       *replacement;
    void      **replaced;
} sbxk_binding_t;

static int sbxk_rebind_image(const struct mach_header_64 *mh,
                             const sbxk_binding_t *binds, int nbinds)
{
    intptr_t slide = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        if (_dyld_get_image_header(i) == (const struct mach_header *)mh) {
            slide = _dyld_get_image_vmaddr_slide(i);
            break;
        }
    }

    uintptr_t linkedit_base = 0;
    const struct symtab_command   *symtab = NULL;
    const struct dysymtab_command *dysym  = NULL;

    const struct load_command *lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__LINKEDIT") == 0) {
                linkedit_base = (uintptr_t)seg->vmaddr - seg->fileoff + (uintptr_t)slide;
            }
        } else if (lc->cmd == LC_SYMTAB) {
            symtab = (const struct symtab_command *)lc;
        } else if (lc->cmd == LC_DYSYMTAB) {
            dysym = (const struct dysymtab_command *)lc;
        }
        lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }
    if (!linkedit_base || !symtab || !dysym) return -1;

    const struct nlist_64 *symtab_array =
        (const struct nlist_64 *)(linkedit_base + symtab->symoff);
    const char *strtab = (const char *)(linkedit_base + symtab->stroff);
    const uint32_t *indirect =
        (const uint32_t *)(linkedit_base + dysym->indirectsymoff);

    lc = (const struct load_command *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            const struct section_64 *sect = (const struct section_64 *)(seg + 1);
            for (uint32_t j = 0; j < seg->nsects; j++, sect++) {
                uint8_t type = sect->flags & SECTION_TYPE;
                if (type != S_LAZY_SYMBOL_POINTERS &&
                    type != S_NON_LAZY_SYMBOL_POINTERS) continue;

                uint32_t nsyms = (uint32_t)(sect->size / 8);
                uint32_t base  = sect->reserved1;
                void **ptrs = (void **)(sect->addr + slide);

                for (uint32_t k = 0; k < nsyms; k++) {
                    uint32_t idx = indirect[base + k];
                    const struct nlist_64 *sym = &symtab_array[idx];
                    if ((sym->n_type & N_TYPE) != N_UNDF) continue;
                    const char *name = strtab + sym->n_un.n_strx;
                    if (name[0] == '_') name++;
                    for (int b = 0; b < nbinds; b++) {
                        if (strcmp(name, binds[b].name) != 0) continue;
                        if (binds[b].replaced) *binds[b].replaced = ptrs[k];
                        ptrs[k] = binds[b].replacement;
                        break;
                    }
                }
            }
        }
        lc = (const struct load_command *)((uintptr_t)lc + lc->cmdsize);
    }
    return 0;
}

static void sbxk_rebind_all(const sbxk_binding_t *binds, int nbinds) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const struct mach_header *h = _dyld_get_image_header(i);
        if (!h) continue;
        if (h->magic == MH_MAGIC_64) {
            sbxk_rebind_image((const struct mach_header_64 *)h, binds, nbinds);
        }
    }
}

#pragma mark =========================================================
#pragma mark 2. SWIZZLE ENGINE
#pragma mark =========================================================

static void SBXK_HookInstanceMethod(const char *cls, const char *sel, IMP imp) {
    Class c = objc_getClass(cls);
    if (!c) return;
    SEL s = sel_registerName(sel);
    Method m = class_getInstanceMethod(c, s);
    if (!m) return;
    class_replaceMethod(c, s, imp, method_getTypeEncoding(m));
}

#define HOOK_I(cls, sel) SBXK_HookInstanceMethod(#cls, sel, (IMP)SBXK_##cls##_##sel)

#pragma mark =========================================================
#pragma mark 3. ORIGINAL POINTERS (populated by rebind)
#pragma mark =========================================================

// RSA
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

// AES / DES
static int  (*orig_AES_set_encrypt_key)(const unsigned char *, int, void *);
static int  (*orig_AES_set_decrypt_key)(const unsigned char *, int, void *);
static void (*orig_AES_encrypt)(const unsigned char *, unsigned char *, const void *);
static void (*orig_AES_decrypt)(const unsigned char *, unsigned char *, const void *);
static int  (*orig_AES_cbc_encrypt)(const unsigned char *, unsigned char *, size_t, const void *, unsigned char *, int);
static void (*orig_DES_encrypt)(unsigned long *, void *, int);
static void (*orig_DES_decrypt)(unsigned long *, void *, int);
static int  (*orig_DES_cbc_encrypt)(const unsigned char *, unsigned char *, long, void *, unsigned char *, int);
static int  (*orig_DES_set_key)(const unsigned char *, void *);

// Hash
static int (*orig_MD5_Init)(void *);
static int (*orig_MD5_Update)(void *, const void *, size_t);
static int (*orig_MD5_Final)(unsigned char *, void *);
static int (*orig_SHA1_Init)(void *);
static int (*orig_SHA1_Update)(void *, const void *, size_t);
static int (*orig_SHA1_Final)(unsigned char *, void *);
static int (*orig_SHA256_Init)(void *);
static int (*orig_SHA256_Update)(void *, const void *, size_t);
static int (*orig_SHA256_Final)(unsigned char *, void *);
static int (*orig_SHA512_Init)(void *);
static int (*orig_SHA512_Update)(void *, const void *, size_t);
static int (*orig_SHA512_Final)(unsigned char *, void *);
static int (*orig_HMAC_Init)(void *, const void *, int, const void *);
static int (*orig_HMAC_Update)(void *, const void *, size_t);
static int (*orig_HMAC_Final)(void *, unsigned char *, unsigned int *);

// EVP / SSL / X509
static int  (*orig_EVP_SignFinal)(void *, unsigned char *, unsigned int *, void *);
static int  (*orig_EVP_VerifyFinal)(void *, const unsigned char *, unsigned int, void *);
static int  (*orig_EVP_DigestSign)(void *, unsigned char *, size_t *, const unsigned char *, size_t);
static int  (*orig_EVP_DigestVerify)(void *, const unsigned char *, size_t, const unsigned char *, size_t);
static int  (*orig_X509_verify_cert)(void *);
static long (*orig_SSL_get_verify_result)(const void *);
static int  (*orig_SSL_CTX_set_verify)(void *, int, void *);
static void (*orig_SSL_set_verify)(void *, int, void *);

// RAND / POSIX
static int (*orig_RAND_bytes)(unsigned char *, int);
static int (*orig_access)(const char *, int);

#pragma mark =========================================================
#pragma mark 4. CRYPTO HOOKS
#pragma mark =========================================================

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
static int SBXK_RSA_sign(int type, const unsigned char *m, unsigned int ml,
                         unsigned char *sig, unsigned int *sl, void *rsa) {
    int r = orig_RSA_sign ? orig_RSA_sign(type, m, ml, sig, sl, rsa) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_verify(int type, const unsigned char *m, unsigned int ml,
                           const unsigned char *sig, unsigned int sl, void *rsa) {
    (void)type; (void)m; (void)ml; (void)sig; (void)sl; (void)rsa;
    (void)orig_RSA_verify;
    return 1;
}
static int SBXK_RSA_check_key(const void *rsa) { (void)rsa; (void)orig_RSA_check_key; return 1; }
static int SBXK_RSA_generate_key(void *rsa, int bits, unsigned long e, void *cb) {
    int r = orig_RSA_generate_key ? orig_RSA_generate_key(rsa, bits, e, cb) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_padding_add_PKCS1_type_1(unsigned char *to, int tl,
                                             const unsigned char *f, int fl) {
    int r = orig_RSA_padding_add_PKCS1_type_1 ? orig_RSA_padding_add_PKCS1_type_1(to, tl, f, fl) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_RSA_padding_add_PKCS1_type_2(unsigned char *to, int tl,
                                             const unsigned char *f, int fl) {
    int r = orig_RSA_padding_add_PKCS1_type_2 ? orig_RSA_padding_add_PKCS1_type_2(to, tl, f, fl) : 1;
    return (r != 1) ? 1 : r;
}

static int SBXK_AES_set_encrypt_key(const unsigned char *k, int b, void *key) {
    int r = orig_AES_set_encrypt_key ? orig_AES_set_encrypt_key(k, b, key) : 0;
    return (r != 0) ? 0 : r;
}
static int SBXK_AES_set_decrypt_key(const unsigned char *k, int b, void *key) {
    int r = orig_AES_set_decrypt_key ? orig_AES_set_decrypt_key(k, b, key) : 0;
    return (r != 0) ? 0 : r;
}
static void SBXK_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (orig_AES_encrypt) orig_AES_encrypt(in, out, key);
    else if (out) memset(out, 0, 16);
}
static void SBXK_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (orig_AES_decrypt) orig_AES_decrypt(in, out, key);
    else if (out) memset(out, 0, 16);
}
static int SBXK_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len,
                                const void *key, unsigned char *ivec, int enc) {
    if (orig_AES_cbc_encrypt) return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
    if (in && out && len) memcpy(out, in, len);
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
    if (in && out && len > 0) memcpy(out, in, (size_t)len);
    return 1;
}
static int SBXK_DES_set_key(const unsigned char *k, void *sched) {
    int r = orig_DES_set_key ? orig_DES_set_key(k, sched) : 0;
    return (r != 0) ? 0 : r;
}

static int SBXK_MD5_Init(void *c) { int r = orig_MD5_Init ? orig_MD5_Init(c) : 1; return (r != 1) ? 1 : r; }
static int SBXK_MD5_Update(void *c, const void *d, size_t n) { return orig_MD5_Update ? orig_MD5_Update(c, d, n) : 1; }
static int SBXK_MD5_Final(unsigned char *md, void *c) { int r = orig_MD5_Final ? orig_MD5_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA1_Init(void *c) { int r = orig_SHA1_Init ? orig_SHA1_Init(c) : 1; return (r != 1) ? 1 : r; }
static int SBXK_SHA1_Update(void *c, const void *d, size_t n) { return orig_SHA1_Update ? orig_SHA1_Update(c, d, n) : 1; }
static int SBXK_SHA1_Final(unsigned char *md, void *c) { int r = orig_SHA1_Final ? orig_SHA1_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA256_Init(void *c) { int r = orig_SHA256_Init ? orig_SHA256_Init(c) : 1; return (r != 1) ? 1 : r; }
static int SBXK_SHA256_Update(void *c, const void *d, size_t n) { return orig_SHA256_Update ? orig_SHA256_Update(c, d, n) : 1; }
static int SBXK_SHA256_Final(unsigned char *md, void *c) { int r = orig_SHA256_Final ? orig_SHA256_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_SHA512_Init(void *c) { int r = orig_SHA512_Init ? orig_SHA512_Init(c) : 1; return (r != 1) ? 1 : r; }
static int SBXK_SHA512_Update(void *c, const void *d, size_t n) { return orig_SHA512_Update ? orig_SHA512_Update(c, d, n) : 1; }
static int SBXK_SHA512_Final(unsigned char *md, void *c) { int r = orig_SHA512_Final ? orig_SHA512_Final(md, c) : 1; return (r != 1) ? 1 : r; }

static int SBXK_HMAC_Init(void *ctx, const void *k, int kl, const void *md) {
    int r = orig_HMAC_Init ? orig_HMAC_Init(ctx, k, kl, md) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_HMAC_Update(void *ctx, const void *d, size_t n) {
    return orig_HMAC_Update ? orig_HMAC_Update(ctx, d, n) : 1;
}
static int SBXK_HMAC_Final(void *ctx, unsigned char *md, unsigned int *len) {
    int r = orig_HMAC_Final ? orig_HMAC_Final(ctx, md, len) : 1;
    return (r != 1) ? 1 : r;
}

static int SBXK_EVP_SignFinal(void *ctx, unsigned char *md, unsigned int *s, void *pk) {
    int r = orig_EVP_SignFinal ? orig_EVP_SignFinal(ctx, md, s, pk) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_EVP_VerifyFinal(void *ctx, const unsigned char *sig, unsigned int sl, void *pk) {
    (void)ctx; (void)sig; (void)sl; (void)pk; (void)orig_EVP_VerifyFinal;
    return 1;
}
static int SBXK_EVP_DigestSign(void *ctx, unsigned char *sig, size_t *sl,
                               const unsigned char *tbs, size_t tbl) {
    int r = orig_EVP_DigestSign ? orig_EVP_DigestSign(ctx, sig, sl, tbs, tbl) : 1;
    return (r != 1) ? 1 : r;
}
static int SBXK_EVP_DigestVerify(void *ctx, const unsigned char *sig, size_t sl,
                                 const unsigned char *tbs, size_t tbl) {
    (void)ctx; (void)sig; (void)sl; (void)tbs; (void)tbl; (void)orig_EVP_DigestVerify;
    return 1;
}

static int SBXK_X509_verify_cert(void *ctx) { (void)ctx; (void)orig_X509_verify_cert; return 1; }
static long SBXK_SSL_get_verify_result(const void *ssl) { (void)ssl; (void)orig_SSL_get_verify_result; return 0; }

static int SBXK_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    (void)mode; (void)cb;
    if (orig_SSL_CTX_set_verify) return orig_SSL_CTX_set_verify(ctx, 0, NULL);
    return 1;
}
static void SBXK_SSL_set_verify(void *ssl, int mode, void *cb) {
    (void)mode; (void)cb;
    if (orig_SSL_set_verify) orig_SSL_set_verify(ssl, 0, NULL);
}

static int SBXK_RAND_bytes(unsigned char *buf, int n) {
    return orig_RAND_bytes ? orig_RAND_bytes(buf, n) : 1;
}

static int SBXK_access(const char *path, int amode) {
    static const char *jb[] = {
        "/Applications/Cydia.app", "/Applications/Sileo.app",
        "/Applications/Zebra.app", "/Library/MobileSubstrate",
        "/Library/MobileSubstrate/DynamicLibraries", "/bin/bash", "/bin/sh",
        "/etc/apt", "/private/var/lib/apt", "/private/var/tmp/cydia.log",
        "/usr/bin/cycript", "/usr/bin/ssh", "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd", "/var/cache/apt", "/var/lib/cydia",
        "/var/log/syslog", "/var/tmp/cydia.log", NULL
    };
    if (path) {
        for (int i = 0; jb[i]; i++) {
            if (strcmp(path, jb[i]) == 0) { errno = ENOENT; return -1; }
        }
    }
    return orig_access ? orig_access(path, amode) : -1;
}

#pragma mark =========================================================
#pragma mark 5. INTEGRITY / DETECT HOOKS
#pragma mark =========================================================

#define IMP_NO(cls, sel)  static BOOL SBXK_##cls##_##sel(id s, SEL c) { (void)s; (void)c; return NO; }
#define IMP_YES(cls, sel) static BOOL SBXK_##cls##_##sel(id s, SEL c) { (void)s; (void)c; return YES; }

// Jailbreak / simulator / debugger / hook / tamper / injection / reversing detection
IMP_NO(IntegrityChecker, integrity_detect)
IMP_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
IMP_NO(JailbreakDetector, isJailbroken)
IMP_NO(JailbreakDetector, isJailbreak)
IMP_NO(JailbreakDetector, checkJailbreak)
IMP_NO(JailbreakDetector, jailbreakDetection)
IMP_NO(SimulatorDetector, isSimulator)
IMP_NO(SimulatorDetector, isSimulatorDevice)
IMP_NO(SimulatorDetector, checkSimulator)
IMP_NO(SecurityChecker, IsFileSystemModified)
IMP_NO(SecurityChecker, isDebuggerAttached)
IMP_NO(SecurityChecker, isDebugged)
IMP_NO(SecurityChecker, checkDebugger)
IMP_NO(SecurityChecker, amIBeingDebugged)
IMP_NO(SecurityChecker, checkDebuggerAttach)
IMP_NO(SecurityChecker, isHooked)
IMP_NO(SecurityChecker, isHookDetected)
IMP_NO(SecurityChecker, checkHook)
IMP_NO(SecurityChecker, detectHook)
IMP_NO(SecurityChecker, antiHookCheck)
IMP_NO(SecurityChecker, isTampered)
IMP_NO(SecurityChecker, checkTamper)
IMP_NO(SecurityChecker, antiTamperCheck)
IMP_NO(SecurityChecker, isInjected)
IMP_NO(SecurityChecker, isLibraryInjected)
IMP_NO(SecurityChecker, checkInjection)
IMP_NO(SecurityChecker, antiInjectionCheck)
IMP_NO(SecurityChecker, isReversingDetected)
IMP_NO(SecurityChecker, checkReversing)
IMP_NO(SecurityChecker, antiReversingCheck)
IMP_NO(SecurityChecker, isBlocked)
IMP_NO(SecurityChecker, antiBlockingCheck)

IMP_YES(SecurityChecker, verifyIntegrity)
IMP_YES(SecurityChecker, checkTokenValid)
IMP_YES(SecurityChecker, checkConfigSignValidity)
IMP_YES(SecurityChecker, verify_file_md5)
IMP_YES(SecurityChecker, CheckFileMd5)
IMP_YES(SecurityChecker, CheckFileHeader)
IMP_YES(SecurityChecker, IsFileExistInResDir)
IMP_YES(SecurityChecker, verifySignature)

// GAD specific
IMP_YES(GADAppOpenAd, adDidDismissFullScreenContent_)
IMP_YES(GADAppOpenAd, adWillDismissFullScreenContent_)

// GSDK DetectPort / UDP / WIFI / Reachability / Audio
IMP_YES(AReachability, isConnectionOnDemand)
IMP_YES(AReachability, isConnectionRequired)
IMP_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

#pragma mark =========================================================
#pragma mark 6. GAME LOGIC HOOKS
#pragma mark =========================================================

static id SBXK_WeaponProcessor_CalculateDamage(id s, SEL c, id target, float dist) {
    (void)s; (void)c; (void)target; (void)dist; return @(0);
}
static BOOL SBXK_CharacterMovement_IsSpeedExceeded(id s, SEL c) { (void)s; (void)c; return NO; }
static id SBXK_BulletSimulator_CheckWallCollision(id s, SEL c) { (void)s; (void)c; return nil; }
static void SBXK_NetworkManager_SendSecurityReport(id s, SEL c, id r) {
    (void)s; (void)c; (void)r; SBXK_LOG(@"suppressed SecurityReport");
}

#pragma mark =========================================================
#pragma mark 7. GENERIC ZERO-RETURN / NOOP MACROS
#pragma mark =========================================================

#define Z_ID(cls, sel)   static id   SBXK_##cls##_##sel(id s, SEL c) { (void)s; (void)c; return @(0); }
#define N_ID(cls, sel)   static id   SBXK_##cls##_##sel(id s, SEL c) { (void)s; (void)c; return nil;  }
#define Z_ID_A(cls, sel, a)          static id SBXK_##cls##_##sel(id s, SEL c, id a) { (void)s;(void)c;(void)a; return @(0); }
#define Z_ID_AA(cls, sel, a, b)      static id SBXK_##cls##_##sel(id s, SEL c, id a, id b) { (void)s;(void)c;(void)a;(void)b; return @(0); }
#define Z_ID_AAA(cls, sel, a, b, cc) static id SBXK_##cls##_##sel(id s, SEL c, id a, id b, id cc) { (void)s;(void)c;(void)a;(void)b;(void)cc; return @(0); }
#define Z_ID_AB(cls, sel, a, b)      static id SBXK_##cls##_##sel(id s, SEL c, id a, BOOL b) { (void)s;(void)c;(void)a;(void)b; return @(0); }
#define Z_V_A(cls, sel, a)           static void SBXK_##cls##_##sel(id s, SEL c, id a) { (void)s;(void)c;(void)a; }
#define Z_V_AB(cls, sel, a, b)       static void SBXK_##cls##_##sel(id s, SEL c, id a, BOOL b) { (void)s;(void)c;(void)a;(void)b; }
#define Z_V_AI(cls, sel, a, b)       static void SBXK_##cls##_##sel(id s, SEL c, id a, int b) { (void)s;(void)c;(void)a;(void)b; }
#define Z_V_AA(cls, sel, a, b)       static void SBXK_##cls##_##sel(id s, SEL c, id a, id b) { (void)s;(void)c;(void)a;(void)b; }
#define Z_V_AAB(cls, sel, a, b, cc)  static void SBXK_##cls##_##sel(id s, SEL c, id a, id b, BOOL cc) { (void)s;(void)c;(void)a;(void)b;(void)cc; }
#define Z_V_AII(cls, sel, a, b, cc)  static void SBXK_##cls##_##sel(id s, SEL c, id a, int b, int cc) { (void)s;(void)c;(void)a;(void)b;(void)cc; }
#define Z_V_AIID(cls, sel, a, b, cc, d) static void SBXK_##cls##_##sel(id s, SEL c, id a, int b, int cc, int d) { (void)s;(void)c;(void)a;(void)b;(void)cc;(void)d; }

#pragma mark =========================================================
#pragma mark 8. GSDK HOOKS
#pragma mark =========================================================

Z_ID(GSDKCPU, getSystemCPUCircle)
Z_ID(GSDKMemory, getSystemAvailableMemory)
Z_ID(GSDKInGameManager, GSDKRealTimeDetect)
Z_ID(GSDKInGameSystem, GSDKInnerEnd)
Z_ID(GSDKInGameSystem, GSDKInnerRealTimeDetect)
Z_ID(GSDKPing, ping)
Z_ID(GSDKPing, stopPing)
Z_ID(GSDKPing, dealloc)
Z_ID(GSDKPingDetect, ping)
Z_ID(GSDKPingDetect, dealloc)
Z_ID(GSDKHttpDnsResolver, dealloc)
Z_ID(GSDKHttpRequest, dealloc)
Z_ID(PingDelegate, pingTimer)
Z_ID(SimplePing, dealloc)
Z_ID(SimplePing, start)
Z_ID(SimplePing, startWithHostAddress)
Z_ID(SimplePing, readData)
Z_ID(GSDKRealTimeDetect, pingDelayDetect_)
Z_ID(GSDKRealTimeDetect, updDelayDetect_Port_)
Z_ID(GSDKUdpDetect, isUDPConnect_Port_)
Z_ID(GSDKWIFI, ping_)
Z_ID(GSDKDetectPort, isConnection_Port_)
Z_ID(GSDKInitManager, detectOperation_)
Z_ID(GSDKPayEvent, GSDKPay_Tag_Status_Msg_)
Z_ID(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env_)
Z_ID(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots_)
Z_ID(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP_)
Z_ID(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error_)
Z_ID(GSDKPing, simplePing_didFailWithError_)
Z_ID(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber_)
Z_ID(GSDKPing, simplePing_didReceiveUnexpectedPacket_)
Z_ID(GSDKPing, simplePing_didSendPacket_sequenceNumber_)
Z_ID(GSDKPing, simplePing_didStartWithAddress_)
Z_ID(GSDKPingDetect, simplePing_didFailToSendPacket_sequenceNumber_error_)
Z_ID(GSDKPingDetect, simplePing_didFailWithError_)
Z_ID(GSDKPingDetect, simplePing_didReceivePingResponsePacket_sequenceNumber_)
Z_ID(GSDKPingDetect, simplePing_didReceiveUnexpectedPacket_)
Z_ID(GSDKPingDetect, simplePing_didSendPacket_sequenceNumber_)
Z_ID(GSDKPingDetect, simplePing_didStartWithAddress_)
Z_ID(PingDelegate, simplePing_didFailToSendPacket_sequenceNumber_error_)
Z_ID(PingDelegate, simplePing_didSendPacket_sequenceNumber_)
Z_ID(SimplePing, didFailWithError_)
Z_ID(SimplePing, sendPingWithData_)
Z_ID(SimplePing, validatePingResponsePacket_sequenceNumber_)
Z_ID(SimplePing, pingPacketWithType_payload_requiresChecksum_)

#pragma mark =========================================================
#pragma mark 9. VOICE (GVoice / GCloud) HOOKS
#pragma mark =========================================================

Z_ID(GVGCloudVoice, openMic)
Z_ID(GVGCloudVoice, openSpeaker)
Z_V_A(GVGCloudVoice, setAppInfo_withKey_andOpenID_, a)   // simplify: 3 args tidak dipakai
Z_ID(GVGCloudVoiceExtension, GetBGMPlayState)
Z_ID(GVGCloudVoiceExtension, GetMicState)
Z_ID(GVGCloudVoiceExtension, GetSpeakerState)
Z_ID(GVGCloudVoiceExtension, EnableKeyWordsDetect_)       // simplify
Z_ID(GVoiceMuteSwitch, detectMuteSwitch)
Z_ID(GCloudVoiceEngine, StartTve)
Z_ID(GCloudVoiceEngine, StopRecording)
Z_ID(GCloudVoiceEngine, TestMic)
Z_ID(GCloudVoiceEngine, StartBGMPlay)
Z_ID(GCloudVoiceEngine, StopBGMPlay)
Z_ID(GCloudVoiceEngine, PauseBGMPlay)
Z_ID(GCloudVoiceEngine, ResumeBGMPlay)
Z_ID(GCloudVoiceEngine, RSTSStopRecording)
Z_ID(GCloudVoiceEngine, TextToStreamSpeechStop)
Z_ID(GCloudVoiceEngine, StartPreview)
Z_ID(GCloudVoiceEngine, StopPreview)
Z_ID(GCloudVoiceEngine, PauseKaraoke)
Z_ID(GCloudVoiceEngine, ResumeKaraoke)
Z_ID(GCloudVoiceEngine, GetMicLevel)
Z_ID(GCloudVoiceEngine, GetSpeakerLevel)
Z_ID(GCloudVoiceEngine, GetBGMLevel)
Z_ID(GCloudVoiceEngine, GetBGMFileTime)
Z_ID(GCloudVoiceEngine, GetBGMPlayTime)
Z_ID(GCloudVoiceEngine, GetRecordKaraokeTotalTime)
Z_ID(GCloudVoiceEngine, StopKaraokeRecording)
Z_ID(GCloudCoreRemoteConfig, updateConfig_)
Z_ID(GCloudCoreRemoteConfig, getConfig_)
Z_ID(GCloudUnityPlugin, Initialize)
Z_ID(GCloudUnityPlugin, ReportEvent)
Z_ID(GCloudUnityPlugin, SetGameObjectName_)
Z_ID(GCloudVoiceEngine, GetFileParam_data_time_)

Z_V_AII(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout_, a, b, c)
Z_V_AI(GCloudVoiceEngine, QuitRoom_Scenes_timeout_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableMultiRoom_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableRoomMicrophone_enable_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableRoomSpeaker_enable_, a, b)
Z_V_AII(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout_, a, b, c)
Z_V_A(GCloudVoiceEngine, StartRecording_, a)
Z_V_A(GCloudVoiceEngine, SetBGMPath_, a)
Z_V_A(GCloudVoiceEngine, SetLogCallBack_, a)
Z_V_AI(GCloudVoiceEngine, SetMicVolume_, a, b)
Z_V_AI(GCloudVoiceEngine, SetSpeakerVolume_, a, b)
Z_V_AI(GCloudVoiceEngine, SetBitRate_, a, b)
Z_V_AI(GCloudVoiceEngine, SetDataFree_, a, b)
Z_V_AI(GCloudVoiceEngine, SetReportBufferTime_, a, b)
Z_V_AI(GCloudVoiceEngine, SetBGMPlayTime_, a, b)
Z_V_AI(GCloudVoiceEngine, SetKaraokeVoiceVol_, a, b)
Z_V_AI(GCloudVoiceEngine, SetKaraokeAccVol_, a, b)
Z_V_AI(GCloudVoiceEngine, SetKaraokeVoiceDelay_, a, b)
Z_V_AI(GCloudVoiceEngine, SeekTimeMsForPreview_, a, b)
Z_V_AI(GCloudVoiceEngine, SeekTimeMsForAcc_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableLog_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableNativeBGMPlay_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableRecvMagicVoice_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableReportALL_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableReportALLAbroad_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableReportForAbroad_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableCivilFile_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableCivilVoice_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableEarBack_, a, b)
Z_V_AB(GCloudVoiceEngine, EnableAccFilePlay_, a, b)

#pragma mark =========================================================
#pragma mark 10. ADS / FIREBASE / QQ / IMSDK / APM
#pragma mark =========================================================

Z_ID(FIRMessagingRmqManager, openDatabase)
Z_ID(FIRMessaging, APNSToken)
Z_ID(FIRMessaging, retrieveFCMTokenForSenderID_completion_)
Z_ID(FIRMessaging, deleteFCMTokenForSenderID_completion_)
Z_ID(FIRMessaging, subscribeToTopic_completion_)
Z_ID(FIRMessaging, unsubscribeFromTopic_completion_)
Z_ID(FIRMessaging, setAPNSToken_withUserInfo_)
Z_ID(GADMobileAds, initializationStatus)
Z_ID(GADAppOpenAd, responseInfo)
Z_ID(GADAppOpenAd, adDidRecordClick_)
Z_ID(GADAppOpenAd, adDidRecordImpression_)
Z_ID(GADAppOpenAd, adWillPresentFullScreenContent_)
Z_ID(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError_)
Z_ID(GADAppOpenAd, setPaidEventHandler_)
Z_ID(GADAdNetworkResponseInfo, adUnitMapping)
Z_ID(FBAdViewabilityValidator, checkViewability_)
Z_ID(FBAdMonitor, startMonitoringAd_)
Z_ID(FBAdViewabilityValidator, stopMonitoring)
Z_ID(FBAdMonitor, stopMonitoring)
Z_ID(FBAdEvent, logEvent_withParameters_)
Z_ID(FBAdLogger, logMessage_withLevel_)
Z_ID(QQApiInterface, sendReq_resultBlock_)
Z_ID(QQApiInterface, sendThirdAppBindGroupReq_resultBlock_)
Z_ID(QQApiInterface, sendThirdAppUnBindGroupReq_resultBlock_)
Z_ID(QQApiInterface, sendThirdAppJoinGroupReq_resultBlock_)
Z_ID(QQApiInterface, sendQueryQQGroupProInfo_resultBlock_)
Z_ID(QQApiInterface, sendMessageToQQAuthWithReq_)
Z_ID(QQApiInterface, sendMessageToQQAvatarWithReq_)
Z_ID(QQApiInterface, sendMessageToFaceCollectionWithReq_)
Z_ID(QQOpenApiUtility, cgiRequestGetSdkConfig_)
Z_ID(TDataMasterApplication, handleOpenURL_)
Z_ID(TDataMasterApplication, reportEventWithSrcID_eventName_AndEventKVArray_)
Z_ID(TcApiTool, openUniversallinkIfNeed_)
Z_ID(GTMSessionFetcher, setSystemCompletionHandler_forSessionIdentifier_)
Z_ID(IMSDKCustomWebView, dealloc)
Z_ID(IMSDKNoticeIMSDKManager, getImageCache_imagePath_imageHash_queue_completeHandle_)
Z_ID(IMSDKNoticeIMSDKManager, imsdkCoreKitNoticeImageFileHash_)
Z_ID(IMSDKStatAdjustManager, reportEvent_eventBody_isRealtime_)
Z_ID(IMSDKStatAdjustManager, reportEvent_params_isRealtime_)
Z_ID(IMSDKStatAdjustManager, reportPurchase_currentCode_expense_isRealTime_)
Z_ID(IMSDKStatAdjustManager, reportRevenue_currencyCode_revenueValue_params_extraJson_)
Z_ID(INTLWebViewManager, openURL_observerID_baseParams_)
Z_ID(APMMonitor, handleEvent_)
Z_ID(APMMonitor, startMonitoring_)
Z_ID(APMDeviceInfoSupport, getBatteryState)
Z_ID(APMDeviceInfoSupport, getThermalState)
Z_ID(APMCollector, collectMetrics_)
Z_ID(APMCollector, reportNow_)
Z_ID(TApmSceneMarker, markLoadLevel_)
Z_ID(TApmSceneMarker, markLevelFin)
Z_ID(TApmSceneMarker, postStepEvent_)
Z_ID(TApmSceneMarker, postStreamEvent_)
Z_ID(serviceCommunication, getValueForKeypath)
Z_ID(AudioDeviceMgr, GetAudioDeviceConnectState)
Z_ID(AudioDeviceMgr, UpdateDeviceState_)
Z_ID(TikTokAuth, authorizeWithPermissions_)
Z_ID(TikTokAuth, handleOpenURL_)
Z_ID(VKAuth, authorizeWithPermissions_)
Z_ID(VKAuth, logout)
Z_ID(SCSDKLoginClient, loginWithCompletion_)
Z_ID(SCSDKLoginClient, logout)

#pragma mark =========================================================
#pragma mark 11. ADVERTISING / TRACKING
#pragma mark =========================================================

static NSString *SBXK_ASIdentifierManager_advertisingIdentifier(id s, SEL c) {
    (void)s; (void)c;
    return @"00000000-0000-0000-0000-000000000000";
}
static NSInteger SBXK_ATTrackingManager_trackingAuthorizationStatus(id s, SEL c) {
    (void)s; (void)c;
    return 3; // authorized
}

#pragma mark =========================================================
#pragma mark 12. NSFileManager SWIZZLE
#pragma mark =========================================================

static NSArray<NSString *> *SBXK_JailbreakPrefixes(void) {
    static NSArray *arr;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[
            @"/Applications/Cydia.app", @"/Applications/Sileo.app",
            @"/Applications/Zebra.app", @"/bin/bash", @"/bin/sh",
            @"/etc/apt", @"/usr/bin/ssh", @"/usr/sbin/sshd",
            @"/private/var/lib/apt", @"/Library/MobileSubstrate",
            @"/var/log/syslog"
        ];
    });
    return arr;
}

static BOOL SBXK_NSFileManager_fileExistsAtPath_(id self, SEL _cmd, NSString *path) {
    for (NSString *p in SBXK_JailbreakPrefixes()) {
        if ([path isEqualToString:p] || [path hasPrefix:p]) return NO;
    }
    IMP orig = class_getMethodImplementation([self class], @selector(SBXK_orig_fileExistsAtPath:));
    if (orig) {
        BOOL (*fn)(id, SEL, NSString *) = (void *)orig;
        return fn(self, @selector(SBXK_orig_fileExistsAtPath:), path);
    }
    return NO;
}

static BOOL SBXK_NSFileManager_fileExistsAtPath_isDirectory_(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    for (NSString *p in SBXK_JailbreakPrefixes()) {
        if ([path isEqualToString:p] || [path hasPrefix:p]) { if (isDir) *isDir = NO; return NO; }
    }
    IMP orig = class_getMethodImplementation([self class], @selector(SBXK_orig_fileExistsAtPath:isDirectory:));
    if (orig) {
        BOOL (*fn)(id, SEL, NSString *, BOOL *) = (void *)orig;
        return fn(self, @selector(SBXK_orig_fileExistsAtPath:isDirectory:), path, isDir);
    }
    return NO;
}

static void SBXK_InstallFileManagerSwizzle(void) {
    Class fm = [NSFileManager class];

    Method m1 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
    if (m1) {
        class_addMethod(fm, @selector(SBXK_orig_fileExistsAtPath:),
                        method_getImplementation(m1),
                        method_getTypeEncoding(m1));
        method_setImplementation(m1, (IMP)SBXK_NSFileManager_fileExistsAtPath_);
    }

    Method m2 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
    if (m2) {
        class_addMethod(fm, @selector(SBXK_orig_fileExistsAtPath:isDirectory:),
                        method_getImplementation(m2),
                        method_getTypeEncoding(m2));
        method_setImplementation(m2, (IMP)SBXK_NSFileManager_fileExistsAtPath_isDirectory_);
    }
}

#pragma mark =========================================================
#pragma mark 13. APPDLEGATE PROXY + BANNER
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

    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"AMAR VIP 2026"
        message:@"حماية عمار مفعلة 😎\nالحساب الآن تحت الحماية الشبحية."
        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"استمرار"
                                          style:UIAlertActionStyleDefault handler:nil]];
    [w.rootViewController presentViewController:a animated:YES completion:nil];
}

@end

#pragma mark =========================================================
#pragma mark 14. FILE CLEANUP TIMER
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
#pragma mark 15. INSTALL ALL SWIZZLES
#pragma mark =========================================================

static void SBXK_InstallAllSwizzles(void) {
    // Detection
    HOOK_I(IntegrityChecker, integrity_detect);
    HOOK_I(IntegrityChecker, MTML_INTEGRITY_DETECT);
    HOOK_I(JailbreakDetector, isJailbroken);
    HOOK_I(JailbreakDetector, isJailbreak);
    HOOK_I(JailbreakDetector, checkJailbreak);
    HOOK_I(JailbreakDetector, jailbreakDetection);
    HOOK_I(SimulatorDetector, isSimulator);
    HOOK_I(SimulatorDetector, isSimulatorDevice);
    HOOK_I(SimulatorDetector, checkSimulator);
    HOOK_I(SecurityChecker, IsFileSystemModified);
    HOOK_I(SecurityChecker, isDebuggerAttached);
    HOOK_I(SecurityChecker, isDebugged);
    HOOK_I(SecurityChecker, checkDebugger);
    HOOK_I(SecurityChecker, amIBeingDebugged);
    HOOK_I(SecurityChecker, checkDebuggerAttach);
    HOOK_I(SecurityChecker, isHooked);
    HOOK_I(SecurityChecker, isHookDetected);
    HOOK_I(SecurityChecker, checkHook);
    HOOK_I(SecurityChecker, detectHook);
    HOOK_I(SecurityChecker, antiHookCheck);
    HOOK_I(SecurityChecker, isTampered);
    HOOK_I(SecurityChecker, checkTamper);
    HOOK_I(SecurityChecker, antiTamperCheck);
    HOOK_I(SecurityChecker, isInjected);
    HOOK_I(SecurityChecker, isLibraryInjected);
    HOOK_I(SecurityChecker, checkInjection);
    HOOK_I(SecurityChecker, antiInjectionCheck);
    HOOK_I(SecurityChecker, isReversingDetected);
    HOOK_I(SecurityChecker, checkReversing);
    HOOK_I(SecurityChecker, antiReversingCheck);
    HOOK_I(SecurityChecker, isBlocked);
    HOOK_I(SecurityChecker, antiBlockingCheck);
    HOOK_I(SecurityChecker, verifyIntegrity);
    HOOK_I(SecurityChecker, checkTokenValid);
    HOOK_I(SecurityChecker, checkConfigSignValidity);
    HOOK_I(SecurityChecker, verify_file_md5);
    HOOK_I(SecurityChecker, CheckFileMd5);
    HOOK_I(SecurityChecker, CheckFileHeader);
    HOOK_I(SecurityChecker, IsFileExistInResDir);
    HOOK_I(SecurityChecker, verifySignature);

    // Game logic
    HOOK_I(WeaponProcessor, CalculateDamage);
    HOOK_I(CharacterMovement, IsSpeedExceeded);
    HOOK_I(BulletSimulator, CheckWallCollision);
    HOOK_I(NetworkManager, SendSecurityReport);

    // GSDK
    HOOK_I(GSDKCPU, getSystemCPUCircle);
    HOOK_I(GSDKMemory, getSystemAvailableMemory);
    HOOK_I(GSDKInGameManager, GSDKRealTimeDetect);
    HOOK_I(GSDKInGameSystem, GSDKInnerEnd);
    HOOK_I(GSDKInGameSystem, GSDKInnerRealTimeDetect);
    HOOK_I(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots_);
    HOOK_I(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP_);
    HOOK_I(GSDKInitManager, detectOperation_);
    HOOK_I(GSDKPayEvent, GSDKPay_Tag_Status_Msg_);
    HOOK_I(GSDKHttpDnsResolver, dealloc);
    HOOK_I(GSDKHttpRequest, dealloc);
    HOOK_I(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env_);
    HOOK_I(GSDKDetectPort, isConnection_Port_);
    HOOK_I(GSDKRealTimeDetect, pingDelayDetect_);
    HOOK_I(GSDKRealTimeDetect, updDelayDetect_Port_);
    HOOK_I(GSDKUdpDetect, isUDPConnect_Port_);
    HOOK_I(GSDKWIFI, ping_);
    HOOK_I(GSDKPing, dealloc);
    HOOK_I(GSDKPing, ping);
    HOOK_I(GSDKPing, stopPing);
    HOOK_I(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error_);
    HOOK_I(GSDKPing, simplePing_didFailWithError_);
    HOOK_I(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber_);
    HOOK_I(GSDKPing, simplePing_didReceiveUnexpectedPacket_);
    HOOK_I(GSDKPing, simplePing_didSendPacket_sequenceNumber_);
    HOOK_I(GSDKPing, simplePing_didStartWithAddress_);
    HOOK_I(GSDKPingDetect, dealloc);
    HOOK_I(GSDKPingDetect, ping);
    HOOK_I(GSDKPingDetect, simplePing_didFailToSendPacket_sequenceNumber_error_);
    HOOK_I(GSDKPingDetect, simplePing_didFailWithError_);
    HOOK_I(GSDKPingDetect, simplePing_didReceivePingResponsePacket_sequenceNumber_);
    HOOK_I(GSDKPingDetect, simplePing_didReceiveUnexpectedPacket_);
    HOOK_I(GSDKPingDetect, simplePing_didSendPacket_sequenceNumber_);
    HOOK_I(GSDKPingDetect, simplePing_didStartWithAddress_);
    HOOK_I(PingDelegate, pingTimer);
    HOOK_I(PingDelegate, simplePing_didFailToSendPacket_sequenceNumber_error_);
    HOOK_I(PingDelegate, simplePing_didSendPacket_sequenceNumber_);
    HOOK_I(SimplePing, dealloc);
    HOOK_I(SimplePing, didFailWithError_);
    HOOK_I(SimplePing, pingPacketWithType_payload_requiresChecksum_);
    HOOK_I(SimplePing, readData);
    HOOK_I(SimplePing, sendPingWithData_);
    HOOK_I(SimplePing, start);
    HOOK_I(SimplePing, startWithHostAddress);
    HOOK_I(SimplePing, validatePingResponsePacket_sequenceNumber_);

    // Voice
    HOOK_I(GVGCloudVoice, openMic);
    HOOK_I(GVGCloudVoice, openSpeaker);
    HOOK_I(GVGCloudVoice, setAppInfo_withKey_andOpenID_);
    HOOK_I(GVGCloudVoiceExtension, CheckDeviceMuteStat);
    HOOK_I(GVGCloudVoiceExtension, EnableKeyWordsDetect_);
    HOOK_I(GVGCloudVoiceExtension, GetBGMPlayState);
    HOOK_I(GVGCloudVoiceExtension, GetMicState);
    HOOK_I(GVGCloudVoiceExtension, GetSpeakerState);
    HOOK_I(GVoiceMuteSwitch, detectMuteSwitch);
    HOOK_I(GCloudVoiceEngine, StartTve);
    HOOK_I(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout_);
    HOOK_I(GCloudVoiceEngine, QuitRoom_Scenes_timeout_);
    HOOK_I(GCloudVoiceEngine, EnableMultiRoom_);
    HOOK_I(GCloudVoiceEngine, EnableRoomMicrophone_enable_);
    HOOK_I(GCloudVoiceEngine, EnableRoomSpeaker_enable_);
    HOOK_I(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout_);
    HOOK_I(GCloudVoiceEngine, StartRecording_);
    HOOK_I(GCloudVoiceEngine, StopRecording);
    HOOK_I(GCloudVoiceEngine, EnableLog_);
    HOOK_I(GCloudVoiceEngine, SetLogCallBack_);
    HOOK_I(GCloudVoiceEngine, GetMicLevel);
    HOOK_I(GCloudVoiceEngine, GetSpeakerLevel);
    HOOK_I(GCloudVoiceEngine, SetMicVolume_);
    HOOK_I(GCloudVoiceEngine, SetSpeakerVolume_);
    HOOK_I(GCloudVoiceEngine, TestMic);
    HOOK_I(GCloudVoiceEngine, GetFileParam_data_time_);
    HOOK_I(GCloudVoiceEngine, SetBGMPath_);
    HOOK_I(GCloudVoiceEngine, StartBGMPlay);
    HOOK_I(GCloudVoiceEngine, StopBGMPlay);
    HOOK_I(GCloudVoiceEngine, PauseBGMPlay);
    HOOK_I(GCloudVoiceEngine, ResumeBGMPlay);
    HOOK_I(GCloudVoiceEngine, EnableNativeBGMPlay_);
    HOOK_I(GCloudVoiceEngine, SetBitRate_);
    HOOK_I(GCloudVoiceEngine, SetDataFree_);
    HOOK_I(GCloudVoiceEngine, RSTSStopRecording);
    HOOK_I(GCloudVoiceEngine, TextToStreamSpeechStop);
    HOOK_I(GCloudVoiceEngine, EnableRecvMagicVoice_);
    HOOK_I(GCloudVoiceEngine, EnableReportALL_);
    HOOK_I(GCloudVoiceEngine, EnableReportALLAbroad_);
    HOOK_I(GCloudVoiceEngine, EnableReportForAbroad_);
    HOOK_I(GCloudVoiceEngine, EnableCivilFile_);
    HOOK_I(GCloudVoiceEngine, EnableCivilVoice_);
    HOOK_I(GCloudVoiceEngine, EnableEarBack_);
    HOOK_I(GCloudVoiceEngine, StopKaraokeRecording);
    HOOK_I(GCloudVoiceEngine, EnableAccFilePlay_);
    HOOK_I(GCloudVoiceEngine, SetKaraokeVoiceVol_);
    HOOK_I(GCloudVoiceEngine, SetKaraokeAccVol_);
    HOOK_I(GCloudVoiceEngine, SetKaraokeVoiceDelay_);
    HOOK_I(GCloudVoiceEngine, StartPreview);
    HOOK_I(GCloudVoiceEngine, StopPreview);
    HOOK_I(GCloudVoiceEngine, SeekTimeMsForPreview_);
    HOOK_I(GCloudVoiceEngine, SeekTimeMsForAcc_);
    HOOK_I(GCloudVoiceEngine, PauseKaraoke);
    HOOK_I(GCloudVoiceEngine, ResumeKaraoke);
    HOOK_I(GCloudVoiceEngine, GetRecordKaraokeTotalTime);
    HOOK_I(GCloudVoiceEngine, GetBGMLevel);
    HOOK_I(GCloudVoiceEngine, SetReportBufferTime_);
    HOOK_I(GCloudVoiceEngine, GetBGMFileTime);
    HOOK_I(GCloudVoiceEngine, GetBGMPlayTime);
    HOOK_I(GCloudVoiceEngine, SetBGMPlayTime_);

    // GCloud core
    HOOK_I(GCloudCoreRemoteConfig, updateConfig_);
    HOOK_I(GCloudCoreRemoteConfig, getConfig_);
    HOOK_I(GCloudUnityPlugin, Initialize);
    HOOK_I(GCloudUnityPlugin, ReportEvent);
    HOOK_I(GCloudUnityPlugin, SetGameObjectName_);

    // APM
    HOOK_I(APMMonitor, handleEvent_);
    HOOK_I(APMMonitor, startMonitoring_);
    HOOK_I(APMDeviceInfoSupport, getBatteryState);
    HOOK_I(APMDeviceInfoSupport, getThermalState);
    HOOK_I(APMCollector, collectMetrics_);
    HOOK_I(APMCollector, reportNow_);
    HOOK_I(TApmSceneMarker, markLoadLevel_);
    HOOK_I(TApmSceneMarker, markLevelFin);
    HOOK_I(TApmSceneMarker, postStepEvent_);
    HOOK_I(TApmSceneMarker, postStreamEvent_);

    // IMSDK
    HOOK_I(IMSDKCustomWebView, dealloc);
    HOOK_I(IMSDKNoticeIMSDKManager, getImageCache_imagePath_imageHash_queue_completeHandle_);
    HOOK_I(IMSDKNoticeIMSDKManager, imsdkCoreKitNoticeImageFileHash_);
    HOOK_I(IMSDKStatAdjustManager, reportEvent_eventBody_isRealtime_);
    HOOK_I(IMSDKStatAdjustManager, reportEvent_params_isRealtime_);
    HOOK_I(IMSDKStatAdjustManager, reportPurchase_currentCode_expense_isRealTime_);
    HOOK_I(IMSDKStatAdjustManager, reportRevenue_currencyCode_revenueValue_params_extraJson_);
    HOOK_I(INTLWebViewManager, openURL_observerID_baseParams_);

    // Firebase / GAD / FB
    HOOK_I(FIRMessagingRmqManager, openDatabase);
    HOOK_I(FIRMessaging, retrieveFCMTokenForSenderID_completion_);
    HOOK_I(FIRMessaging, deleteFCMTokenForSenderID_completion_);
    HOOK_I(FIRMessaging, subscribeToTopic_completion_);
    HOOK_I(FIRMessaging, unsubscribeFromTopic_completion_);
    HOOK_I(FIRMessaging, setAPNSToken_withUserInfo_);
    HOOK_I(FIRMessaging, APNSToken);
    HOOK_I(GADAdNetworkResponseInfo, adUnitMapping);
    HOOK_I(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError_);
    HOOK_I(GADAppOpenAd, adDidDismissFullScreenContent_);
    HOOK_I(GADAppOpenAd, adDidRecordClick_);
    HOOK_I(GADAppOpenAd, adDidRecordImpression_);
    HOOK_I(GADAppOpenAd, adWillDismissFullScreenContent_);
    HOOK_I(GADAppOpenAd, adWillPresentFullScreenContent_);
    HOOK_I(GADAppOpenAd, responseInfo);
    HOOK_I(GADAppOpenAd, setPaidEventHandler_);
    HOOK_I(GADMobileAds, initializationStatus);
    HOOK_I(FBAdViewabilityValidator, checkViewability_);
    HOOK_I(FBAdViewabilityValidator, stopMonitoring);
    HOOK_I(FBAdMonitor, startMonitoringAd_);
    HOOK_I(FBAdMonitor, stopMonitoring);
    HOOK_I(FBAdEvent, logEvent_withParameters_);
    HOOK_I(FBAdLogger, logMessage_withLevel_);

    // QQ
    HOOK_I(QQApiInterface, sendReq_resultBlock_);
    HOOK_I(QQApiInterface, sendThirdAppBindGroupReq_resultBlock_);
    HOOK_I(QQApiInterface, sendThirdAppUnBindGroupReq_resultBlock_);
    HOOK_I(QQApiInterface, sendThirdAppJoinGroupReq_resultBlock_);
    HOOK_I(QQApiInterface, sendQueryQQGroupProInfo_resultBlock_);
    HOOK_I(QQApiInterface, sendMessageToQQAuthWithReq_);
    HOOK_I(QQApiInterface, sendMessageToQQAvatarWithReq_);
    HOOK_I(QQApiInterface, sendMessageToFaceCollectionWithReq_);
    HOOK_I(QQOpenApiUtility, cgiRequestGetSdkConfig_);
    HOOK_I(TDataMasterApplication, handleOpenURL_);
    HOOK_I(TDataMasterApplication, reportEventWithSrcID_eventName_AndEventKVArray_);
    HOOK_I(TcApiTool, openUniversallinkIfNeed_);
    HOOK_I(GTMSessionFetcher, setSystemCompletionHandler_forSessionIdentifier_);

    // Audio / Reachability / serviceCommunication
    HOOK_I(AReachability, isConnectionOnDemand);
    HOOK_I(AReachability, isConnectionRequired);
    HOOK_I(AudioDeviceMgr, GetAudioDeviceConnectState);
    HOOK_I(AudioDeviceMgr, UpdateDeviceState_);
    HOOK_I(serviceCommunication, getValueForKeypath);

    // Social
    HOOK_I(TikTokAuth, authorizeWithPermissions_);
    HOOK_I(TikTokAuth, handleOpenURL_);
    HOOK_I(VKAuth, authorizeWithPermissions_);
    HOOK_I(VKAuth, logout);
    HOOK_I(SCSDKLoginClient, loginWithCompletion_);
    HOOK_I(SCSDKLoginClient, logout);

    // Ads identity
    HOOK_I(ASIdentifierManager, advertisingIdentifier);
    HOOK_I(ATTrackingManager, trackingAuthorizationStatus);
}

#pragma mark =========================================================
#pragma mark 16. FISHHOOK TABLE
#pragma mark =========================================================

static void SBXK_InstallRebindings(void) {
    sbxk_binding_t b[] = {
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
        {"MD5_Init",    (void *)SBXK_MD5_Init,    (void **)&orig_MD5_Init},
        {"MD5_Update",  (void *)SBXK_MD5_Update,  (void **)&orig_MD5_Update},
        {"MD5_Final",   (void *)SBXK_MD5_Final,   (void **)&orig_MD5_Final},
        {"SHA1_Init",   (void *)SBXK_SHA1_Init,   (void **)&orig_SHA1_Init},
        {"SHA1_Update", (void *)SBXK_SHA1_Update, (void **)&orig_SHA1_Update},
        {"SHA1_Final",  (void *)SBXK_SHA1_Final,  (void **)&orig_SHA1_Final},
        {"SHA256_Init", (void *)SBXK_SHA256_Init, (void **)&orig_SHA256_Init},
        {"SHA256_Update",(void *)SBXK_SHA256_Update,(void **)&orig_SHA256_Update},
        {"SHA256_Final",(void *)SBXK_SHA256_Final,(void **)&orig_SHA256_Final},
        {"SHA512_Init", (void *)SBXK_SHA512_Init, (void **)&orig_SHA512_Init},
        {"SHA512_Update",(void *)SBXK_SHA512_Update,(void **)&orig_SHA512_Update},
        {"SHA512_Final",(void *)SBXK_SHA512_Final,(void **)&orig_SHA512_Final},
        {"HMAC_Init",   (void *)SBXK_HMAC_Init,   (void **)&orig_HMAC_Init},
        {"HMAC_Update", (void *)SBXK_HMAC_Update, (void **)&orig_HMAC_Update},
        {"HMAC_Final",  (void *)SBXK_HMAC_Final,  (void **)&orig_HMAC_Final},

        // EVP / SSL / X509
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

        // POSIX
        {"access",     (void *)SBXK_access,     (void **)&orig_access},
    };
    sbxk_rebind_all(b, (int)(sizeof(b) / sizeof(b[0])));
}

#pragma mark =========================================================
#pragma mark 17. ENTRY
#pragma mark =========================================================

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        SBXK_LOG(@"v2 boot");

        // 1) Fishhook — kena symbol libcrypto/libSystem via lazy binding.
        SBXK_InstallRebindings();

        // 2) Swizzle semua kelas — skip yang tidak ada.
        SBXK_InstallAllSwizzles();

        // 3) FileManager.
        SBXK_InstallFileManagerSwizzle();

        // 4) AppDelegate proxy (kalau sudah dibentuk).
        [SBXK_AppDelegateProxy installIfPossible];

        // 5) Timer pembersih.
        SBXK_StartCleanupTimer();

        SBXK_LOG(@"v2 ready");
    }
}
