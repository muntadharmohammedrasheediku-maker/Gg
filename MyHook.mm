#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCrypto.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import <sys/socket.h>
#import <sys/sysctl.h>
#import <netinet/in.h>
#import <AdSupport/AdSupport.h>
#import <AppTrackingTransparency/AppTrackingTransparency.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

#import "fishhook.h"

// ==========================================================
// 🛡️ SMART SWIZZLING HELPER (يمنع الكراش إذا لم يكن الكلاس موجوداً)
// ==========================================================
static void safe_swizzle(Class cls, SEL original, SEL replacement) {
    if (!cls) return;
    Method origMethod = class_getInstanceMethod(cls, original);
    Method newMethod = class_getInstanceMethod(cls, replacement);
    if (origMethod && newMethod) {
        method_exchangeImplementations(origMethod, newMethod);
    }
}

// ==========================================================
// 🔐 CRYPTO HOOKS (مع حماية من الكراش)
// ==========================================================
int (*orig_AES_cbc_encrypt)(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char *ivec, int enc);
int hooked_AES_cbc_encrypt(const unsigned char *in, unsigned char *out, size_t len, const void *key, unsigned char *ivec, int enc) {
    if (!orig_AES_cbc_encrypt) return 0;
    return orig_AES_cbc_encrypt(in, out, len, key, ivec, enc);
}

void (*orig_AES_encrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_encrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (!orig_AES_encrypt) return;
    orig_AES_encrypt(in, out, key);
}

void (*orig_AES_decrypt)(const unsigned char *in, unsigned char *out, const void *key);
void hooked_AES_decrypt(const unsigned char *in, unsigned char *out, const void *key) {
    if (!orig_AES_decrypt) return;
    orig_AES_decrypt(in, out, key);
}

int (*orig_RSA_verify)(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, void *rsa);
int hooked_RSA_verify(int type, const unsigned char *m, unsigned int m_len, const unsigned char *sigbuf, unsigned int siglen, void *rsa) {
    if (!orig_RSA_verify) return 1; // نجاح وهمي
    int ret = orig_RSA_verify(type, m, m_len, sigbuf, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

int (*orig_RSA_sign)(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, void *rsa);
int hooked_RSA_sign(int type, const unsigned char *m, unsigned int m_len, unsigned char *sigret, unsigned int *siglen, void *rsa) {
    if (!orig_RSA_sign) return 1;
    int ret = orig_RSA_sign(type, m, m_len, sigret, siglen, rsa);
    return (ret != 1) ? 1 : ret;
}

// ==========================================================
// 🔒 SSL & X509 HOOKS (تجاوز التحقق من الشهادات)
// ==========================================================
int (*orig_X509_verify_cert)(void *ctx);
int hooked_X509_verify_cert(void *ctx) {
    if (!orig_X509_verify_cert) return 1;
    orig_X509_verify_cert(ctx);
    return 1; // دائماً ناجح
}

void (*orig_SSL_CTX_set_verify)(void *ctx, int mode, void *cb);
void hooked_SSL_CTX_set_verify(void *ctx, int mode, void *cb) {
    if (!orig_SSL_CTX_set_verify) return;
    orig_SSL_CTX_set_verify(ctx, 0x00, NULL); // SSL_VERIFY_NONE
}

long (*orig_SSL_get_verify_result)(const void *ssl);
long hooked_SSL_get_verify_result(const void *ssl) {
    return 0; // X509_V_OK
}

// ==========================================================
// 🛡️ iOS SECURITY FRAMEWORK HOOKS (الذاكرة الذكية)
// ==========================================================
OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    if (!orig_SecItemCopyMatching) return errSecSuccess;
    
    OSStatus status = orig_SecItemCopyMatching(query, result);
    if (status == errSecItemNotFound) {
        NSString *queryDesc = [(__bridge NSDictionary *)query description];
        // إذا كان يبحث عن مفتاح، نعطيه بيانات وهمية لتجنب الكراش
        if ([queryDesc containsString:@"kSecClassKey"] || [queryDesc containsString:@"private"]) {
            if (result) {
                // تخصيص ذاكرة وهمية (32 بايت) لتجنب NULL Pointer Crash
                NSData *dummyData = [NSData dataWithBytes:"\x00\x00\x00\x00" length:32];
                *result = CFBridgingRetain(dummyData);
            }
            return errSecSuccess;
        }
    }
    return status;
}

OSStatus (*orig_SecKeyDecrypt)(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen);
OSStatus hooked_SecKeyDecrypt(SecKeyRef key, SecPadding padding, const uint8_t *cipherText, size_t cipherTextLen, uint8_t *plainText, size_t *plainTextLen) {
    if (!orig_SecKeyDecrypt) return errSecSuccess;
    return orig_SecKeyDecrypt(key, padding, cipherText, cipherTextLen, plainText, plainTextLen);
}

// ==========================================================
// 🕵️ ANTI-DEBUG & ANTI-JAILBREAK (الجزء الذكي)
// ==========================================================

// 1. إخفاء ملف الـ Dylib من الذاكرة
uint32_t (*orig__dyld_image_count)(void);
uint32_t hooked__dyld_image_count(void) {
    if (!orig__dyld_image_count) return 0;
    return orig__dyld_image_count() - 1; // إنقاص عدد المكتبات بمقدار 1 (لإخفاء MyHook.dylib)
}

const char* (*orig__dyld_get_image_name)(uint32_t image_index);
const char* hooked__dyld_get_image_name(uint32_t image_index) {
    if (!orig__dyld_get_image_name) return NULL;
    const char *name = orig__dyld_get_image_name(image_index);
    if (name && strstr(name, "MyHook.dylib")) {
        return ""; // إرجاع اسم فارغ إذا حاولوا قراءة اسم مكتبتنا
    }
    return name;
}

// 2. إخفاء متغيرات البيئة (DYLD_INSERT_LIBRARIES)
char* (*orig_getenv)(const char *name);
char* hooked_getenv(const char *name) {
    if (!orig_getenv) return NULL;
    if (strcmp(name, "DYLD_INSERT_LIBRARIES") == 0) {
        return NULL; // كأن المتغير غير موجود
    }
    return orig_getenv(name);
}

// 3. تجاوز فحص sysctl (الطريقة الكلاسيكية لكشف الجيلبريك)
int (*orig_sysctl)(int *name, u_int namelen, void *info, size_t *infosize, void *newp, size_t newlen);
int hooked_sysctl(int *name, u_int namelen, void *info, size_t *infosize, void *newp, size_t newlen) {
    if (!orig_sysctl) return -1;
    int ret = orig_sysctl(name, namelen, info, infosize, newp, newlen);
    
    // CTL_KERN = 1, KERN_PROC = 14 (فحص العمليات النشطة)
    if (name && namelen >= 2 && name[0] == 1 && name[1] == 14) {
        if (info && infosize) {
            // يمكنك هنا تعديل البيانات لإخفاء عمليات الجيلبريك (Cydia, SSH, etc)
            // لتبسيط الأمر، نتركها تمر لكن مع إخفاء مكتبتنا
        }
    }
    return ret;
}

// 4. دوال فحص الجيلبريك الشائعة
BOOL hooked_isJailbroken(id self, SEL _cmd) { return NO; }
BOOL hooked_checkJailbreak(id self, SEL _cmd) { return NO; }
BOOL hooked_isDebuggerAttached(id self, SEL _cmd) { return NO; }
BOOL hooked_amIBeingDebugged(id self, SEL _cmd) { return NO; }
BOOL hooked_isHooked(id self, SEL _cmd) { return NO; }
BOOL hooked_verifyIntegrity(id self, SEL _cmd) { return YES; }

// ==========================================================
// 📁 FILE SYSTEM BYPASS (إخفاء ملفات الجيلبريك)
// ==========================================================
int (*orig_access)(const char *path, int amode);
int hooked_access(const char *path, int amode) {
    if (!orig_access) return -1;
    const char *jailbreakPaths[] = {
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/bin/bash",
        "/etc/apt", "/usr/bin/ssh", "/usr/sbin/sshd", "/Library/MobileSubstrate",
        "/private/var/lib/apt", "/var/log/syslog", NULL
    };
    for (int i = 0; jailbreakPaths[i] != NULL; i++) {
        if (strcmp(path, jailbreakPaths[i]) == 0) {
            errno = ENOENT;
            return -1; // كأن الملف غير موجود
        }
    }
    return orig_access(path, amode);
}

static BOOL (*orig_fileExistsAtPath)(id self, SEL _cmd, NSString *path);
BOOL hooked_fileExistsAtPath(id self, SEL _cmd, NSString *path) {
    if (!orig_fileExistsAtPath) return NO;
    if ([path containsString:@"Cydia"] || [path containsString:@"MobileSubstrate"] || [path containsString:@"bash"]) {
        return NO;
    }
    return orig_fileExistsAtPath(self, _cmd, path);
}

// ==========================================================
// 📊 GSDK & TELEMETRY BYPASS (تجاوز أنظمة التتبع)
// ==========================================================
// بدلاً من عمل Swizzle لكل دالة بشكل منفصل، نستخدم safe_swizzle
// لضمان عدم حدوث كراش إذا لم تكن هذه الكلاسات موجودة في التطبيق.

void setup_gsdk_hooks() {
    Class gsdkClass = NSClassFromString(@"GSDKInner");
    if (gsdkClass) {
        safe_swizzle(gsdkClass, @selector(report_start_event:), @selector(hooked_report_start_event:));
        safe_swizzle(gsdkClass, @selector(report_system_event:), @selector(hooked_report_system_event:));
    }
    
    Class pufferClass = NSClassFromString(@"PufferDownload");
    if (pufferClass) {
        safe_swizzle(pufferClass, @selector(GetCurrentDownloadSpeed), @selector(hooked_GetCurrentDownloadSpeed));
    }
}

// دوال GSDK الوهمية (يجب أن تكون بنفس توقيع الدوال الأصلية)
- (void)hooked_report_start_event:(id)event {}
- (void)hooked_report_system_event:(id)event {}
- (float)hooked_GetCurrentDownloadSpeed { return 0.0f; }

// ==========================================================
// 🚀 CONSTRUCTOR (نقطة البداية الذكية)
// ==========================================================
#define REBIND(name) {(#name), (void *)hooked_##name, (void **)&orig_##name}

static __attribute__((constructor)) void initialize_hook() {
    @autoreleasepool {
        NSLog(@"[ShadowTrackerBypass] 🛡️ Advanced Bypass Loading...");
        
        // 1. تحميل المكتبات
        dlopen("/usr/lib/libcrypto.dylib", RTLD_LAZY);
        dlopen("/usr/lib/libssl.dylib", RTLD_LAZY);
        
        // 2. ربط دوال C باستخدام Fishhook
        struct rebinding bindings[] = {
            // Crypto
            REBIND(AES_cbc_encrypt), REBIND(AES_encrypt), REBIND(AES_decrypt),
            REBIND(RSA_verify), REBIND(RSA_sign),
            
            // SSL
            REBIND(X509_verify_cert), REBIND(SSL_CTX_set_verify), REBIND(SSL_get_verify_result),
            
            // Security
            REBIND(SecItemCopyMatching), REBIND(SecKeyDecrypt),
            
            // Anti-Detection (الجزء الذكي)
            REBIND(_dyld_image_count), REBIND(_dyld_get_image_name),
            REBIND(getenv), REBIND(sysctl),
            
            // File System
            REBIND(access),
        };
        
        rebind_symbols(bindings, sizeof(bindings)/sizeof(bindings[0]));
        
        // 3. تفعيل هوكات Objective-C (GSDK, etc) بشكل آمن
        setup_gsdk_hooks();
        
        // 4. تفعيل هوكات فحص الجيلبريك (فقط إذا كان الكلاس موجوداً)
        Class jbClass = NSClassFromString(@"JailbreakDetection");
        if (jbClass) {
            safe_swizzle(jbClass, @selector(isJailbroken), @selector(hooked_isJailbroken));
        }
        
        NSLog(@"[ShadowTrackerBypass] ✅ Bypass Loaded Successfully.");
    }
}
