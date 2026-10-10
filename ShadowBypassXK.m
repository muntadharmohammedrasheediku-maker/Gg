// ============================================================================
// ShadowBypass XK v7.2 — inherited method safety, diagnostic clarity
//
// Build (arm64 saja — tidak berasumsi arm64e/PAC sebagai penyebab crash):
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
//         -fobjc-arc -fblocks -O2 -dynamiclib \
//         -Wno-nullability-completeness \
//         ShadowBypassXK.m \
//         -framework Foundation -framework UIKit \
//         -o ShadowBypassXK.dylib
//
// Catatan diagnostik:
//   - رسائل [SBXK-diag] هي "نتائج فحوصات" فقط. ليست دليلاً على سبب الانهيار.
//   - المصدر الوحيد لسبب الانهيار هو sbxk_crash_prev.log المولَّد من معالج
//     الإشارة (SIGSEGV/ABRT/...). إذا لم يوجد الملف، لم يُنفَّذ المعالج.
//   - لا تفترض أن ARM64e أو PAC هو السبب قبل رؤية si_addr وsignal في
//     sbxk_crash_prev.log.
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <signal.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdatomic.h>

#pragma mark =========================================================
#pragma mark 0. GLOBALS
#pragma mark =========================================================

static atomic_int  g_phase    = 0;
static atomic_bool g_pending  = false;
static atomic_int  g_crash_fd = -1;

#pragma mark =========================================================
#pragma mark 1. AS-SAFE WRITERS
#pragma mark =========================================================

#define SBXK_WLIT(fd, lit)  do { \
    static const char _s[] = lit; \
    ssize_t _r = write((fd), _s, sizeof(_s) - 1); (void)_r; \
} while (0)

static void sbxk_wdec(int fd, long v) {
    if (fd < 0) return;
    char buf[24]; int i = 0;
    if (v < 0) { SBXK_WLIT(fd, "-"); v = -v; }
    if (v == 0) { SBXK_WLIT(fd, "0"); return; }
    while (v > 0 && i < 23) { buf[i++] = (char)('0' + (v % 10)); v /= 10; }
    while (i > 0) { char c = buf[--i]; ssize_t _r = write(fd, &c, 1); (void)_r; }
}

static void sbxk_whex(int fd, const void *p) {
    if (fd < 0) return;
    uintptr_t v = (uintptr_t)p;
    static const char hex[] = "0123456789abcdef";
    SBXK_WLIT(fd, "0x");
    if (v == 0) { SBXK_WLIT(fd, "0"); return; }
    char buf[20]; int i = 0;
    while (v > 0 && i < 19) { buf[i++] = hex[v & 0xF]; v >>= 4; }
    while (i > 0) { char c = buf[--i]; ssize_t _r = write(fd, &c, 1); (void)_r; }
}

#pragma mark =========================================================
#pragma mark 2. CRASH HANDLER — AS-safe, SA_RESETHAND
#pragma mark =========================================================

static void sbxk_on_signal(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    int fd = atomic_load(&g_crash_fd);
    if (fd >= 0) {
        SBXK_WLIT(fd, "\n=== SBXK CRASH ===\n");
        SBXK_WLIT(fd, "signal="); sbxk_wdec(fd, sig); SBXK_WLIT(fd, "\n");
        SBXK_WLIT(fd, "phase=");  sbxk_wdec(fd, atomic_load(&g_phase)); SBXK_WLIT(fd, "\n");
        if (info) {
            SBXK_WLIT(fd, "si_addr="); sbxk_whex(fd, info->si_addr); SBXK_WLIT(fd, "\n");
        }
        SBXK_WLIT(fd, "=== END CRASH ===\n");
    }
    // لا signal/raise — SA_RESETHAND تكفّل
}

static void sbxk_on_exception(NSException *e) {
    int fd = atomic_load(&g_crash_fd);
    if (fd < 0) return;
    SBXK_WLIT(fd, "\n=== SBXK EXCEPTION ===\n");
    @try {
        NSString *n = [e name];
        NSString *r = [e reason];
        if (n) { SBXK_WLIT(fd, "name=");
                 const char *s = n.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; }
                 SBXK_WLIT(fd, "\n"); }
        if (r) { SBXK_WLIT(fd, "reason=");
                 const char *s = r.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; }
                 SBXK_WLIT(fd, "\n"); }
    } @catch (__unused NSException *ign) { }
    SBXK_WLIT(fd, "=== END EXCEPTION ===\n");
}

#pragma mark =========================================================
#pragma mark 3. PATHS + INIT
#pragma mark =========================================================

static char g_crash_path[512] = {0};
static char g_prev_path[512]  = {0};

static void SBXK_InitPaths(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *c  = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *p  = [docs stringByAppendingPathComponent:@"sbxk_crash_prev.log"];
    strncpy(g_crash_path, c.UTF8String, sizeof(g_crash_path) - 1);
    strncpy(g_prev_path,  p.UTF8String, sizeof(g_prev_path)  - 1);
}

static void SBXK_InstallCrashHandlers(void) {
    if (g_crash_path[0] == 0) return;
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    atomic_store(&g_crash_fd, fd);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sbxk_on_signal;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    NSSetUncaughtExceptionHandler(&sbxk_on_exception);
}

static void SBXK_RotateCrashLog(void) {
    if (g_crash_path[0] == 0) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *c = [NSString stringWithUTF8String:g_crash_path];
    NSString *p = [NSString stringWithUTF8String:g_prev_path];
    if (![fm fileExistsAtPath:c]) return;

    [fm removeItemAtPath:p error:nil];
    [fm moveItemAtPath:c toPath:p error:nil];

    int old = atomic_exchange(&g_crash_fd, -1);
    if (old >= 0) close(old);
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    atomic_store(&g_crash_fd, fd);
}

#pragma mark =========================================================
#pragma mark 4. SWIZZLE REGISTRY
#pragma mark =========================================================

static NSMutableDictionary<NSString *, NSValue *> *g_orig = nil;
static NSMutableSet<NSString *> *g_done = nil;
static NSMutableSet<NSString *> *g_skip = nil;

static NSString *SBXK_Key(const char *cls, const char *sel) {
    return [NSString stringWithFormat:@"%s::%s", cls, sel];
}

// ---------------------------------------------------------------------------
// [A] فحص ما إذا كان Selector مُعرَّفاً على الكلاس نفسه — وليس موروثاً.
//     هذا يمنع لبس "c يعرّف s" مع "c يرث s من parent".
// ---------------------------------------------------------------------------
static BOOL SBXK_MethodIsOwn(Class c, SEL s) {
    if (!c || !s) return NO;
    unsigned int count = 0;
    Method *methods = class_copyMethodList(c, &count);
    if (!methods) return NO;
    BOOL found = NO;
    for (unsigned int i = 0; i < count; i++) {
        if (method_getName(methods[i]) == s) { found = YES; break; }
    }
    free(methods);
    return found;
}

// ---------------------------------------------------------------------------
// [B] فحص ما إذا كان Selector معرَّفاً كـ class method على الميتاكلاس مباشرة.
// ---------------------------------------------------------------------------
static BOOL SBXK_ClassMethodIsOwn(Class metacls, SEL s) {
    return SBXK_MethodIsOwn(metacls, s);
}

static BOOL SBXK_EncodingMatches(const char *actual, const char *expected) {
    if (!actual || !expected) return NO;
    return strcmp(actual, expected) == 0;
}

// ---------------------------------------------------------------------------
// [C] منطق التثبيت: يفرّق بين method مُعرَّف على الكلاس نفسه (استبدال)
//     وmethod موروث (إضافة override صريح عبر class_addMethod).
//
//     السبب: class_replaceMethod على كلاس لا يعرّف method يعمل كـ addMethod،
//     وهذا سلوك صحيح — لكن يجب أن نكون واعين بأننا نضيف override وليس
//     نُعدّل الأصل. الرسالة [SBXK-diag] توضح هذا.
// ---------------------------------------------------------------------------
static BOOL SBXK_SwizzleFull(const char *clsName,
                             const char *selName,
                             IMP         replacement,
                             const char *expectedFullEncoding)
{
    if (!clsName || !selName || !replacement || !expectedFullEncoding) return NO;

    NSString *key = SBXK_Key(clsName, selName);
    if ([g_done containsObject:key]) return YES;
    if ([g_skip containsObject:key]) return NO;

    Class c = objc_getClass(clsName);
    if (!c) return NO;   // pending, bukan failed

    SEL s = sel_registerName(selName);
    if (!s) { [g_skip addObject:key]; return NO; }

    // تحديد: instance أم class؟ وأين مُعرَّف؟
    Method instM = class_getInstanceMethod(c, s);
    Method clsM  = class_getClassMethod(c, s);

    BOOL isClassMethod = NO;
    Method m = NULL;
    BOOL ownOnTarget = NO;
    Class target = nil;

    if (instM && SBXK_MethodIsOwn(c, s)) {
        m = instM; isClassMethod = NO; ownOnTarget = YES; target = c;
    } else if (clsM && SBXK_ClassMethodIsOwn(object_getClass(c), s)) {
        m = clsM; isClassMethod = YES; ownOnTarget = YES; target = object_getClass(c);
    } else if (instM) {
        // وراثة من superclass — نضيف override على c نفسه
        m = instM; isClassMethod = NO; ownOnTarget = NO; target = c;
    } else if (clsM) {
        m = clsM; isClassMethod = YES; ownOnTarget = NO; target = object_getClass(c);
    } else {
        [g_skip addObject:key];
        return NO;
    }

    const char *enc = method_getTypeEncoding(m);
    if (!SBXK_EncodingMatches(enc, expectedFullEncoding)) {
        // [SBXK-diag] رسالة تشخيصية — ليست سبب انهيار.
        NSLog(@"[SBXK-diag] verify failed: %s %s — got '%s', want '%s'",
              clsName, selName, enc ? enc : "(null)", expectedFullEncoding);
        [g_skip addObject:key];
        return NO;
    }

    IMP orig = method_getImplementation(m);
    g_orig[key] = [NSValue valueWithPointer:orig];

    @try {
        if (ownOnTarget) {
            // الطريقة مُعرَّفة على الكلاس — استبدال مباشر
            class_replaceMethod(target, s, replacement, enc);
        } else {
            // وراثة — نضيف override على target فقط. الأصل في superclass لا يُلمس.
            if (!class_addMethod(target, s, replacement, enc)) {
                // فشل الإضافة (سباق أو سبق): استبدال
                class_replaceMethod(target, s, replacement, enc);
            }
            NSLog(@"[SBXK-diag] added override for inherited %s %s on %s",
                  clsName, selName, isClassMethod ? "metaclass" : "class");
        }
        [g_done addObject:key];
    } @catch (NSException *e) {
        NSLog(@"[SBXK-diag] exception while swizzling %s %s: %@", clsName, selName, e);
        [g_skip addObject:key];
        return NO;
    }
    return YES;
}

static IMP SBXK_Original(const char *cls, const char *sel) {
    if (!g_orig) return NULL;
    NSValue *v = g_orig[SBXK_Key(cls, sel)];
    return v ? (IMP)[v pointerValue] : NULL;
}

#pragma mark =========================================================
#pragma mark 5. HOOK — advertisingIdentifier (مثال وحيد)
#pragma mark =========================================================

static id SBXK_ASIdentifier_advertisingIdentifier(id self, SEL _cmd) {
    (void)self; (void)_cmd;
    static NSUUID *zero = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        unsigned char b[16] = {0};
        zero = [[NSUUID alloc] initWithUUIDBytes:b];
    });
    return zero;
}

#pragma mark =========================================================
#pragma mark 6. REGISTER
#pragma mark =========================================================

static void SBXK_RegisterAll(void) {
    // الترميز الكامل لـ advertisingIdentifier على ASIdentifierManager هو "@@:"
    SBXK_SwizzleFull("ASIdentifierManager",
                     "advertisingIdentifier",
                     (IMP)SBXK_ASIdentifier_advertisingIdentifier,
                     "@@:");

    // لا تضف صفوفاً قبل قراءة sbxk_crash_prev.log من نسخة مبنية بدونها.
}

#pragma mark =========================================================
#pragma mark 7. LOG VIEWER — بدون macOS
#pragma mark =========================================================

@interface SBXK_LogViewer : NSObject
@end

@implementation SBXK_LogViewer

+ (void)installObserver {
    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(onLaunched:)
               name:UIApplicationDidFinishLaunchingNotification
             object:nil];
}

+ (void)onLaunched:(NSNotification *)note {
    (void)note;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self show]; });
}

+ (void)show {
    NSString *path = [NSHomeDirectory()
                      stringByAppendingPathComponent:@"Documents/sbxk_crash_prev.log"];
    NSData *d = [NSData dataWithContentsOfFile:path];
    if (!d || d.length == 0) return;

    NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
    if (!s || s.length == 0) return;
    if (s.length > 2500) s = [[s substringToIndex:2500] stringByAppendingString:@"…"];

    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
            if (sc.activationState == UISceneActivationStateForegroundActive &&
                [sc isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *win in ((UIWindowScene *)sc).windows) {
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
    if (w.rootViewController.presentedViewController) return;

    UIAlertController *a = [UIAlertController
        alertControllerWithTitle:@"SBXK — previous crash"
                         message:s
                  preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK"
                                          style:UIAlertActionStyleDefault
                                        handler:nil]];
    [w.rootViewController presentViewController:a animated:YES completion:nil];
}

@end

#pragma mark =========================================================
#pragma mark 8. RETRY
#pragma mark =========================================================

static void sbxk_on_image_added(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    atomic_store(&g_pending, true);
}

static void SBXK_RetryPass(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ SBXK_RetryPass(); });
        return;
    }
    SBXK_RegisterAll();
}

#pragma mark =========================================================
#pragma mark 9. ENTRY
#pragma mark =========================================================

static void SBXK_RunInstall(void) {
    atomic_store(&g_phase, 20);
    SBXK_RegisterAll();
    atomic_store(&g_phase, 30);
    NSLog(@"[SBXK] v7.2 install: done=%lu skip=%lu",
          (unsigned long)g_done.count, (unsigned long)g_skip.count);
    NSLog(@"[SBXK] note: skip counts فحوصات فاشلة — ليست دليل انهيار");
}

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        g_orig = [NSMutableDictionary dictionary];
        g_done = [NSMutableSet set];
        g_skip = [NSMutableSet set];

        SBXK_InitPaths();
        SBXK_InstallCrashHandlers();
        atomic_store(&g_phase, 1);

        SBXK_RotateCrashLog();
        atomic_store(&g_phase, 2);

        NSLog(@"[SBXK] v7.2 boot");

        [SBXK_LogViewer installObserver];

        _dyld_register_func_for_add_image(sbxk_on_image_added);

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                SBXK_RunInstall();
                [NSTimer scheduledTimerWithTimeInterval:3.0 repeats:YES block:^(NSTimer *t) {
                    (void)t;
                    if (atomic_exchange(&g_pending, false)) {
                        SBXK_RetryPass();
                    }
                }];
            }
        });
    }
}
