// ============================================================================
// ShadowBypass XK v6.1.3-diag — diagnostic mode
//
// Removed vs v6.1.2 (لأغراض البحث عن سبب الكراش):
//   - FileManager swizzle
//   - Cleanup timer
//   - Retry timer / dyld callback
//   - Banner
//   - كل شيء ما عدا: crash handler + install pass + probe
//
// Added:
//   - SBXK_ReturnType يستخدم method_getTypeEncoding مباشرة (أمان)
//   - Probe per-hook: BEFORE idx=N + AFTER idx=N مع fsync
//   - Install pass مقسّم لمراحل معروفة (A..G)
//
// كيف تقرأ السبب:
//   1. شغّل التطبيق — ينهار في t≈7s
//   2. شغّل ثانية — راقب Console.app/idevicesyslog فلتر [SBXK]
//   3. ستجد: PREVIOUS CRASH LOG + آخر BEFORE idx=N بدون AFTER
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <signal.h>
#import <fcntl.h>
#import <unistd.h>
#import <stdio.h>
#import <string.h>

extern int backtrace(void **buffer, int size) __attribute__((weak_import));
extern void backtrace_symbols_fd(void *const *buffer, int size, int fd) __attribute__((weak_import));

#define SBXK_LOG(fmt, ...) NSLog(@"[SBXK] " fmt, ##__VA_ARGS__)

#pragma mark =========================================================
#pragma mark 0. GLOBALS
#pragma mark =========================================================

static volatile int g_phase = 0;
static volatile int g_hook_idx = -1;
static char g_crash_path[512] = {0};
static char g_probe_path[512] = {0};

#pragma mark =========================================================
#pragma mark 1. SAFE WRITERS
#pragma mark =========================================================

static void sbxk_wr(int fd, const char *s) {
    if (!s) s = "(null)";
    size_t len = strlen(s);
    while (len > 0) {
        ssize_t w = write(fd, s, len);
        if (w <= 0) return;
        s += w; len -= (size_t)w;
    }
}
static void sbxk_wrn(int fd, long v) {
    char b[32]; int n = snprintf(b, sizeof(b), "%ld", v);
    if (n > 0) write(fd, b, (size_t)n);
}
static void sbxk_wrhex(int fd, const void *p) {
    char b[32]; int n = snprintf(b, sizeof(b), "%p", p);
    if (n > 0) write(fd, b, (size_t)n);
}

// Probe — يُكتب على القرص فوراً مع fsync. لا يعتمد على buffer.
static void sbxk_probe(const char *msg, int idx, const char *cls, const char *sel) {
    if (g_probe_path[0] == 0) return;
    int fd = open(g_probe_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    sbxk_wr(fd, msg);
    sbxk_wr(fd, " idx="); sbxk_wrn(fd, idx);
    if (cls) { sbxk_wr(fd, " cls="); sbxk_wr(fd, cls); }
    if (sel) { sbxk_wr(fd, " sel="); sbxk_wr(fd, sel); }
    sbxk_wr(fd, "\n");
    fsync(fd);
    close(fd);
}

#pragma mark =========================================================
#pragma mark 2. CRASH HANDLER
#pragma mark =========================================================

static void sbxk_signal_handler(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    if (g_crash_path[0] == 0) { signal(sig, SIG_DFL); raise(sig); return; }

    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sbxk_wr(fd, "\n=== SBXK CRASH ===\n");
        sbxk_wr(fd, "signal="); sbxk_wrn(fd, sig); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "phase=");  sbxk_wrn(fd, g_phase); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "hook_idx="); sbxk_wrn(fd, g_hook_idx); sbxk_wr(fd, "\n");
        if (info) {
            sbxk_wr(fd, "si_addr="); sbxk_wrhex(fd, info->si_addr); sbxk_wr(fd, "\n");
        }
        if (backtrace && backtrace_symbols_fd) {
            sbxk_wr(fd, "--- backtrace ---\n");
            void *frames[64];
            int nf = backtrace(frames, 64);
            backtrace_symbols_fd(frames, nf, fd);
        }
        sbxk_wr(fd, "=== END CRASH ===\n");
        fsync(fd);
        close(fd);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void sbxk_uncaught_exception(NSException *e) {
    if (g_crash_path[0] == 0) return;
    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sbxk_wr(fd, "\n=== SBXK EXCEPTION ===\n");
        sbxk_wr(fd, "phase="); sbxk_wrn(fd, g_phase); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "hook_idx="); sbxk_wrn(fd, g_hook_idx); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "name="); sbxk_wr(fd, [[e name] UTF8String]); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "reason="); sbxk_wr(fd, [[e reason] UTF8String]); sbxk_wr(fd, "\n");
        fsync(fd);
        close(fd);
    }
}

#pragma mark =========================================================
#pragma mark 3. TYPE + GLOBALS
#pragma mark =========================================================

typedef struct {
    const char *cls;
    const char *sel;
    IMP         imp;
    char        expectedRet;   // حرف واحد فقط: 'B','@','v','q'
} sbxk_hook_t;

// g_hooks مُصفَّر إلى عدد صغير جداً للاختبار الأول.
// بعد ثبات الأساس، يُضاف الباقي تدريجياً.
static const sbxk_hook_t g_hooks[] = {
    // فئة مضمونة الوجود في أي تطبيق iOS (للتأكد من أن الآلية نفسها تعمل)
    {"NSFileManager", "fileExistsAtPath:", (IMP)NULL, '@'},
    // فئات اختبار
    {"NSObject", "description", (IMP)NULL, '@'},
};

#pragma mark =========================================================
#pragma mark 4. IMP MACROS (نموذج مصغّر)
#pragma mark =========================================================

// IMP بسيط لتجربة الاستبدال
static id SBXK_test_id(id _s, SEL _c) { (void)_s;(void)_c; return @"sbxk"; }

// استبدال المؤشرات في الجدول بعد التعريف
// (لا نستخدم static init لكي نتفادى مشكلة ترتيب التهيئة)
static void sbxk_fill_imps(void) {
    // هذا placeholder — الجدول الحقيقي يأتي لاحقاً
}

#pragma mark =========================================================
#pragma mark 5. INSTALL DRIVER — مع probe
#pragma mark =========================================================

// ملاحظة: نستخدم method_getTypeEncoding مباشرة.
// لا NSMethodSignature — لأنه قد يُعيد pointer مؤقت.
static const char *SBXK_SafeReturnType(Class c, SEL s, BOOL *isClassMethod) {
    if (!c) return NULL;
    Method m = class_getInstanceMethod(c, s);
    if (m) { if (isClassMethod) *isClassMethod = NO; }
    else {
        m = class_getClassMethod(c, s);
        if (m) { if (isClassMethod) *isClassMethod = YES; }
        else return NULL;
    }
    // method_getTypeEncoding يُعيد pointer ثابت من mach-o metadata.
    // الحرف الأول = return type.
    return method_getTypeEncoding(m);
}

static void SBXK_InstallOneHook(const sbxk_hook_t *h, int idx) {
    g_hook_idx = idx;

    sbxk_probe("BEFORE", idx, h->cls, h->sel);

    // حماية إضافية: NSException محتمل من sel_registerName في بيئات نادرة
    @try {
        Class c = objc_getClass(h->cls);
        if (!c) {
            sbxk_probe("SKIP-NOCLASS", idx, h->cls, h->sel);
            return;
        }
        SEL s = sel_registerName(h->sel);
        if (!s) {
            sbxk_probe("SKIP-NOSEL", idx, h->cls, h->sel);
            return;
        }
        BOOL isClassMethod = NO;
        const char *enc = SBXK_SafeReturnType(c, s, &isClassMethod);
        if (!enc) {
            sbxk_probe("SKIP-NOMETHOD", idx, h->cls, h->sel);
            return;
        }
        char actualRet = enc[0];
        if (actualRet != h->expectedRet) {
            sbxk_probe("SKIP-RETMISMATCH", idx, h->cls, h->sel);
            return;
        }
        Method m = isClassMethod ? class_getClassMethod(c, s) : class_getInstanceMethod(c, s);
        if (!m) {
            sbxk_probe("SKIP-RACE", idx, h->cls, h->sel);
            return;
        }
        Class target = isClassMethod ? object_getClass(c) : c;
        class_replaceMethod(target, s, h->imp, method_getTypeEncoding(m));

        sbxk_probe("AFTER", idx, h->cls, h->sel);
    } @catch (NSException *e) {
        sbxk_probe("EXCEPTION", idx, h->cls, h->sel);
    }
}

static void SBXK_InstallAllSwizzles(void) {
    sbxk_probe("PHASE-A", 0, NULL, NULL);

    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ SBXK_InstallAllSwizzles(); });
        return;
    }
    sbxk_probe("PHASE-B", 0, NULL, NULL);

    size_t n = sizeof(g_hooks) / sizeof(g_hooks[0]);
    sbxk_probe("PHASE-C", (int)n, NULL, NULL);

    for (size_t i = 0; i < n; i++) {
        SBXK_InstallOneHook(&g_hooks[i], (int)i);
    }
    g_hook_idx = -1;
    sbxk_probe("PHASE-D", 0, NULL, NULL);
}

#pragma mark =========================================================
#pragma mark 6. PATHS + ENTRY
#pragma mark =========================================================

static void SBXK_InitPaths(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *c = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *p = [docs stringByAppendingPathComponent:@"sbxk_probe.log"];
    strncpy(g_crash_path, c.UTF8String, sizeof(g_crash_path) - 1);
    strncpy(g_probe_path, p.UTF8String, sizeof(g_probe_path) - 1);
}

static void SBXK_InstallSignalHandlers(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sbxk_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS,  &sa, NULL);
    sigaction(SIGILL,  &sa, NULL);
    sigaction(SIGFPE,  &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);
    NSSetUncaughtExceptionHandler(&sbxk_uncaught_exception);
}

static void SBXK_FlushPrev(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *current = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *probe   = [docs stringByAppendingPathComponent:@"sbxk_probe.log"];

    // crash log
    if ([[NSFileManager defaultManager] fileExistsAtPath:current]) {
        NSData *d = [NSData dataWithContentsOfFile:current];
        if (d.length > 0) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s) SBXK_LOG(@"\n===== PREVIOUS CRASH =====\n%@\n===== END =====", s);
        }
    }
    // probe log
    if ([[NSFileManager defaultManager] fileExistsAtPath:probe]) {
        NSData *d = [NSData dataWithContentsOfFile:probe];
        if (d.length > 0) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            if (s) SBXK_LOG(@"\n===== PREVIOUS PROBE (tail) =====\n%@\n===== END =====", s);
        }
        [[NSFileManager defaultManager] removeItemAtPath:probe error:nil];
    }
}

#pragma mark =========================================================
#pragma mark 7. BOOTSTRAP
#pragma mark =========================================================

static void SBXK_RunInstalls(void) {
    SBXK_LOG(@"v6.1.3-diag: install starting");
    g_phase = 20;
    sbxk_probe("PHASE-20-install-start", 0, NULL, NULL);

    SBXK_InstallAllSwizzles();

    g_phase = 50;
    sbxk_probe("PHASE-50-install-done", 0, NULL, NULL);
    SBXK_LOG(@"v6.1.3-diag: install done");
}

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        SBXK_InitPaths();
        SBXK_InstallSignalHandlers();
        g_phase = 1;
        sbxk_probe("PHASE-1-boot", 0, NULL, NULL);

        SBXK_FlushPrev();
        g_phase = 2;
        sbxk_probe("PHASE-2-flushed", 0, NULL, NULL);

        SBXK_LOG(@"v6.1.3-diag: boot");
        sbxk_fill_imps();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { SBXK_RunInstalls(); }
        });
        g_phase = 3;
        sbxk_probe("PHASE-3-scheduled", 0, NULL, NULL);
    }
}
