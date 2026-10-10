// ============================================================================
// ShadowBypass XK v7.4 — hooks lengkap, aman-by-design
//
// قاعدة صارمة:
//   ✓ BOOL  → return NO/YES  (آمن)
//   ✓ void  → no-op          (آمن)
//   ✓ id    → pass-through للأصل حصراً، أو nil. ممنوع إرجاع فئة مختلفة.
//   ✗ أي محاولة لإرجاع كائن من فئة غير الفئة الأصلية = جريمة.
//
// الدرس (من الكراش السابق):
//   __NSCFConstantString UUIDString → abort.
//   السبب: hook أرجَع NSString حيث كان NSUUID متوقعاً.
//   القاعدة: id-returning = pass-through دائماً، أو nil.
//
// البناء:
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
//         -fobjc-arc -fblocks -O2 -dynamiclib -Wno-nullability-completeness \
//         ShadowBypassXK.m -framework Foundation -framework UIKit \
//         -framework Security -framework AdSupport \
//         -o ShadowBypassXK.dylib
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
#pragma mark 0. الحالة العامة
#pragma mark =========================================================

static atomic_int  g_phase    = 0;
static atomic_bool g_pending  = false;
static atomic_int  g_crash_fd = -1;

#pragma mark =========================================================
#pragma mark 1. كتابة AS-safe
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
#pragma mark 2. معالج الانهيار
#pragma mark =========================================================

static void sbxk_on_signal(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    int fd = atomic_load(&g_crash_fd);
    if (fd >= 0) {
        SBXK_WLIT(fd, "\n=== SBXK CRASH ===\n");
        SBXK_WLIT(fd, "signal="); sbxk_wdec(fd, sig);                    SBXK_WLIT(fd, "\n");
        SBXK_WLIT(fd, "phase=");  sbxk_wdec(fd, atomic_load(&g_phase));  SBXK_WLIT(fd, "\n");
        if (info) {
            SBXK_WLIT(fd, "si_addr="); sbxk_whex(fd, info->si_addr); SBXK_WLIT(fd, "\n");
        }
        SBXK_WLIT(fd, "=== END CRASH ===\n");
    }
}

static void sbxk_on_exception(NSException *e) {
    int fd = atomic_load(&g_crash_fd);
    if (fd < 0) return;
    SBXK_WLIT(fd, "\n=== SBXK EXCEPTION ===\n");
    @try {
        NSString *n = [e name];
        NSString *r = [e reason];
        if (n) { SBXK_WLIT(fd, "name=");   const char *s = n.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; } SBXK_WLIT(fd, "\n"); }
        if (r) { SBXK_WLIT(fd, "reason="); const char *s = r.UTF8String;
                 if (s) { ssize_t _r = write(fd, s, strlen(s)); (void)_r; } SBXK_WLIT(fd, "\n"); }
    } @catch (__unused NSException *ign) { }
    SBXK_WLIT(fd, "=== END EXCEPTION ===\n");
}

#pragma mark =========================================================
#pragma mark 3. المسارات
#pragma mark =========================================================

static char g_crash_path[512] = {0};
static char g_prev_path[512]  = {0};

static void SBXK_InitPaths(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *c = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *p = [docs stringByAppendingPathComponent:@"sbxk_crash_prev.log"];
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
#pragma mark 4. registry swizzle
#pragma mark =========================================================

static NSMutableDictionary<NSString *, NSValue *> *g_orig = nil;
static NSMutableSet<NSString *> *g_done = nil;
static NSMutableSet<NSString *> *g_skip = nil;

static NSString *SBXK_Key(const char *cls, const char *sel) {
    return [NSString stringWithFormat:@"%s::%s", cls, sel];
}

static BOOL SBXK_MethodIsOwn(Class c, SEL s) {
    if (!c || !s) return NO;
    unsigned int n = 0;
    Method *list = class_copyMethodList(c, &n);
    if (!list) return NO;
    BOOL found = NO;
    for (unsigned int i = 0; i < n; i++) {
        if (method_getName(list[i]) == s) { found = YES; break; }
    }
    free(list);
    return found;
}

static BOOL SBXK_EncodingMatches(const char *actual, const char *expected) {
    if (!actual || !expected) return NO;
    return strcmp(actual, expected) == 0;
}

static BOOL SBXK_SwizzleFull(const char *clsName, const char *selName,
                             IMP replacement, const char *expectedEncoding)
{
    if (!clsName || !selName || !replacement || !expectedEncoding) return NO;
    NSString *key = SBXK_Key(clsName, selName);
    if ([g_done containsObject:key]) return YES;
    if ([g_skip containsObject:key]) return NO;

    Class c = objc_getClass(clsName);
    if (!c) return NO;

    SEL s = sel_registerName(selName);
    if (!s) { [g_skip addObject:key]; return NO; }

    Method instM = class_getInstanceMethod(c, s);
    Method clsM  = class_getClassMethod(c, s);

    BOOL isClass = NO;
    Method m = NULL;
    BOOL own = NO;
    Class target = nil;

    if (instM && SBXK_MethodIsOwn(c, s)) {
        m = instM; isClass = NO; own = YES; target = c;
    } else if (clsM && SBXK_MethodIsOwn(object_getClass(c), s)) {
        m = clsM; isClass = YES; own = YES; target = object_getClass(c);
    } else if (instM) {
        m = instM; isClass = NO; own = NO; target = c;
    } else if (clsM) {
        m = clsM; isClass = YES; own = NO; target = object_getClass(c);
    } else {
        [g_skip addObject:key];
        return NO;
    }

    const char *enc = method_getTypeEncoding(m);
    if (!SBXK_EncodingMatches(enc, expectedEncoding)) {
        NSLog(@"[SBXK-diag] verify failed: %s %s — got '%s' want '%s'",
              clsName, selName, enc ? enc : "(null)", expectedEncoding);
        [g_skip addObject:key];
        return NO;
    }

    IMP orig = method_getImplementation(m);
    g_orig[key] = [NSValue valueWithPointer:orig];

    @try {
        if (own) {
            class_replaceMethod(target, s, replacement, enc);
        } else {
            if (!class_addMethod(target, s, replacement, enc)) {
                class_replaceMethod(target, s, replacement, enc);
            }
        }
        [g_done addObject:key];
    } @catch (NSException *e) {
        NSLog(@"[SBXK-diag] exception: %s %s: %@", clsName, selName, e);
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
#pragma mark 5. IMP — الدفعة الكاملة
#pragma mark =========================================================
//
// كل IMP هنا إما:
//   BOOL   → return NO/YES
//   void   → no-op
//   id     → pass-through للأصل (SBXK_Original) أو nil
//
// لا شيء آخر. لا NSString، لا NSNumber، لا NSData من عندنا.

// ─────────────── Detection — Force NO ───────────────

#define DEF_NO(cls, name) \
    static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return NO; }

DEF_NO(IntegrityChecker,    integrity_detect)
DEF_NO(IntegrityChecker,    MTML_INTEGRITY_DETECT)
DEF_NO(JailbreakDetector,   isJailbroken)
DEF_NO(JailbreakDetector,   isJailbreak)
DEF_NO(JailbreakDetector,   checkJailbreak)
DEF_NO(JailbreakDetector,   jailbreakDetection)
DEF_NO(SimulatorDetector,   isSimulator)
DEF_NO(SimulatorDetector,   isSimulatorDevice)
DEF_NO(SimulatorDetector,   checkSimulator)
DEF_NO(SecurityChecker,     IsFileSystemModified)
DEF_NO(SecurityChecker,     isDebuggerAttached)
DEF_NO(SecurityChecker,     isDebugged)
DEF_NO(SecurityChecker,     checkDebugger)
DEF_NO(SecurityChecker,     amIBeingDebugged)
DEF_NO(SecurityChecker,     checkDebuggerAttach)
DEF_NO(SecurityChecker,     isHooked)
DEF_NO(SecurityChecker,     isHookDetected)
DEF_NO(SecurityChecker,     checkHook)
DEF_NO(SecurityChecker,     detectHook)
DEF_NO(SecurityChecker,     antiHookCheck)
DEF_NO(SecurityChecker,     isTampered)
DEF_NO(SecurityChecker,     checkTamper)
DEF_NO(SecurityChecker,     antiTamperCheck)
DEF_NO(SecurityChecker,     isInjected)
DEF_NO(SecurityChecker,     isLibraryInjected)
DEF_NO(SecurityChecker,     checkInjection)
DEF_NO(SecurityChecker,     antiInjectionCheck)
DEF_NO(SecurityChecker,     isReversingDetected)
DEF_NO(SecurityChecker,     checkReversing)
DEF_NO(SecurityChecker,     antiReversingCheck)
DEF_NO(SecurityChecker,     isBlocked)
DEF_NO(SecurityChecker,     antiBlockingCheck)
DEF_NO(SecurityChecker,     isVPNUsed)
DEF_NO(SecurityChecker,     isProxyUsed)
DEF_NO(SecurityChecker,     isFridaRunning)
DEF_NO(SecurityChecker,     isSubstrateLoaded)
DEF_NO(SecurityChecker,     isCydiaInstalled)
DEF_NO(SecurityChecker,     hasSuspiciousFiles)
DEF_NO(SecurityChecker,     isEnvironmentClean)

// ─────────────── Detection — Force YES ───────────────

#define DEF_YES(cls, name) \
    static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return YES; }

DEF_YES(SecurityChecker, verifyIntegrity)
DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe)
DEF_YES(SecurityChecker, verifySignature)
DEF_YES(AReachability,   isConnectionOnDemand)
DEF_YES(AReachability,   isConnectionRequired)
DEF_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

// ─────────────── Void — No-op ───────────────

#define DEF_V1(cls, name) \
    static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { \
        (void)_s; (void)_c; (void)_a1; }

#define DEF_V2(cls, name) \
    static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { \
        (void)_s; (void)_c; (void)_a1; (void)_a2; }

#define DEF_V3(cls, name) \
    static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { \
        (void)_s; (void)_c; (void)_a1; (void)_a2; (void)_a3; }

DEF_V1(GADAppOpenAd, adDidDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adWillDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adDidRecordClick)
DEF_V1(GADAppOpenAd, adDidRecordImpression)
DEF_V1(GADAppOpenAd, adWillPresentFullScreenContent)
DEF_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
DEF_V1(GADAppOpenAd, setPaidEventHandler)
DEF_V1(GADAppOpenAd, adDidRecordUserInteraction)

DEF_V1(GSDKPing,     ping)
DEF_V1(GSDKPing,     stopPing)
DEF_V1(GSDKPing,     simplePing_didFailToSendPacket_sequenceNumber_error)
DEF_V1(GSDKPing,     simplePing_didFailWithError)
DEF_V1(GSDKPing,     simplePing_didReceivePingResponsePacket_sequenceNumber)
DEF_V1(GSDKPing,     simplePing_didReceiveUnexpectedPacket)
DEF_V1(GSDKPing,     simplePing_didSendPacket_sequenceNumber)
DEF_V1(GSDKPing,     simplePing_didStartWithAddress)

DEF_V1(GSDKInGameManager, GSDKRealTimeDetect)
DEF_V1(GSDKInGameSystem,  GSDKInnerRealTimeDetect)

DEF_V1(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env)
DEF_V1(GSDKInitManager, detectOperation)
DEF_V1(GSDKRealTimeDetect, pingDelayDetect)
DEF_V1(GSDKRealTimeDetect, updDelayDetect_Port)
DEF_V1(GSDKUdpDetect, isUDPConnect_Port)
DEF_V1(GSDKWIFI, ping)
DEF_V1(GSDKDetectPort, isConnection_Port)

DEF_V1(GCloudVoiceEngine, StartTve)
DEF_V1(GCloudVoiceEngine, StopRecording)
DEF_V1(GCloudVoiceEngine, TestMic)
DEF_V1(GCloudVoiceEngine, StartBGMPlay)
DEF_V1(GCloudVoiceEngine, StopBGMPlay)
DEF_V1(GCloudVoiceEngine, PauseBGMPlay)
DEF_V1(GCloudVoiceEngine, ResumeBGMPlay)
DEF_V1(GCloudVoiceEngine, RSTSStopRecording)
DEF_V1(GCloudVoiceEngine, TextToStreamSpeechStop)
DEF_V1(GCloudVoiceEngine, StopKaraokeRecording)
DEF_V1(GCloudVoiceEngine, StartRecording)
DEF_V1(GCloudVoiceEngine, SetBGMPath)
DEF_V1(GCloudVoiceEngine, SetLogCallBack)

DEF_V1(GCloudVoiceEngine, SetMicVolume)
DEF_V1(GCloudVoiceEngine, SetSpeakerVolume)
DEF_V1(GCloudVoiceEngine, SetBitRate)
DEF_V1(GCloudVoiceEngine, SetDataFree)
DEF_V1(GCloudVoiceEngine, SetReportBufferTime)
DEF_V1(GCloudVoiceEngine, SetBGMPlayTime)
DEF_V1(GCloudVoiceEngine, SetKaraokeVoiceVol)
DEF_V1(GCloudVoiceEngine, SetKaraokeAccVol)
DEF_V1(GCloudVoiceEngine, SetKaraokeVoiceDelay)
DEF_V1(GCloudVoiceEngine, SeekTimeMsForPreview)
DEF_V1(GCloudVoiceEngine, SeekTimeMsForAcc)

DEF_V2(GVGCloudVoice, setAppInfo_withKey_andOpenID)
DEF_V2(GCloudVoiceEngine, EnableMultiRoom)
DEF_V2(GCloudVoiceEngine, EnableRoomMicrophone_enable)
DEF_V2(GCloudVoiceEngine, EnableRoomSpeaker_enable)
DEF_V2(GCloudVoiceEngine, EnableLog)
DEF_V2(GCloudVoiceEngine, EnableNativeBGMPlay)
DEF_V2(GCloudVoiceEngine, EnableRecvMagicVoice)
DEF_V2(GCloudVoiceEngine, EnableReportALL)
DEF_V2(GCloudVoiceEngine, EnableReportALLAbroad)
DEF_V2(GCloudVoiceEngine, EnableReportForAbroad)
DEF_V2(GCloudVoiceEngine, EnableCivilFile)
DEF_V2(GCloudVoiceEngine, EnableCivilVoice)
DEF_V2(GCloudVoiceEngine, EnableEarBack)
DEF_V2(GCloudVoiceEngine, EnableAccFilePlay)
DEF_V2(GCloudVoiceExtension, EnableKeyWordsDetect)

DEF_V3(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout)
DEF_V3(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout)
DEF_V3(GCloudVoiceEngine, QuitRoom_Scenes_timeout)

DEF_V1(NetworkManager, SendSecurityReport)
DEF_V1(FBAdMonitor,    startMonitoringAd)
DEF_V1(FBAdEvent,      logEvent_withParameters)
DEF_V1(FBAdLogger,     logMessage_withLevel)
DEF_V1(FIRMessaging,   retrieveFCMTokenForSenderID_completion)
DEF_V1(FIRMessaging,   deleteFCMTokenForSenderID_completion)
DEF_V1(FIRMessaging,   subscribeToTopic_completion)
DEF_V1(FIRMessaging,   unsubscribeFromTopic_completion)
DEF_V1(FIRMessaging,   setAPNSToken_withUserInfo)
DEF_V1(APMMonitor,     handleEvent)
DEF_V1(APMMonitor,     startMonitoring)
DEF_V1(APMCollector,   collectMetrics)
DEF_V1(TApmSceneMarker, markLoadLevel)
DEF_V1(TApmSceneMarker, postStepEvent)
DEF_V1(TApmSceneMarker, postStreamEvent)
DEF_V1(TDataMasterApplication, handleOpenURL)
DEF_V1(TcApiTool,      openUniversallinkIfNeed)
DEF_V1(TikTokAuth,     authorizeWithPermissions)
DEF_V1(TikTokAuth,     handleOpenURL)
DEF_V1(VKAuth,         authorizeWithPermissions)
DEF_V1(SCSDKLoginClient, loginWithCompletion)

// ─────────────── id — pass-through حصراً ───────────────
//
// هذه الدوال يجب أن تُرجع نفس نوع الأصل. ممنوع إرجاع NSString/NSUUID/NSError
// من عندنا. إن أردنا تعديل النتيجة، نعدّلها ثم نعيدها كما هي (نفس الفئة).

#define DEF_ID_PASS(cls, name) \
    static id SBXK_##cls##_##name(id _s, SEL _c) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL) = (void *)orig; \
        return fn(_s, _c); \
    }

// هذه الدوال تُرجع id بمعامل — مثال: -[Foo barWithArg:]
#define DEF_ID_PASS1(cls, name) \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL, id) = (void *)orig; \
        return fn(_s, _c, _a1); \
    }

// Placeholders — تُنشّط إذا ALPHA أراد pass-through لفئات محددة.
// الافتراضي: لا شيء. لأن أي id-hook قد يُدخل فئة جديدة على التطبيق.
//
// مثال مُعطَّل:
// DEF_ID_PASS(GADAppOpenAd, responseInfo)
// DEF_ID_PASS(FIRMessaging, APNSToken)
// DEF_ID_PASS1(FIRMessaging, retrieveFCMTokenForSenderID_completion)

#pragma mark =========================================================
#pragma mark 6. التسجيل
#pragma mark =========================================================

static void SBXK_RegisterAll(void) {

    // ───── Detection BOOL (0 args → "B@:") ─────

#define REG_BOOL_NO(cls, name) \
    SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "B@:")

#define REG_BOOL_YES(cls, name) \
    SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "B@:")

    REG_BOOL_NO (IntegrityChecker,  integrity_detect);
    REG_BOOL_NO (IntegrityChecker,  MTML_INTEGRITY_DETECT);
    REG_BOOL_NO (JailbreakDetector, isJailbroken);
    REG_BOOL_NO (JailbreakDetector, isJailbreak);
    REG_BOOL_NO (JailbreakDetector, checkJailbreak);
    REG_BOOL_NO (JailbreakDetector, jailbreakDetection);
    REG_BOOL_NO (SimulatorDetector, isSimulator);
    REG_BOOL_NO (SimulatorDetector, isSimulatorDevice);
    REG_BOOL_NO (SimulatorDetector, checkSimulator);
    REG_BOOL_NO (SecurityChecker,   IsFileSystemModified);
    REG_BOOL_NO (SecurityChecker,   isDebuggerAttached);
    REG_BOOL_NO (SecurityChecker,   isDebugged);
    REG_BOOL_NO (SecurityChecker,   checkDebugger);
    REG_BOOL_NO (SecurityChecker,   amIBeingDebugged);
    REG_BOOL_NO (SecurityChecker,   checkDebuggerAttach);
    REG_BOOL_NO (SecurityChecker,   isHooked);
    REG_BOOL_NO (SecurityChecker,   isHookDetected);
    REG_BOOL_NO (SecurityChecker,   checkHook);
    REG_BOOL_NO (SecurityChecker,   detectHook);
    REG_BOOL_NO (SecurityChecker,   antiHookCheck);
    REG_BOOL_NO (SecurityChecker,   isTampered);
    REG_BOOL_NO (SecurityChecker,   checkTamper);
    REG_BOOL_NO (SecurityChecker,   antiTamperCheck);
    REG_BOOL_NO (SecurityChecker,   isInjected);
    REG_BOOL_NO (SecurityChecker,   isLibraryInjected);
    REG_BOOL_NO (SecurityChecker,   checkInjection);
    REG_BOOL_NO (SecurityChecker,   antiInjectionCheck);
    REG_BOOL_NO (SecurityChecker,   isReversingDetected);
    REG_BOOL_NO (SecurityChecker,   checkReversing);
    REG_BOOL_NO (SecurityChecker,   antiReversingCheck);
    REG_BOOL_NO (SecurityChecker,   isBlocked);
    REG_BOOL_NO (SecurityChecker,   antiBlockingCheck);
    REG_BOOL_NO (SecurityChecker,   isVPNUsed);
    REG_BOOL_NO (SecurityChecker,   isProxyUsed);
    REG_BOOL_NO (SecurityChecker,   isFridaRunning);
    REG_BOOL_NO (SecurityChecker,   isSubstrateLoaded);
    REG_BOOL_NO (SecurityChecker,   isCydiaInstalled);
    REG_BOOL_NO (SecurityChecker,   hasSuspiciousFiles);
    REG_BOOL_NO (SecurityChecker,   isEnvironmentClean);

    REG_BOOL_YES(SecurityChecker,   verifyIntegrity);
    REG_BOOL_YES(SecurityChecker,   checkTokenValid);
    REG_BOOL_YES(SecurityChecker,   isEnvironmentSafe);
    REG_BOOL_YES(SecurityChecker,   verifySignature);
    REG_BOOL_YES(AReachability,     isConnectionOnDemand);
    REG_BOOL_YES(AReachability,     isConnectionRequired);
    REG_BOOL_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat);

    // ───── Void: encoding "v@:" أو "v@:@" أو "v@:@@" أو "v@:@@@" ─────

#define REG_VOID_1(cls, name) \
    SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@")

#define REG_VOID_2(cls, name) \
    SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@@")

#define REG_VOID_3(cls, name) \
    SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@@@")

    // GAD callbacks — signature: void(id self, SEL, id arg)
    REG_VOID_1(GADAppOpenAd, adDidDismissFullScreenContent);
    REG_VOID_1(GADAppOpenAd, adWillDismissFullScreenContent);
    REG_VOID_1(GADAppOpenAd, adDidRecordClick);
    REG_VOID_1(GADAppOpenAd, adDidRecordImpression);
    REG_VOID_1(GADAppOpenAd, adWillPresentFullScreenContent);
    REG_VOID_1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError);
    REG_VOID_1(GADAppOpenAd, setPaidEventHandler);
    REG_VOID_1(GADAppOpenAd, adDidRecordUserInteraction);

    // GSDK ping — many signatures start with "v@:@"
    REG_VOID_1(GSDKPing, ping);
    REG_VOID_1(GSDKPing, stopPing);
    REG_VOID_1(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error);
    REG_VOID_1(GSDKPing, simplePing_didFailWithError);
    REG_VOID_1(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber);
    REG_VOID_1(GSDKPing, simplePing_didReceiveUnexpectedPacket);
    REG_VOID_1(GSDKPing, simplePing_didSendPacket_sequenceNumber);
    REG_VOID_1(GSDKPing, simplePing_didStartWithAddress);

    REG_VOID_1(GSDKInGameManager, GSDKRealTimeDetect);
    REG_VOID_1(GSDKInGameSystem,  GSDKInnerRealTimeDetect);
    REG_VOID_1(GSDKHttpRequest,   requestControl_Openid_Acctype_Zoneid_Env);
    REG_VOID_1(GSDKInitManager,   detectOperation);
    REG_VOID_1(GSDKRealTimeDetect, pingDelayDetect);
    REG_VOID_1(GSDKRealTimeDetect, updDelayDetect_Port);
    REG_VOID_1(GSDKUdpDetect,     isUDPConnect_Port);
    REG_VOID_1(GSDKWIFI,          ping);
    REG_VOID_1(GSDKDetectPort,    isConnection_Port);

    REG_VOID_1(GCloudVoiceEngine, StartTve);
    REG_VOID_1(GCloudVoiceEngine, StopRecording);
    REG_VOID_1(GCloudVoiceEngine, TestMic);
    REG_VOID_1(GCloudVoiceEngine, StartBGMPlay);
    REG_VOID_1(GCloudVoiceEngine, StopBGMPlay);
    REG_VOID_1(GCloudVoiceEngine, PauseBGMPlay);
    REG_VOID_1(GCloudVoiceEngine, ResumeBGMPlay);
    REG_VOID_1(GCloudVoiceEngine, RSTSStopRecording);
    REG_VOID_1(GCloudVoiceEngine, TextToStreamSpeechStop);
    REG_VOID_1(GCloudVoiceEngine, StopKaraokeRecording);
    REG_VOID_1(GCloudVoiceEngine, StartRecording);
    REG_VOID_1(GCloudVoiceEngine, SetBGMPath);
    REG_VOID_1(GCloudVoiceEngine, SetLogCallBack);
    REG_VOID_1(GCloudVoiceEngine, SetMicVolume);
    REG_VOID_1(GCloudVoiceEngine, SetSpeakerVolume);
    REG_VOID_1(GCloudVoiceEngine, SetBitRate);
    REG_VOID_1(GCloudVoiceEngine, SetDataFree);
    REG_VOID_1(GCloudVoiceEngine, SetReportBufferTime);
    REG_VOID_1(GCloudVoiceEngine, SetBGMPlayTime);
    REG_VOID_1(GCloudVoiceEngine, SetKaraokeVoiceVol);
    REG_VOID_1(GCloudVoiceEngine, SetKaraokeAccVol);
    REG_VOID_1(GCloudVoiceEngine, SetKaraokeVoiceDelay);
    REG_VOID_1(GCloudVoiceEngine, SeekTimeMsForPreview);
    REG_VOID_1(GCloudVoiceEngine, SeekTimeMsForAcc);

    REG_VOID_2(GVGCloudVoice,     setAppInfo_withKey_andOpenID);
    REG_VOID_2(GCloudVoiceEngine, EnableMultiRoom);
    REG_VOID_2(GCloudVoiceEngine, EnableRoomMicrophone_enable);
    REG_VOID_2(GCloudVoiceEngine, EnableRoomSpeaker_enable);
    REG_VOID_2(GCloudVoiceEngine, EnableLog);
    REG_VOID_2(GCloudVoiceEngine, EnableNativeBGMPlay);
    REG_VOID_2(GCloudVoiceEngine, EnableRecvMagicVoice);
    REG_VOID_2(GCloudVoiceEngine, EnableReportALL);
    REG_VOID_2(GCloudVoiceEngine, EnableReportALLAbroad);
    REG_VOID_2(GCloudVoiceEngine, EnableReportForAbroad);
    REG_VOID_2(GCloudVoiceEngine, EnableCivilFile);
    REG_VOID_2(GCloudVoiceEngine, EnableCivilVoice);
    REG_VOID_2(GCloudVoiceEngine, EnableEarBack);
    REG_VOID_2(GCloudVoiceEngine, EnableAccFilePlay);
    REG_VOID_2(GVGCloudVoiceExtension, EnableKeyWordsDetect);

    REG_VOID_3(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout);
    REG_VOID_3(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout);
    REG_VOID_3(GCloudVoiceEngine, QuitRoom_Scenes_timeout);

    REG_VOID_1(NetworkManager, SendSecurityReport);
    REG_VOID_1(FBAdMonitor,    startMonitoringAd);
    REG_VOID_1(FBAdEvent,      logEvent_withParameters);
    REG_VOID_1(FBAdLogger,     logMessage_withLevel);
    REG_VOID_1(FIRMessaging,   retrieveFCMTokenForSenderID_completion);
    REG_VOID_1(FIRMessaging,   deleteFCMTokenForSenderID_completion);
    REG_VOID_1(FIRMessaging,   subscribeToTopic_completion);
    REG_VOID_1(FIRMessaging,   unsubscribeFromTopic_completion);
    REG_VOID_1(FIRMessaging,   setAPNSToken_withUserInfo);
    REG_VOID_1(APMMonitor,     handleEvent);
    REG_VOID_1(APMMonitor,     startMonitoring);
    REG_VOID_1(APMCollector,   collectMetrics);
    REG_VOID_1(TApmSceneMarker, markLoadLevel);
    REG_VOID_1(TApmSceneMarker, postStepEvent);
    REG_VOID_1(TApmSceneMarker, postStreamEvent);
    REG_VOID_1(TDataMasterApplication, handleOpenURL);
    REG_VOID_1(TcApiTool,      openUniversallinkIfNeed);
    REG_VOID_1(TikTokAuth,     authorizeWithPermissions);
    REG_VOID_1(TikTokAuth,     handleOpenURL);
    REG_VOID_1(VKAuth,         authorizeWithPermissions);
    REG_VOID_1(SCSDKLoginClient, loginWithCompletion);

    // ───── id pass-through — مُعطَّل عمداً ─────
    //
    // لا نُنشّط أي id-hook. القاعدة:
    //   لا تُنشّط DEF_ID_PASS إلا إذا كنت تعرف فئة الإرجاع بالضبط،
    //   والـ IMP يعيد نفس الفئة.
    //
    // مثال لو احتجت يوماً:
    // SBXK_SwizzleFull("GADAppOpenAd", "responseInfo",
    //                  (IMP)SBXK_GADAppOpenAd_responseInfo, "@@:");
    // حيث DEF_ID_PASS(GADAppOpenAd, responseInfo) — يعيد نفس الكائن الأصلي.

#undef REG_BOOL_NO
#undef REG_BOOL_YES
#undef REG_VOID_1
#undef REG_VOID_2
#undef REG_VOID_3
}

#pragma mark =========================================================
#pragma mark 7. عارض السجل
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
#pragma mark 8. Retry + Entry
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

static void SBXK_RunInstall(void) {
    atomic_store(&g_phase, 20);
    SBXK_RegisterAll();
    atomic_store(&g_phase, 30);
    NSLog(@"[SBXK] v7.4 install: done=%lu skip=%lu",
          (unsigned long)g_done.count, (unsigned long)g_skip.count);
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

        NSLog(@"[SBXK] v7.4 boot");

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
