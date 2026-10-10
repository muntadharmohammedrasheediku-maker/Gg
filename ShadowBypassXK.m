// ============================================================================
// ShadowBypass XK v7.5 — iOS 14+, arm64
// Build (GitHub Actions macOS runner):
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
#pragma mark 0. GLOBALS
#pragma mark =========================================================

static atomic_int  g_phase    = 0;
static atomic_bool g_pending  = false;
static atomic_int  g_crash_fd = -1;

#pragma mark =========================================================
#pragma mark 1. AS-SAFE WRITERS
#pragma mark =========================================================

#define SBXK_WLIT(fd, lit) do { \
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
#pragma mark 2. CRASH HANDLER
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
#pragma mark 3. PATHS
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
#pragma mark 4. SWIZZLE REGISTRY
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
    if (!enc || strcmp(enc, expectedEncoding) != 0) {
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
#pragma mark 5. IMP MACROS — كلها معرّفة، بلا استخدامات ناقصة
#pragma mark =========================================================

#define DEF_NO(cls, name)  static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return NO; }
#define DEF_YES(cls, name) static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return YES; }

#define DEF_V1(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; }
#define DEF_V2(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }
#define DEF_V3(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { (void)_s;(void)_c;(void)_a1;(void)_a2;(void)_a3; }

#define DEF_V1B(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, BOOL _b) { (void)_s;(void)_c;(void)_a1;(void)_b; }
#define DEF_V1I(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, int _i) { (void)_s;(void)_c;(void)_a1;(void)_i; }

#pragma mark =========================================================
#pragma mark 6. IMP DEFINITIONS
#pragma mark =========================================================

// ─── Detection — Force NO ───
DEF_NO(IntegrityChecker,  integrity_detect)
DEF_NO(IntegrityChecker,  MTML_INTEGRITY_DETECT)
DEF_NO(JailbreakDetector, isJailbroken)
DEF_NO(JailbreakDetector, isJailbreak)
DEF_NO(JailbreakDetector, checkJailbreak)
DEF_NO(JailbreakDetector, jailbreakDetection)
DEF_NO(SimulatorDetector, isSimulator)
DEF_NO(SimulatorDetector, isSimulatorDevice)
DEF_NO(SimulatorDetector, checkSimulator)
DEF_NO(SecurityChecker,   IsFileSystemModified)
DEF_NO(SecurityChecker,   isDebuggerAttached)
DEF_NO(SecurityChecker,   isDebugged)
DEF_NO(SecurityChecker,   checkDebugger)
DEF_NO(SecurityChecker,   amIBeingDebugged)
DEF_NO(SecurityChecker,   checkDebuggerAttach)
DEF_NO(SecurityChecker,   isHooked)
DEF_NO(SecurityChecker,   isHookDetected)
DEF_NO(SecurityChecker,   checkHook)
DEF_NO(SecurityChecker,   detectHook)
DEF_NO(SecurityChecker,   antiHookCheck)
DEF_NO(SecurityChecker,   isTampered)
DEF_NO(SecurityChecker,   checkTamper)
DEF_NO(SecurityChecker,   antiTamperCheck)
DEF_NO(SecurityChecker,   isInjected)
DEF_NO(SecurityChecker,   isLibraryInjected)
DEF_NO(SecurityChecker,   checkInjection)
DEF_NO(SecurityChecker,   antiInjectionCheck)
DEF_NO(SecurityChecker,   isReversingDetected)
DEF_NO(SecurityChecker,   checkReversing)
DEF_NO(SecurityChecker,   antiReversingCheck)
DEF_NO(SecurityChecker,   isBlocked)
DEF_NO(SecurityChecker,   antiBlockingCheck)
DEF_NO(SecurityChecker,   isVPNUsed)
DEF_NO(SecurityChecker,   isProxyUsed)
DEF_NO(SecurityChecker,   isFridaRunning)
DEF_NO(SecurityChecker,   isSubstrateLoaded)
DEF_NO(SecurityChecker,   isCydiaInstalled)
DEF_NO(SecurityChecker,   hasSuspiciousFiles)
DEF_NO(SecurityChecker,   isEnvironmentClean)

// ─── Detection — Force YES ───
DEF_YES(SecurityChecker, verifyIntegrity)
DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe)
DEF_YES(SecurityChecker, verifySignature)
DEF_YES(AReachability,   isConnectionOnDemand)
DEF_YES(AReachability,   isConnectionRequired)
DEF_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

// ─── GAD — void(id) ───
DEF_V1(GADAppOpenAd, adDidDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adWillDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adDidRecordClick)
DEF_V1(GADAppOpenAd, adDidRecordImpression)
DEF_V1(GADAppOpenAd, adWillPresentFullScreenContent)
DEF_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
DEF_V1(GADAppOpenAd, setPaidEventHandler)
DEF_V1(GADAppOpenAd, adDidRecordUserInteraction)

// ─── GSDK — void(id) ───
DEF_V1(GSDKPing, ping)
DEF_V1(GSDKPing, stopPing)
DEF_V1(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error)
DEF_V1(GSDKPing, simplePing_didFailWithError)
DEF_V1(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber)
DEF_V1(GSDKPing, simplePing_didReceiveUnexpectedPacket)
DEF_V1(GSDKPing, simplePing_didSendPacket_sequenceNumber)
DEF_V1(GSDKPing, simplePing_didStartWithAddress)
DEF_V1(GSDKInGameManager, GSDKRealTimeDetect)
DEF_V1(GSDKInGameSystem,  GSDKInnerRealTimeDetect)
DEF_V1(GSDKHttpRequest,   requestControl_Openid_Acctype_Zoneid_Env)
DEF_V1(GSDKInitManager,   detectOperation)
DEF_V1(GSDKRealTimeDetect, pingDelayDetect)
DEF_V1(GSDKRealTimeDetect, updDelayDetect_Port)
DEF_V1(GSDKUdpDetect,     isUDPConnect_Port)
DEF_V1(GSDKWIFI,          ping)
DEF_V1(GSDKDetectPort,    isConnection_Port)

// ─── GCloud — نقتصر على void(id) فقط ───
DEF_V1(GCloudVoiceEngine, StopRecording)
DEF_V1(GCloudVoiceEngine, StartBGMPlay)
DEF_V1(GCloudVoiceEngine, StopBGMPlay)
DEF_V1(GCloudVoiceEngine, PauseBGMPlay)
DEF_V1(GCloudVoiceEngine, ResumeBGMPlay)
DEF_V1(GCloudVoiceEngine, RSTSStopRecording)
DEF_V1(GCloudVoiceEngine, TextToStreamSpeechStop)
DEF_V1(GCloudVoiceEngine, StartRecording)
DEF_V1(GCloudVoiceEngine, SetBGMPath)
DEF_V1(GCloudVoiceEngine, SetLogCallBack)

// ─── Ads / Firebase / APM — void(id) ───
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

#pragma mark =========================================================
#pragma mark 7. REGISTRATION
#pragma mark =========================================================

static void SBXK_RegisterAll(void) {

#define REG_B(cls, name)  SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "B@:")
#define REG_V1(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@")

    // Detection NO
    REG_B(IntegrityChecker,  integrity_detect);
    REG_B(IntegrityChecker,  MTML_INTEGRITY_DETECT);
    REG_B(JailbreakDetector, isJailbroken);
    REG_B(JailbreakDetector, isJailbreak);
    REG_B(JailbreakDetector, checkJailbreak);
    REG_B(JailbreakDetector, jailbreakDetection);
    REG_B(SimulatorDetector, isSimulator);
    REG_B(SimulatorDetector, isSimulatorDevice);
    REG_B(SimulatorDetector, checkSimulator);
    REG_B(SecurityChecker,   IsFileSystemModified);
    REG_B(SecurityChecker,   isDebuggerAttached);
    REG_B(SecurityChecker,   isDebugged);
    REG_B(SecurityChecker,   checkDebugger);
    REG_B(SecurityChecker,   amIBeingDebugged);
    REG_B(SecurityChecker,   checkDebuggerAttach);
    REG_B(SecurityChecker,   isHooked);
    REG_B(SecurityChecker,   isHookDetected);
    REG_B(SecurityChecker,   checkHook);
    REG_B(SecurityChecker,   detectHook);
    REG_B(SecurityChecker,   antiHookCheck);
    REG_B(SecurityChecker,   isTampered);
    REG_B(SecurityChecker,   checkTamper);
    REG_B(SecurityChecker,   antiTamperCheck);
    REG_B(SecurityChecker,   isInjected);
    REG_B(SecurityChecker,   isLibraryInjected);
    REG_B(SecurityChecker,   checkInjection);
    REG_B(SecurityChecker,   antiInjectionCheck);
    REG_B(SecurityChecker,   isReversingDetected);
    REG_B(SecurityChecker,   checkReversing);
    REG_B(SecurityChecker,   antiReversingCheck);
    REG_B(SecurityChecker,   isBlocked);
    REG_B(SecurityChecker,   antiBlockingCheck);
    REG_B(SecurityChecker,   isVPNUsed);
    REG_B(SecurityChecker,   isProxyUsed);
    REG_B(SecurityChecker,   isFridaRunning);
    REG_B(SecurityChecker,   isSubstrateLoaded);
    REG_B(SecurityChecker,   isCydiaInstalled);
    REG_B(SecurityChecker,   hasSuspiciousFiles);
    REG_B(SecurityChecker,   isEnvironmentClean);

    // Detection YES
    REG_B(SecurityChecker,   verifyIntegrity);
    REG_B(SecurityChecker,   checkTokenValid);
    REG_B(SecurityChecker,   isEnvironmentSafe);
    REG_B(SecurityChecker,   verifySignature);
    REG_B(AReachability,     isConnectionOnDemand);
    REG_B(AReachability,     isConnectionRequired);
    REG_B(GVGCloudVoiceExtension, CheckDeviceMuteStat);

    // GAD
    REG_V1(GADAppOpenAd, adDidDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adWillDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adDidRecordClick);
    REG_V1(GADAppOpenAd, adDidRecordImpression);
    REG_V1(GADAppOpenAd, adWillPresentFullScreenContent);
    REG_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError);
    REG_V1(GADAppOpenAd, setPaidEventHandler);
    REG_V1(GADAppOpenAd, adDidRecordUserInteraction);

    // GSDK
    REG_V1(GSDKPing, ping);
    REG_V1(GSDKPing, stopPing);
    REG_V1(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error);
    REG_V1(GSDKPing, simplePing_didFailWithError);
    REG_V1(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber);
    REG_V1(GSDKPing, simplePing_didReceiveUnexpectedPacket);
    REG_V1(GSDKPing, simplePing_didSendPacket_sequenceNumber);
    REG_V1(GSDKPing, simplePing_didStartWithAddress);
    REG_V1(GSDKInGameManager, GSDKRealTimeDetect);
    REG_V1(GSDKInGameSystem,  GSDKInnerRealTimeDetect);
    REG_V1(GSDKHttpRequest,   requestControl_Openid_Acctype_Zoneid_Env);
    REG_V1(GSDKInitManager,   detectOperation);
    REG_V1(GSDKRealTimeDetect, pingDelayDetect);
    REG_V1(GSDKRealTimeDetect, updDelayDetect_Port);
    REG_V1(GSDKUdpDetect,     isUDPConnect_Port);
    REG_V1(GSDKWIFI,          ping);
    REG_V1(GSDKDetectPort,    isConnection_Port);

    // GCloud — void(id)
    REG_V1(GCloudVoiceEngine, StopRecording);
    REG_V1(GCloudVoiceEngine, StartBGMPlay);
    REG_V1(GCloudVoiceEngine, StopBGMPlay);
    REG_V1(GCloudVoiceEngine, PauseBGMPlay);
    REG_V1(GCloudVoiceEngine, ResumeBGMPlay);
    REG_V1(GCloudVoiceEngine, RSTSStopRecording);
    REG_V1(GCloudVoiceEngine, TextToStreamSpeechStop);
    REG_V1(GCloudVoiceEngine, StartRecording);
    REG_V1(GCloudVoiceEngine, SetBGMPath);
    REG_V1(GCloudVoiceEngine, SetLogCallBack);

    // Ads / Firebase / APM
    REG_V1(NetworkManager, SendSecurityReport);
    REG_V1(FBAdMonitor,    startMonitoringAd);
    REG_V1(FBAdEvent,      logEvent_withParameters);
    REG_V1(FBAdLogger,     logMessage_withLevel);
    REG_V1(FIRMessaging,   retrieveFCMTokenForSenderID_completion);
    REG_V1(FIRMessaging,   deleteFCMTokenForSenderID_completion);
    REG_V1(FIRMessaging,   subscribeToTopic_completion);
    REG_V1(FIRMessaging,   unsubscribeFromTopic_completion);
    REG_V1(FIRMessaging,   setAPNSToken_withUserInfo);
    REG_V1(APMMonitor,     handleEvent);
    REG_V1(APMMonitor,     startMonitoring);
    REG_V1(APMCollector,   collectMetrics);
    REG_V1(TApmSceneMarker, markLoadLevel);
    REG_V1(TApmSceneMarker, postStepEvent);
    REG_V1(TApmSceneMarker, postStreamEvent);
    REG_V1(TDataMasterApplication, handleOpenURL);
    REG_V1(TcApiTool,      openUniversallinkIfNeed);
    REG_V1(TikTokAuth,     authorizeWithPermissions);
    REG_V1(TikTokAuth,     handleOpenURL);
    REG_V1(VKAuth,         authorizeWithPermissions);
    REG_V1(SCSDKLoginClient, loginWithCompletion);

#undef REG_B
#undef REG_V1
}

#pragma mark =========================================================
#pragma mark 8. LOG VIEWER
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
#pragma mark 9. RETRY + ENTRY
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
    NSLog(@"[SBXK] v7.5 install: done=%lu skip=%lu",
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

        NSLog(@"[SBXK] v7.5 boot");

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
