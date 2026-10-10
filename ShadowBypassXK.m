// ============================================================================
// ShadowBypass XK v7.7 — iOS 14+, arm64
// Full integrated single-file build.
//
//   v7.6 core  : detection NO, lifecycle no-op, id pass-through
//   v7.7 ext   : TssInfo / AntiDataProxy / MRPCS / CheckSymbol / Alert gates
//
// قاعدة pass-through id:
//   DEF_ID_Pn → يستدعي الأصل ويرجّع النتيجة كما هي.
//   لا يصنع كائنًا جديدًا → لا unrecognized selector.
//
// البناء:
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -isysroot "$SDK" -miphoneos-version-min=14.0 \
//         -fobjc-arc -fblocks -O2 -dynamiclib -Wno-nullability-completeness \
//         ShadowBypassXK.m \
//         -framework Foundation -framework UIKit -framework Security -framework AdSupport \
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
        if (info) { SBXK_WLIT(fd, "si_addr="); sbxk_whex(fd, info->si_addr); SBXK_WLIT(fd, "\n"); }
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
        if (own) class_replaceMethod(target, s, replacement, enc);
        else if (!class_addMethod(target, s, replacement, enc))
            class_replaceMethod(target, s, replacement, enc);
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
#pragma mark 5. IMP MACROS
#pragma mark =========================================================

// BOOL — no args
#define DEF_NO(cls, name)  static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return NO; }
#define DEF_YES(cls, name) static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s; (void)_c; return YES; }

// void — 1..2 args
#define DEF_V1(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; }
#define DEF_V2(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }

// id — PASS-THROUGH
#define DEF_ID_P0(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL) = (void *)orig; \
        return fn(_s, _c); \
    }

#define DEF_ID_P1(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL, id) = (void *)orig; \
        return fn(_s, _c, _a1); \
    }

#define DEF_ID_P2(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL, id, id) = (void *)orig; \
        return fn(_s, _c, _a1, _a2); \
    }

#define DEF_ID_P3(cls, name)  \
    static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { \
        IMP orig = SBXK_Original(#cls, #name); \
        if (!orig) return nil; \
        id (*fn)(id, SEL, id, id, id) = (void *)orig; \
        return fn(_s, _c, _a1, _a2, _a3); \
    }

#pragma mark =========================================================
#pragma mark 6. BASE IMPs — BOOL
#pragma mark =========================================================

// Detection NO
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

// Detection YES
DEF_YES(SecurityChecker, verifyIntegrity)
DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe)
DEF_YES(SecurityChecker, verifySignature)
DEF_YES(AReachability,   isConnectionOnDemand)
DEF_YES(AReachability,   isConnectionRequired)
DEF_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

#pragma mark =========================================================
#pragma mark 7. BASE IMPs — VOID
#pragma mark =========================================================

DEF_V1(GADAppOpenAd, adDidDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adWillDismissFullScreenContent)
DEF_V1(GADAppOpenAd, adDidRecordClick)
DEF_V1(GADAppOpenAd, adDidRecordImpression)
DEF_V1(GADAppOpenAd, adWillPresentFullScreenContent)
DEF_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
DEF_V1(GADAppOpenAd, setPaidEventHandler)
DEF_V1(GADAppOpenAd, adDidRecordUserInteraction)

DEF_V1(NetworkManager, SendSecurityReport)

#pragma mark =========================================================
#pragma mark 8. BASE IMPs — ID pass-through
#pragma mark =========================================================

// ───── GSDK (0 arg) ─────
DEF_ID_P0(GSDKCPU,               getSystemCPUCircle)
DEF_ID_P0(GSDKMemory,            getSystemAvailableMemory)
DEF_ID_P0(GSDKInGameManager,     GSDKRealTimeDetect)
DEF_ID_P0(GSDKInGameSystem,      GSDKInnerEnd)
DEF_ID_P0(GSDKInGameSystem,      GSDKInnerRealTimeDetect)
DEF_ID_P0(GSDKPing,              ping)
DEF_ID_P0(GSDKPing,              stopPing)
DEF_ID_P0(GSDKPingDetect,        ping)
DEF_ID_P0(PingDelegate,          pingTimer)
DEF_ID_P0(SimplePing,            start)
DEF_ID_P0(SimplePing,            startWithHostAddress)
DEF_ID_P0(SimplePing,            readData)
DEF_ID_P0(GSDKRealTimeDetect,    pingDelayDetect)
DEF_ID_P0(GSDKRealTimeDetect,    updDelayDetect_Port)
DEF_ID_P0(GSDKUdpDetect,         isUDPConnect_Port)
DEF_ID_P0(GSDKWIFI,              ping)
DEF_ID_P0(GSDKDetectPort,        isConnection_Port)
DEF_ID_P0(GSDKInitManager,       detectOperation)
DEF_ID_P0(GSDKPayEvent,          GSDKPay_Tag_Status_Msg)
DEF_ID_P0(GSDKHttpRequest,       requestControl_Openid_Acctype_Zoneid_Env)

// ───── GSDK (1 arg) ─────
DEF_ID_P1(SimplePing,            sendPingWithData)
DEF_ID_P1(SimplePing,            didFailWithError)
DEF_ID_P1(FBAdViewabilityValidator, checkViewability)
DEF_ID_P1(TApmSceneMarker,       postStepEvent)
DEF_ID_P1(TApmSceneMarker,       postStreamEvent)
DEF_ID_P1(APMCollector,          collectMetrics)
DEF_ID_P1(APMCollector,          reportNow)
DEF_ID_P1(AudioDeviceMgr,        UpdateDeviceState)

// ───── GSDK (2 arg) ─────
DEF_ID_P2(SimplePing,            validatePingResponsePacket_sequenceNumber)
DEF_ID_P2(FIRMessaging,          retrieveFCMTokenForSenderID_completion)
DEF_ID_P2(FIRMessaging,          deleteFCMTokenForSenderID_completion)
DEF_ID_P2(FIRMessaging,          subscribeToTopic_completion)
DEF_ID_P2(FIRMessaging,          unsubscribeFromTopic_completion)
DEF_ID_P2(FIRMessaging,          setAPNSToken_withUserInfo)
DEF_ID_P2(GSDKInGameSystem,      GSDKInnerSaveFPS_FpsDots)

// ───── GSDK (3 arg) ─────
DEF_ID_P3(SimplePing,            pingPacketWithType_payload_requiresChecksum)
DEF_ID_P3(GSDKInGameSystem,      GSDKInnerStart_SceneID_RoomIP)

// ───── Voice (0 arg) ─────
DEF_ID_P0(GVGCloudVoice,           openMic)
DEF_ID_P0(GVGCloudVoice,           openSpeaker)
DEF_ID_P0(GVGCloudVoiceExtension,  GetBGMPlayState)
DEF_ID_P0(GVGCloudVoiceExtension,  GetMicState)
DEF_ID_P0(GVGCloudVoiceExtension,  GetSpeakerState)
DEF_ID_P0(GVoiceMuteSwitch,        detectMuteSwitch)
DEF_ID_P0(GCloudVoiceEngine,       StartTve)
DEF_ID_P0(GCloudVoiceEngine,       TestMic)
DEF_ID_P0(GCloudVoiceEngine,       GetMicLevel)
DEF_ID_P0(GCloudVoiceEngine,       GetSpeakerLevel)
DEF_ID_P0(GCloudVoiceEngine,       GetBGMLevel)
DEF_ID_P0(GCloudVoiceEngine,       GetBGMFileTime)
DEF_ID_P0(GCloudVoiceEngine,       GetBGMPlayTime)
DEF_ID_P0(GCloudVoiceEngine,       GetRecordKaraokeTotalTime)
DEF_ID_P0(GCloudVoiceEngine,       StartPreview)
DEF_ID_P0(GCloudVoiceEngine,       StopPreview)
DEF_ID_P0(GCloudVoiceEngine,       PauseKaraoke)
DEF_ID_P0(GCloudVoiceEngine,       ResumeKaraoke)
DEF_ID_P0(GCloudVoiceEngine,       RSTSStopRecording)
DEF_ID_P0(GCloudVoiceEngine,       TextToStreamSpeechStop)
DEF_ID_P0(GCloudVoiceEngine,       StopKaraokeRecording)
DEF_ID_P0(GCloudCoreRemoteConfig,  getConfig)
DEF_ID_P0(GCloudUnityPlugin,       Initialize)
DEF_ID_P0(GCloudUnityPlugin,       ReportEvent)

// ───── Voice (1 arg) ─────
DEF_ID_P1(GCloudVoiceEngine,       StartRecording)
DEF_ID_P1(GCloudVoiceEngine,       StopRecording)
DEF_ID_P1(GCloudVoiceEngine,       StartBGMPlay)
DEF_ID_P1(GCloudVoiceEngine,       StopBGMPlay)
DEF_ID_P1(GCloudVoiceEngine,       PauseBGMPlay)
DEF_ID_P1(GCloudVoiceEngine,       ResumeBGMPlay)
DEF_ID_P1(GCloudVoiceEngine,       SetBGMPath)
DEF_ID_P1(GCloudVoiceEngine,       SetLogCallBack)
DEF_ID_P1(GCloudCoreRemoteConfig,  updateConfig)
DEF_ID_P1(GCloudUnityPlugin,       SetGameObjectName)

// ───── Voice (2 arg) ─────
DEF_ID_P2(GCloudVoiceEngine,       QuitRoom_Scenes_timeout)

// ───── Firebase / Ads ─────
DEF_ID_P0(FIRMessagingRmqManager,  openDatabase)
DEF_ID_P0(FIRMessaging,            APNSToken)
DEF_ID_P0(GADAppOpenAd,            responseInfo)
DEF_ID_P0(GADMobileAds,            initializationStatus)
DEF_ID_P0(GADAdNetworkResponseInfo, adUnitMapping)
DEF_ID_P0(FBAdViewabilityValidator, stopMonitoring)
DEF_ID_P0(FBAdMonitor,             stopMonitoring)

// ───── APM ─────
DEF_ID_P0(APMDeviceInfoSupport,    getBatteryState)
DEF_ID_P0(APMDeviceInfoSupport,    getThermalState)
DEF_ID_P0(TApmSceneMarker,         markLevelFin)

// ───── Misc ─────
DEF_ID_P0(serviceCommunication,    getValueForKeypath)
DEF_ID_P0(AudioDeviceMgr,          GetAudioDeviceConnectState)
DEF_ID_P0(VKAuth,                  logout)
DEF_ID_P0(SCSDKLoginClient,        logout)

#pragma mark =========================================================
#pragma mark 9. EXTENDED IMPs — BOOL NO (v7.7)
#pragma mark =========================================================

// ─── AntiDataProxy ───
DEF_NO (AntiDataProxy, checkIntegrity)
DEF_NO (AntiDataProxy, isIntegrityOK)
DEF_NO (AntiDataProxy, verifyData)
DEF_NO (AntiDataProxy, isDataValid)
DEF_NO (AntiDataProxy, isModified)
DEF_NO (AntiDataProxy, isCheat)
DEF_NO (AntiDataProxy, isSuspicious)
DEF_NO (AntiDataProxy, antiCheatCheck)
DEF_NO (AntiDataProxy, securityCheck)
DEF_NO (AntiDataProxy, hasRisk)
DEF_NO (AntiDataProxy, detectRisk)
DEF_NO (AntiDataProxy, isRiskDetected)

// ─── TssInfoReceiver ───
DEF_NO (TssInfoReceiver, isRooted)
DEF_NO (TssInfoReceiver, isRootedDevice)
DEF_NO (TssInfoReceiver, isJailbroken)
DEF_NO (TssInfoReceiver, isJailbreakDevice)
DEF_NO (TssInfoReceiver, isEmulator)
DEF_NO (TssInfoReceiver, isEmulatorDevice)
DEF_NO (TssInfoReceiver, isSimulator)
DEF_NO (TssInfoReceiver, isDebuggerAttached)
DEF_NO (TssInfoReceiver, isDebugged)
DEF_NO (TssInfoReceiver, isModified)
DEF_NO (TssInfoReceiver, isTampered)
DEF_NO (TssInfoReceiver, isInjected)
DEF_NO (TssInfoReceiver, isHooked)
DEF_NO (TssInfoReceiver, hasCheat)
DEF_NO (TssInfoReceiver, hasCheatTool)
DEF_NO (TssInfoReceiver, hasSuspiciousFiles)
DEF_NO (TssInfoReceiver, hasRisk)
DEF_NO (TssInfoReceiver, checkEnvironment)
DEF_NO (TssInfoReceiver, checkSecurity)
DEF_NO (TssInfoReceiver, checkCheat)
DEF_NO (TssInfoReceiver, detectCheat)
DEF_NO (TssInfoReceiver, detectRisk)
DEF_NO (TssInfoReceiver, detectEnvironment)
DEF_NO (TssInfoReceiver, isCheating)
DEF_NO (TssInfoReceiver, isCheatDetected)
DEF_NO (TssInfoReceiver, isSuspicious)
DEF_NO (TssInfoReceiver, antiCheatCheck)
DEF_NO (TssInfoReceiver, securityCheck)
DEF_NO (TssInfoReceiver, shouldReport)
DEF_NO (TssInfoReceiver, shouldBlock)
DEF_NO (TssInfoReceiver, needReport)
DEF_NO (TssInfoReceiver, needBlock)
DEF_NO (TssInfoReceiver, isBlocked)
DEF_NO (TssInfoReceiver, isBanned)

// ─── CheckSymbolSource ───
DEF_NO (CheckSymbolSource, CheckSymbol)
DEF_NO (CheckSymbolSource, checkSymbol)
DEF_NO (CheckSymbolSource, checkSymbolSource)
DEF_NO (CheckSymbolSource, isSymbolValid)
DEF_NO (CheckSymbolSource, isSymbolOK)
DEF_NO (CheckSymbolSource, verifySymbol)
DEF_NO (CheckSymbolSource, verifySymbols)
DEF_NO (CheckSymbolSource, isSourceSafe)
DEF_NO (CheckSymbolSource, checkSource)

// ─── MRPCS thread gates ───
DEF_NO (CFastScanThread, isRunning)
DEF_NO (CFastScanThread, shouldScan)
DEF_NO (CFastScanThread, hasResult)
DEF_NO (CScanThread,     isRunning)
DEF_NO (CScanThread,     shouldScan)
DEF_NO (CScanThread,     hasResult)
DEF_NO (CSendThread,     isRunning)
DEF_NO (CSendThread,     shouldSend)
DEF_NO (CSendThread,     hasData)
DEF_NO (CMrpcsMonitor,   isRunning)
DEF_NO (CMrpcsMonitor,   shouldReport)
DEF_NO (CMrpcsMgrE,      isReady)
DEF_NO (CMrpcsMgrE,      shouldReport)
DEF_NO (CPointDataMgr,   shouldReport)
DEF_NO (CPointDataMgr,   hasData)
DEF_NO (CPointGlobalMgr, shouldReport)
DEF_NO (CPointGlobalMgr, hasData)
DEF_NO (CMrpcsLFUpdater, shouldUpdate)
DEF_NO (CMrpcsLFUpdater, hasUpdate)

#pragma mark =========================================================
#pragma mark 10. EXTENDED IMPs — BOOL YES (v7.7)
#pragma mark =========================================================

DEF_YES(TssInfoReceiver, isSafe)
DEF_YES(TssInfoReceiver, isClean)
DEF_YES(TssInfoReceiver, isEnvironmentClean)
DEF_YES(TssInfoReceiver, isEnvironmentSafe)
DEF_YES(TssInfoReceiver, verifyIntegrity)
DEF_YES(TssInfoReceiver, verifySignature)
DEF_YES(TssInfoReceiver, checkTokenValid)

DEF_YES(AntiDataProxy,  isValid)
DEF_YES(AntiDataProxy,  isSafe)
DEF_YES(AntiDataProxy,  isClean)
DEF_YES(AntiDataProxy,  verifyIntegrity)
DEF_YES(AntiDataProxy,  verifySignature)
DEF_YES(AntiDataProxy,  shouldPass)
DEF_YES(AntiDataProxy,  allowReport)

DEF_YES(CheckSymbolSource, isSourceOK)
DEF_YES(CheckSymbolSource, sourceIsValid)

#pragma mark =========================================================
#pragma mark 11. EXTENDED IMPs — VOID no-op (v7.7)
#pragma mark =========================================================

// ─── TssInfoReceiver lifecycle ───
DEF_V1(TssInfoReceiver, start)
DEF_V1(TssInfoReceiver, stop)
DEF_V1(TssInfoReceiver, run)
DEF_V1(TssInfoReceiver, onReceiveData)
DEF_V1(TssInfoReceiver, onRecvData)
DEF_V1(TssInfoReceiver, report)
DEF_V1(TssInfoReceiver, sendReport)
DEF_V1(TssInfoReceiver, uploadReport)
DEF_V1(TssInfoReceiver, submitReport)
DEF_V1(TssInfoReceiver, reportRoot)
DEF_V1(TssInfoReceiver, reportEmu)
DEF_V1(TssInfoReceiver, reportDebugger)
DEF_V1(TssInfoReceiver, reportCheat)
DEF_V1(TssInfoReceiver, reportAlert)
DEF_V1(TssInfoReceiver, sendAlert)
DEF_V1(TssInfoReceiver, blockGame)
DEF_V1(TssInfoReceiver, blockPlayer)
DEF_V1(TssInfoReceiver, kickPlayer)

// ─── AntiDataProxy lifecycle ───
DEF_V1(AntiDataProxy, sendData)
DEF_V1(AntiDataProxy, report)
DEF_V1(AntiDataProxy, submit)
DEF_V1(AntiDataProxy, upload)
DEF_V1(AntiDataProxy, dispatch)
DEF_V1(AntiDataProxy, flush)

// ─── MRPCS lifecycle ───
DEF_V1(CFastScanThread,    start)
DEF_V1(CFastScanThread,    run)
DEF_V1(CFastScanThread,    execute)
DEF_V1(CFastScanThread,    scan)
DEF_V1(CFastScanThread,    doScan)
DEF_V1(CFastScanThread,    report)
DEF_V1(CFastScanThread,    sendReport)
DEF_V1(CScanThread,        start)
DEF_V1(CScanThread,        run)
DEF_V1(CScanThread,        execute)
DEF_V1(CScanThread,        scan)
DEF_V1(CScanThread,        doScan)
DEF_V1(CScanThread,        report)
DEF_V1(CScanThread,        sendReport)
DEF_V1(CSendThread,        start)
DEF_V1(CSendThread,        run)
DEF_V1(CSendThread,        execute)
DEF_V1(CSendThread,        send)
DEF_V1(CSendThread,        doSend)
DEF_V1(CSendThread,        report)
DEF_V1(CMrpcsMonitor,      start)
DEF_V1(CMrpcsMonitor,      stop)
DEF_V1(CMrpcsMonitor,      run)
DEF_V1(CMrpcsMonitor,      execute)
DEF_V1(CMrpcsMonitor,      report)
DEF_V1(CMrpcsMonitor,      sendReport)
DEF_V1(CMrpcsMgrE,         sendScanResult)
DEF_V1(CMrpcsMgrE,         reportResult)
DEF_V1(CMrpcsMgrE,         sendReport)
DEF_V1(CMrpcsMgrE,         report)
DEF_V1(CMrpcsMgrE,         upload)
DEF_V1(CPointDataMgr,      report)
DEF_V1(CPointDataMgr,      sendData)
DEF_V1(CPointDataMgr,      uploadData)
DEF_V1(CPointDataMgr,      dispatch)
DEF_V1(CPointGlobalMgr,    report)
DEF_V1(CPointGlobalMgr,    sendReport)
DEF_V1(CPointGlobalMgr,    upload)
DEF_V1(CMrpcsLFUpdater,    update)
DEF_V1(CMrpcsLFUpdater,    start)
DEF_V1(CMrpcsLFUpdater,    run)
DEF_V1(CMrpcsLFUpdater,    check)
DEF_V1(CMrpcsLFUpdater,    report)

// ─── NetworkManager alert reporters ───
DEF_V1(NetworkManager, sendRootAlert)
DEF_V1(NetworkManager, sendEmuAlert)
DEF_V1(NetworkManager, sendDebuggerAlert)
DEF_V1(NetworkManager, sendCheatAlert)
DEF_V1(NetworkManager, send9010Alert)
DEF_V1(NetworkManager, send9014Alert)
DEF_V1(NetworkManager, send9005Alert)
DEF_V1(NetworkManager, sendShellReport)
DEF_V1(NetworkManager, sendCheckState)

// ─── AceMsgBoxImp ───
DEF_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn)
DEF_V1(AceMsgBoxImp, dismiss)
DEF_V1(AceMsgBoxImp, show)

#pragma mark =========================================================
#pragma mark 12. EXTENDED IMPs — ID pass-through (v7.7)
#pragma mark =========================================================

// ─── TssInfoReceiver ───
DEF_ID_P0(TssInfoReceiver, currentState)
DEF_ID_P0(TssInfoReceiver, getState)
DEF_ID_P0(TssInfoReceiver, getStatus)
DEF_ID_P0(TssInfoReceiver, getReport)
DEF_ID_P0(TssInfoReceiver, getResult)
DEF_ID_P0(TssInfoReceiver, getData)
DEF_ID_P0(TssInfoReceiver, getInfo)
DEF_ID_P0(TssInfoReceiver, getRiskInfo)
DEF_ID_P0(TssInfoReceiver, getCheatInfo)
DEF_ID_P0(TssInfoReceiver, getEnvInfo)
DEF_ID_P0(TssInfoReceiver, getConfig)
DEF_ID_P1(TssInfoReceiver, updateState)
DEF_ID_P1(TssInfoReceiver, setState)
DEF_ID_P1(TssInfoReceiver, handleData)
DEF_ID_P1(TssInfoReceiver, handleMessage)
DEF_ID_P1(TssInfoReceiver, processData)
DEF_ID_P1(TssInfoReceiver, onMessage)
DEF_ID_P1(TssInfoReceiver, onCommand)

// ─── AntiDataProxy ───
DEF_ID_P0(AntiDataProxy, getData)
DEF_ID_P0(AntiDataProxy, getPayload)
DEF_ID_P0(AntiDataProxy, getHeader)
DEF_ID_P0(AntiDataProxy, getBody)
DEF_ID_P0(AntiDataProxy, getResponse)
DEF_ID_P0(AntiDataProxy, getConfig)
DEF_ID_P0(AntiDataProxy, getState)
DEF_ID_P0(AntiDataProxy, getStatus)
DEF_ID_P1(AntiDataProxy, setData)
DEF_ID_P1(AntiDataProxy, setPayload)
DEF_ID_P1(AntiDataProxy, setConfig)
DEF_ID_P1(AntiDataProxy, process)
DEF_ID_P1(AntiDataProxy, handle)
DEF_ID_P1(AntiDataProxy, onReceive)
DEF_ID_P1(AntiDataProxy, onMessage)
DEF_ID_P2(AntiDataProxy, sendData_withHeader)
DEF_ID_P2(AntiDataProxy, sendReport_withType)
DEF_ID_P2(AntiDataProxy, postData_withURL)

// ─── MRPCS getters ───
DEF_ID_P0(CMrpcsMgrE,        getInstance)
DEF_ID_P0(CMrpcsMgrE,        getState)
DEF_ID_P0(CMrpcsMgrE,        getReport)
DEF_ID_P0(CMrpcsMgrE,        getResult)
DEF_ID_P0(CMrpcsMgrE,        getConfig)
DEF_ID_P0(CMrpcsMonitor,     getState)
DEF_ID_P0(CMrpcsMonitor,     getReport)
DEF_ID_P0(CMrpcsMonitor,     getResult)
DEF_ID_P0(CPointDataMgr,     getData)
DEF_ID_P0(CPointDataMgr,     getReport)
DEF_ID_P0(CPointDataMgr,     getState)
DEF_ID_P0(CPointGlobalMgr,   getData)
DEF_ID_P0(CPointGlobalMgr,   getReport)
DEF_ID_P0(CPointGlobalMgr,   getState)
DEF_ID_P0(CMrpcsLFUpdater,   getState)
DEF_ID_P0(CMrpcsLFUpdater,   getConfig)
DEF_ID_P0(CMrpcsLFUpdater,   getVersion)

DEF_ID_P1(CMrpcsMgrE,        setConfig)
DEF_ID_P1(CMrpcsMgrE,        setState)
DEF_ID_P1(CMrpcsMgrE,        handleData)
DEF_ID_P1(CMrpcsMgrE,        processData)
DEF_ID_P1(CMrpcsMonitor,     setConfig)
DEF_ID_P1(CMrpcsMonitor,     handleData)
DEF_ID_P1(CPointDataMgr,     setData)
DEF_ID_P1(CPointDataMgr,     handleData)
DEF_ID_P1(CPointGlobalMgr,   setData)
DEF_ID_P1(CPointGlobalMgr,   handleData)

DEF_ID_P2(CMrpcsMgrE,        sendData_withType)
DEF_ID_P2(CMrpcsMgrE,        handleMessage_withData)
DEF_ID_P2(CPointDataMgr,     sendData_withType)
DEF_ID_P2(CPointGlobalMgr,   sendData_withType)

// ─── CheckSymbolSource ───
DEF_ID_P0(CheckSymbolSource, getResult)
DEF_ID_P0(CheckSymbolSource, getReport)
DEF_ID_P1(CheckSymbolSource, checkSymbolSourceWithData)
DEF_ID_P1(CheckSymbolSource, verifySymbolWithData)

// ─── Screenshot / Rotate ───
DEF_ID_P0(ScreenShot, takeScreenShot)
DEF_ID_P0(ScreenShot, takeScreenShotEx)
DEF_ID_P0(ScreenShot, screenshot)
DEF_ID_P1(ScreenShot, takeScreenShotEx)
DEF_ID_P1(ScreenShot, screenshotOfView)
DEF_ID_P1(ScreenShot, getBufFromImage)
DEF_ID_P1(ScreenShot, getAppWindowsForScreen)

DEF_ID_P0(Rotate, rotate)
DEF_ID_P0(Rotate, fixOrientation)
DEF_ID_P0(Rotate, flipVertical)
DEF_ID_P0(Rotate, flipHorizontal)
DEF_ID_P1(Rotate, rotate)
DEF_ID_P1(Rotate, imageRotatedByRadians)
DEF_ID_P1(Rotate, imageRotatedByDegrees)

// ─── AceMsgBoxImp ───
DEF_ID_P0(AceMsgBoxImp, viewTitle)
DEF_ID_P0(AceMsgBoxImp, viewContent)
DEF_ID_P0(AceMsgBoxImp, leftBtnContent)
DEF_ID_P0(AceMsgBoxImp, rightBtnContent)

#pragma mark =========================================================
#pragma mark 13. REGISTER EXTENDED
#pragma mark =========================================================

static void SBXK_RegisterExtended(void) {

#define REG_B(cls, name)   SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "B@:")
#define REG_V1(cls, name)  SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@")
#define REG_V2(cls, name)  SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@@")
#define REG_ID0(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:")
#define REG_ID1(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:@")
#define REG_ID2(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:@@")

    // AntiDataProxy
    REG_B (AntiDataProxy, checkIntegrity);
    REG_B (AntiDataProxy, isIntegrityOK);
    REG_B (AntiDataProxy, verifyData);
    REG_B (AntiDataProxy, isDataValid);
    REG_B (AntiDataProxy, isModified);
    REG_B (AntiDataProxy, isCheat);
    REG_B (AntiDataProxy, isSuspicious);
    REG_B (AntiDataProxy, antiCheatCheck);
    REG_B (AntiDataProxy, securityCheck);
    REG_B (AntiDataProxy, hasRisk);
    REG_B (AntiDataProxy, detectRisk);
    REG_B (AntiDataProxy, isRiskDetected);
    REG_B (AntiDataProxy, isValid);
    REG_B (AntiDataProxy, isSafe);
    REG_B (AntiDataProxy, isClean);
    REG_B (AntiDataProxy, verifyIntegrity);
    REG_B (AntiDataProxy, verifySignature);
    REG_B (AntiDataProxy, shouldPass);
    REG_B (AntiDataProxy, allowReport);
    REG_V1(AntiDataProxy, sendData);
    REG_V1(AntiDataProxy, report);
    REG_V1(AntiDataProxy, submit);
    REG_V1(AntiDataProxy, upload);
    REG_V1(AntiDataProxy, dispatch);
    REG_V1(AntiDataProxy, flush);
    REG_ID0(AntiDataProxy, getData);
    REG_ID0(AntiDataProxy, getPayload);
    REG_ID0(AntiDataProxy, getHeader);
    REG_ID0(AntiDataProxy, getBody);
    REG_ID0(AntiDataProxy, getResponse);
    REG_ID0(AntiDataProxy, getConfig);
    REG_ID0(AntiDataProxy, getState);
    REG_ID0(AntiDataProxy, getStatus);
    REG_ID1(AntiDataProxy, setData);
    REG_ID1(AntiDataProxy, setPayload);
    REG_ID1(AntiDataProxy, setConfig);
    REG_ID1(AntiDataProxy, process);
    REG_ID1(AntiDataProxy, handle);
    REG_ID1(AntiDataProxy, onReceive);
    REG_ID1(AntiDataProxy, onMessage);
    REG_ID2(AntiDataProxy, sendData_withHeader);
    REG_ID2(AntiDataProxy, sendReport_withType);
    REG_ID2(AntiDataProxy, postData_withURL);

    // TssInfoReceiver
    REG_B (TssInfoReceiver, isRooted);
    REG_B (TssInfoReceiver, isRootedDevice);
    REG_B (TssInfoReceiver, isJailbroken);
    REG_B (TssInfoReceiver, isJailbreakDevice);
    REG_B (TssInfoReceiver, isEmulator);
    REG_B (TssInfoReceiver, isEmulatorDevice);
    REG_B (TssInfoReceiver, isSimulator);
    REG_B (TssInfoReceiver, isDebuggerAttached);
    REG_B (TssInfoReceiver, isDebugged);
    REG_B (TssInfoReceiver, isModified);
    REG_B (TssInfoReceiver, isTampered);
    REG_B (TssInfoReceiver, isInjected);
    REG_B (TssInfoReceiver, isHooked);
    REG_B (TssInfoReceiver, hasCheat);
    REG_B (TssInfoReceiver, hasCheatTool);
    REG_B (TssInfoReceiver, hasSuspiciousFiles);
    REG_B (TssInfoReceiver, hasRisk);
    REG_B (TssInfoReceiver, checkEnvironment);
    REG_B (TssInfoReceiver, checkSecurity);
    REG_B (TssInfoReceiver, checkCheat);
    REG_B (TssInfoReceiver, detectCheat);
    REG_B (TssInfoReceiver, detectRisk);
    REG_B (TssInfoReceiver, detectEnvironment);
    REG_B (TssInfoReceiver, isCheating);
    REG_B (TssInfoReceiver, isCheatDetected);
    REG_B (TssInfoReceiver, isSuspicious);
    REG_B (TssInfoReceiver, antiCheatCheck);
    REG_B (TssInfoReceiver, securityCheck);
    REG_B (TssInfoReceiver, shouldReport);
    REG_B (TssInfoReceiver, shouldBlock);
    REG_B (TssInfoReceiver, needReport);
    REG_B (TssInfoReceiver, needBlock);
    REG_B (TssInfoReceiver, isBlocked);
    REG_B (TssInfoReceiver, isBanned);
    REG_B (TssInfoReceiver, isSafe);
    REG_B (TssInfoReceiver, isClean);
    REG_B (TssInfoReceiver, isEnvironmentClean);
    REG_B (TssInfoReceiver, isEnvironmentSafe);
    REG_B (TssInfoReceiver, verifyIntegrity);
    REG_B (TssInfoReceiver, verifySignature);
    REG_B (TssInfoReceiver, checkTokenValid);
    REG_V1(TssInfoReceiver, start);
    REG_V1(TssInfoReceiver, stop);
    REG_V1(TssInfoReceiver, run);
    REG_V1(TssInfoReceiver, onReceiveData);
    REG_V1(TssInfoReceiver, onRecvData);
    REG_V1(TssInfoReceiver, report);
    REG_V1(TssInfoReceiver, sendReport);
    REG_V1(TssInfoReceiver, uploadReport);
    REG_V1(TssInfoReceiver, submitReport);
    REG_V1(TssInfoReceiver, reportRoot);
    REG_V1(TssInfoReceiver, reportEmu);
    REG_V1(TssInfoReceiver, reportDebugger);
    REG_V1(TssInfoReceiver, reportCheat);
    REG_V1(TssInfoReceiver, reportAlert);
    REG_V1(TssInfoReceiver, sendAlert);
    REG_V1(TssInfoReceiver, blockGame);
    REG_V1(TssInfoReceiver, blockPlayer);
    REG_V1(TssInfoReceiver, kickPlayer);
    REG_ID0(TssInfoReceiver, currentState);
    REG_ID0(TssInfoReceiver, getState);
    REG_ID0(TssInfoReceiver, getStatus);
    REG_ID0(TssInfoReceiver, getReport);
    REG_ID0(TssInfoReceiver, getResult);
    REG_ID0(TssInfoReceiver, getData);
    REG_ID0(TssInfoReceiver, getInfo);
    REG_ID0(TssInfoReceiver, getRiskInfo);
    REG_ID0(TssInfoReceiver, getCheatInfo);
    REG_ID0(TssInfoReceiver, getEnvInfo);
    REG_ID0(TssInfoReceiver, getConfig);
    REG_ID1(TssInfoReceiver, updateState);
    REG_ID1(TssInfoReceiver, setState);
    REG_ID1(TssInfoReceiver, handleData);
    REG_ID1(TssInfoReceiver, handleMessage);
    REG_ID1(TssInfoReceiver, processData);
    REG_ID1(TssInfoReceiver, onMessage);
    REG_ID1(TssInfoReceiver, onCommand);

    // CheckSymbolSource
    REG_B (CheckSymbolSource, CheckSymbol);
    REG_B (CheckSymbolSource, checkSymbol);
    REG_B (CheckSymbolSource, checkSymbolSource);
    REG_B (CheckSymbolSource, isSymbolValid);
    REG_B (CheckSymbolSource, isSymbolOK);
    REG_B (CheckSymbolSource, verifySymbol);
    REG_B (CheckSymbolSource, verifySymbols);
    REG_B (CheckSymbolSource, isSourceSafe);
    REG_B (CheckSymbolSource, checkSource);
    REG_B (CheckSymbolSource, isSourceOK);
    REG_B (CheckSymbolSource, sourceIsValid);
    REG_ID0(CheckSymbolSource, getResult);
    REG_ID0(CheckSymbolSource, getReport);
    REG_ID1(CheckSymbolSource, checkSymbolSourceWithData);
    REG_ID1(CheckSymbolSource, verifySymbolWithData);

    // MRPCS
    REG_B (CFastScanThread, isRunning);
    REG_B (CFastScanThread, shouldScan);
    REG_B (CFastScanThread, hasResult);
    REG_V1(CFastScanThread, start);
    REG_V1(CFastScanThread, run);
    REG_V1(CFastScanThread, execute);
    REG_V1(CFastScanThread, scan);
    REG_V1(CFastScanThread, doScan);
    REG_V1(CFastScanThread, report);
    REG_V1(CFastScanThread, sendReport);

    REG_B (CScanThread, isRunning);
    REG_B (CScanThread, shouldScan);
    REG_B (CScanThread, hasResult);
    REG_V1(CScanThread, start);
    REG_V1(CScanThread, run);
    REG_V1(CScanThread, execute);
    REG_V1(CScanThread, scan);
    REG_V1(CScanThread, doScan);
    REG_V1(CScanThread, report);
    REG_V1(CScanThread, sendReport);

    REG_B (CSendThread, isRunning);
    REG_B (CSendThread, shouldSend);
    REG_B (CSendThread, hasData);
    REG_V1(CSendThread, start);
    REG_V1(CSendThread, run);
    REG_V1(CSendThread, execute);
    REG_V1(CSendThread, send);
    REG_V1(CSendThread, doSend);
    REG_V1(CSendThread, report);

    REG_B (CMrpcsMonitor, isRunning);
    REG_B (CMrpcsMonitor, shouldReport);
    REG_V1(CMrpcsMonitor, start);
    REG_V1(CMrpcsMonitor, stop);
    REG_V1(CMrpcsMonitor, run);
    REG_V1(CMrpcsMonitor, execute);
    REG_V1(CMrpcsMonitor, report);
    REG_V1(CMrpcsMonitor, sendReport);
    REG_ID0(CMrpcsMonitor, getState);
    REG_ID0(CMrpcsMonitor, getReport);
    REG_ID0(CMrpcsMonitor, getResult);
    REG_ID1(CMrpcsMonitor, setConfig);
    REG_ID1(CMrpcsMonitor, handleData);

    REG_B (CMrpcsMgrE, isReady);
    REG_B (CMrpcsMgrE, shouldReport);
    REG_V1(CMrpcsMgrE, sendScanResult);
    REG_V1(CMrpcsMgrE, reportResult);
    REG_V1(CMrpcsMgrE, sendReport);
    REG_V1(CMrpcsMgrE, report);
    REG_V1(CMrpcsMgrE, upload);
    REG_ID0(CMrpcsMgrE, getInstance);
    REG_ID0(CMrpcsMgrE, getState);
    REG_ID0(CMrpcsMgrE, getReport);
    REG_ID0(CMrpcsMgrE, getResult);
    REG_ID0(CMrpcsMgrE, getConfig);
    REG_ID1(CMrpcsMgrE, setConfig);
    REG_ID1(CMrpcsMgrE, setState);
    REG_ID1(CMrpcsMgrE, handleData);
    REG_ID1(CMrpcsMgrE, processData);
    REG_ID2(CMrpcsMgrE, sendData_withType);
    REG_ID2(CMrpcsMgrE, handleMessage_withData);

    REG_B (CPointDataMgr, shouldReport);
    REG_B (CPointDataMgr, hasData);
    REG_V1(CPointDataMgr, report);
    REG_V1(CPointDataMgr, sendData);
    REG_V1(CPointDataMgr, uploadData);
    REG_V1(CPointDataMgr, dispatch);
    REG_ID0(CPointDataMgr, getData);
    REG_ID0(CPointDataMgr, getReport);
    REG_ID0(CPointDataMgr, getState);
    REG_ID1(CPointDataMgr, setData);
    REG_ID1(CPointDataMgr, handleData);
    REG_ID2(CPointDataMgr, sendData_withType);

    REG_B (CPointGlobalMgr, shouldReport);
    REG_B (CPointGlobalMgr, hasData);
    REG_V1(CPointGlobalMgr, report);
    REG_V1(CPointGlobalMgr, sendReport);
    REG_V1(CPointGlobalMgr, upload);
    REG_ID0(CPointGlobalMgr, getData);
    REG_ID0(CPointGlobalMgr, getReport);
    REG_ID0(CPointGlobalMgr, getState);
    REG_ID1(CPointGlobalMgr, setData);
    REG_ID1(CPointGlobalMgr, handleData);
    REG_ID2(CPointGlobalMgr, sendData_withType);

    REG_B (CMrpcsLFUpdater, shouldUpdate);
    REG_B (CMrpcsLFUpdater, hasUpdate);
    REG_V1(CMrpcsLFUpdater, update);
    REG_V1(CMrpcsLFUpdater, start);
    REG_V1(CMrpcsLFUpdater, run);
    REG_V1(CMrpcsLFUpdater, check);
    REG_V1(CMrpcsLFUpdater, report);
    REG_ID0(CMrpcsLFUpdater, getState);
    REG_ID0(CMrpcsLFUpdater, getConfig);
    REG_ID0(CMrpcsLFUpdater, getVersion);

    // NetworkManager alert reporters
    REG_V1(NetworkManager, sendRootAlert);
    REG_V1(NetworkManager, sendEmuAlert);
    REG_V1(NetworkManager, sendDebuggerAlert);
    REG_V1(NetworkManager, sendCheatAlert);
    REG_V1(NetworkManager, send9010Alert);
    REG_V1(NetworkManager, send9014Alert);
    REG_V1(NetworkManager, send9005Alert);
    REG_V1(NetworkManager, sendShellReport);
    REG_V1(NetworkManager, sendCheckState);

    // ScreenShot / Rotate
    REG_ID0(ScreenShot, takeScreenShot);
    REG_ID0(ScreenShot, takeScreenShotEx);
    REG_ID0(ScreenShot, screenshot);
    REG_ID1(ScreenShot, takeScreenShotEx);
    REG_ID1(ScreenShot, screenshotOfView);
    REG_ID1(ScreenShot, getBufFromImage);
    REG_ID1(ScreenShot, getAppWindowsForScreen);

    REG_ID0(Rotate, rotate);
    REG_ID0(Rotate, fixOrientation);
    REG_ID0(Rotate, flipVertical);
    REG_ID0(Rotate, flipHorizontal);
    REG_ID1(Rotate, rotate);
    REG_ID1(Rotate, imageRotatedByRadians);
    REG_ID1(Rotate, imageRotatedByDegrees);

    // AceMsgBoxImp
    REG_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn);
    REG_V1(AceMsgBoxImp, dismiss);
    REG_V1(AceMsgBoxImp, show);
    REG_ID0(AceMsgBoxImp, viewTitle);
    REG_ID0(AceMsgBoxImp, viewContent);
    REG_ID0(AceMsgBoxImp, leftBtnContent);
    REG_ID0(AceMsgBoxImp, rightBtnContent);

#undef REG_B
#undef REG_V1
#undef REG_V2
#undef REG_ID0
#undef REG_ID1
#undef REG_ID2
}

#pragma mark =========================================================
#pragma mark 14. REGISTER ALL (base + extended)
#pragma mark =========================================================

static void SBXK_RegisterAll(void) {

#define REG_B(cls, name)   SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "B@:")
#define REG_V1(cls, name)  SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "v@:@")
#define REG_ID0(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:")
#define REG_ID1(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:@")
#define REG_ID2(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:@@")
#define REG_ID3(cls, name) SBXK_SwizzleFull(#cls, #name, (IMP)SBXK_##cls##_##name, "@@:@@@")

    // ─── BOOL detection ───
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
    REG_B(SecurityChecker,   verifyIntegrity);
    REG_B(SecurityChecker,   checkTokenValid);
    REG_B(SecurityChecker,   isEnvironmentSafe);
    REG_B(SecurityChecker,   verifySignature);
    REG_B(AReachability,     isConnectionOnDemand);
    REG_B(AReachability,     isConnectionRequired);
    REG_B(GVGCloudVoiceExtension, CheckDeviceMuteStat);

    // ─── void no-op ───
    REG_V1(GADAppOpenAd, adDidDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adWillDismissFullScreenContent);
    REG_V1(GADAppOpenAd, adDidRecordClick);
    REG_V1(GADAppOpenAd, adDidRecordImpression);
    REG_V1(GADAppOpenAd, adWillPresentFullScreenContent);
    REG_V1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError);
    REG_V1(GADAppOpenAd, setPaidEventHandler);
    REG_V1(GADAppOpenAd, adDidRecordUserInteraction);
    REG_V1(NetworkManager, SendSecurityReport);

    // ─── id pass-through — GSDK ───
    REG_ID0(GSDKCPU,               getSystemCPUCircle);
    REG_ID0(GSDKMemory,            getSystemAvailableMemory);
    REG_ID0(GSDKInGameManager,     GSDKRealTimeDetect);
    REG_ID0(GSDKInGameSystem,      GSDKInnerEnd);
    REG_ID0(GSDKInGameSystem,      GSDKInnerRealTimeDetect);
    REG_ID0(GSDKPing,              ping);
    REG_ID0(GSDKPing,              stopPing);
    REG_ID0(GSDKPingDetect,        ping);
    REG_ID0(PingDelegate,          pingTimer);
    REG_ID0(SimplePing,            start);
    REG_ID0(SimplePing,            startWithHostAddress);
    REG_ID0(SimplePing,            readData);
    REG_ID0(GSDKRealTimeDetect,    pingDelayDetect);
    REG_ID0(GSDKRealTimeDetect,    updDelayDetect_Port);
    REG_ID0(GSDKUdpDetect,         isUDPConnect_Port);
    REG_ID0(GSDKWIFI,              ping);
    REG_ID0(GSDKDetectPort,        isConnection_Port);
    REG_ID0(GSDKInitManager,       detectOperation);
    REG_ID0(GSDKPayEvent,          GSDKPay_Tag_Status_Msg);
    REG_ID0(GSDKHttpRequest,       requestControl_Openid_Acctype_Zoneid_Env);

    REG_ID1(SimplePing,            sendPingWithData);
    REG_ID1(SimplePing,            didFailWithError);
    REG_ID1(FBAdViewabilityValidator, checkViewability);
    REG_ID1(TApmSceneMarker,       postStepEvent);
    REG_ID1(TApmSceneMarker,       postStreamEvent);
    REG_ID1(APMCollector,          collectMetrics);
    REG_ID1(APMCollector,          reportNow);
    REG_ID1(AudioDeviceMgr,        UpdateDeviceState);

    REG_ID2(SimplePing,            validatePingResponsePacket_sequenceNumber);
    REG_ID2(FIRMessaging,          retrieveFCMTokenForSenderID_completion);
    REG_ID2(FIRMessaging,          deleteFCMTokenForSenderID_completion);
    REG_ID2(FIRMessaging,          subscribeToTopic_completion);
    REG_ID2(FIRMessaging,          unsubscribeFromTopic_completion);
    REG_ID2(FIRMessaging,          setAPNSToken_withUserInfo);
    REG_ID2(GSDKInGameSystem,      GSDKInnerSaveFPS_FpsDots);

    REG_ID3(SimplePing,            pingPacketWithType_payload_requiresChecksum);
    REG_ID3(GSDKInGameSystem,      GSDKInnerStart_SceneID_RoomIP);

    // ─── id pass-through — Voice ───
    REG_ID0(GVGCloudVoice,           openMic);
    REG_ID0(GVGCloudVoice,           openSpeaker);
    REG_ID0(GVGCloudVoiceExtension,  GetBGMPlayState);
    REG_ID0(GVGCloudVoiceExtension,  GetMicState);
    REG_ID0(GVGCloudVoiceExtension,  GetSpeakerState);
    REG_ID0(GVoiceMuteSwitch,        detectMuteSwitch);
    REG_ID0(GCloudVoiceEngine,       StartTve);
    REG_ID0(GCloudVoiceEngine,       TestMic);
    REG_ID0(GCloudVoiceEngine,       GetMicLevel);
    REG_ID0(GCloudVoiceEngine,       GetSpeakerLevel);
    REG_ID0(GCloudVoiceEngine,       GetBGMLevel);
    REG_ID0(GCloudVoiceEngine,       GetBGMFileTime);
    REG_ID0(GCloudVoiceEngine,       GetBGMPlayTime);
    REG_ID0(GCloudVoiceEngine,       GetRecordKaraokeTotalTime);
    REG_ID0(GCloudVoiceEngine,       StartPreview);
    REG_ID0(GCloudVoiceEngine,       StopPreview);
    REG_ID0(GCloudVoiceEngine,       PauseKaraoke);
    REG_ID0(GCloudVoiceEngine,       ResumeKaraoke);
    REG_ID0(GCloudVoiceEngine,       RSTSStopRecording);
    REG_ID0(GCloudVoiceEngine,       TextToStreamSpeechStop);
    REG_ID0(GCloudVoiceEngine,       StopKaraokeRecording);
    REG_ID0(GCloudCoreRemoteConfig,  getConfig);
    REG_ID0(GCloudUnityPlugin,       Initialize);
    REG_ID0(GCloudUnityPlugin,       ReportEvent);

    REG_ID1(GCloudVoiceEngine,       StartRecording);
    REG_ID1(GCloudVoiceEngine,       StopRecording);
    REG_ID1(GCloudVoiceEngine,       StartBGMPlay);
    REG_ID1(GCloudVoiceEngine,       StopBGMPlay);
    REG_ID1(GCloudVoiceEngine,       PauseBGMPlay);
    REG_ID1(GCloudVoiceEngine,       ResumeBGMPlay);
    REG_ID1(GCloudVoiceEngine,       SetBGMPath);
    REG_ID1(GCloudVoiceEngine,       SetLogCallBack);
    REG_ID1(GCloudCoreRemoteConfig,  updateConfig);
    REG_ID1(GCloudUnityPlugin,       SetGameObjectName);

    REG_ID2(GCloudVoiceEngine,       QuitRoom_Scenes_timeout);

    // ─── id pass-through — Firebase / Ads ───
    REG_ID0(FIRMessagingRmqManager,  openDatabase);
    REG_ID0(FIRMessaging,            APNSToken);
    REG_ID0(GADAppOpenAd,            responseInfo);
    REG_ID0(GADMobileAds,            initializationStatus);
    REG_ID0(GADAdNetworkResponseInfo, adUnitMapping);
    REG_ID0(FBAdViewabilityValidator, stopMonitoring);
    REG_ID0(FBAdMonitor,             stopMonitoring);

    // ─── id pass-through — APM ───
    REG_ID0(APMDeviceInfoSupport,    getBatteryState);
    REG_ID0(APMDeviceInfoSupport,    getThermalState);
    REG_ID0(TApmSceneMarker,         markLevelFin);

    // ─── id pass-through — Misc ───
    REG_ID0(serviceCommunication,    getValueForKeypath);
    REG_ID0(AudioDeviceMgr,          GetAudioDeviceConnectState);
    REG_ID0(VKAuth,                  logout);
    REG_ID0(SCSDKLoginClient,        logout);

#undef REG_B
#undef REG_V1
#undef REG_ID0
#undef REG_ID1
#undef REG_ID2
#undef REG_ID3
}

#pragma mark =========================================================
#pragma mark 15. LOG VIEWER
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
#pragma mark 16. RETRY + ENTRY
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
    SBXK_RegisterExtended();
}

static void SBXK_RunInstall(void) {
    atomic_store(&g_phase, 20);
    SBXK_RegisterAll();
    SBXK_RegisterExtended();
    atomic_store(&g_phase, 30);
    NSLog(@"[SBXK] v7.7 install: done=%lu skip=%lu",
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

        NSLog(@"[SBXK] v7.7 boot");

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
