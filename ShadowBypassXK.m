// ============================================================================
// ShadowBypass XK v6.1.2 — iOS 14+, arm64/arm64e, no jailbreak
//
// v6.1.2:
//   [A] إزالة كل البانر Amar VIP — لا UIAlertController، لا observer
//   [B] Crash Logger: يلتقط SIGSEGV/ABRT/BUS/ILL/FPE/TRAP + NSException
//       ويكتب: signal، phase، hook_idx، si_addr، backtrace على القرص
//   [C] Phase Markers: تسجيل كل مرحلة في Documents/sbxk_phase.log
//   [D] عند الإقلاع التالي: يُطبع محتوى آخر crash log في NSLog
//   [E] dyld callback بسيط — يضبط flag فقط، بلا dispatch_async
//   [F] Retry timer كل 5s للفئات المتأخرة
//
// قراءة السبب:
//   - Console.app / idevicesyslog → ابحث [SBXK] → سيظهر PREVIOUS CRASH LOG
//   - الملفات داخل التطبيق: Documents/sbxk_crash.log (الحالي)
//                            Documents/sbxk_crash_prev.log (السابق)
//                            Documents/sbxk_phase.log (تتبع المراحل)
//
// Build:
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -arch arm64e -isysroot "$SDK" -miphoneos-version-min=14.0 \
//         -fobjc-arc -O2 -dynamiclib -Wno-nullability-completeness \
//         ShadowBypassXK.m \
//         -framework Foundation -framework UIKit -framework Security \
//         -framework AdSupport -framework AppTrackingTransparency \
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
#import <stdio.h>
#import <string.h>

// backtrace ضعيف التصريح (قد لا يكون موجوداً في بعض البيئات)
extern int backtrace(void **buffer, int size) __attribute__((weak_import));
extern void backtrace_symbols_fd(void *const *buffer, int size, int fd) __attribute__((weak_import));

#define SBXK_LOG(fmt, ...) NSLog(@"[SBXK] " fmt, ##__VA_ARGS__)

#pragma mark =========================================================
#pragma mark 0. PHASE + CRASH PATHS
#pragma mark =========================================================

static volatile int g_phase = 0;
static volatile int g_current_hook = -1;

static char g_crash_path[512] = {0};
static char g_phase_path[512] = {0};

// — كتابات آمنة في سياق الإشارة —
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

#pragma mark =========================================================
#pragma mark 1. TYPE + GLOBALS
#pragma mark =========================================================

typedef struct {
    const char *cls;
    const char *sel;
    IMP         imp;
    const char *expectedRet;
} sbxk_hook_t;

static NSMutableSet<NSString *> *g_pendingClasses = nil;
static volatile bool  g_retry_pending = false;

#pragma mark =========================================================
#pragma mark 2. IMP MACROS — بلا أسماء معاملات
#pragma mark =========================================================

#define DEF_BOOL_NO(cls, name)  static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return NO; }
#define DEF_BOOL_YES(cls, name) static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return YES; }

#define DEF_ID_0(cls, name) static id SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return @(0); }
#define DEF_ID_1(cls, name) static id SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; return @(0); }
#define DEF_ID_2(cls, name) static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; return @(0); }
#define DEF_ID_3(cls, name) static id SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { (void)_s;(void)_c;(void)_a1;(void)_a2;(void)_a3; return @(0); }

#define DEF_VOID_0(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; }
#define DEF_VOID_1(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; }
#define DEF_VOID_2(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }
#define DEF_VOID_2B(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, BOOL _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }
#define DEF_VOID_2I(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, int _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }
#define DEF_VOID_3(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2, id _a3) { (void)_s;(void)_c;(void)_a1;(void)_a2;(void)_a3; }
#define DEF_VOID_3I(cls, name) static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, int _a2, int _a3) { (void)_s;(void)_c;(void)_a1;(void)_a2;(void)_a3; }

#pragma mark =========================================================
#pragma mark 3. IMPLEMENTATIONS
#pragma mark =========================================================

// --- Detection ---
DEF_BOOL_NO(IntegrityChecker, integrity_detect)
DEF_BOOL_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
DEF_BOOL_NO(JailbreakDetector, isJailbroken)
DEF_BOOL_NO(JailbreakDetector, isJailbreak)
DEF_BOOL_NO(JailbreakDetector, checkJailbreak)
DEF_BOOL_NO(JailbreakDetector, jailbreakDetection)
DEF_BOOL_NO(SimulatorDetector, isSimulator)
DEF_BOOL_NO(SimulatorDetector, isSimulatorDevice)
DEF_BOOL_NO(SimulatorDetector, checkSimulator)
DEF_BOOL_NO(SecurityChecker, IsFileSystemModified)
DEF_BOOL_NO(SecurityChecker, isDebuggerAttached)
DEF_BOOL_NO(SecurityChecker, isDebugged)
DEF_BOOL_NO(SecurityChecker, checkDebugger)
DEF_BOOL_NO(SecurityChecker, amIBeingDebugged)
DEF_BOOL_NO(SecurityChecker, checkDebuggerAttach)
DEF_BOOL_NO(SecurityChecker, isHooked)
DEF_BOOL_NO(SecurityChecker, isHookDetected)
DEF_BOOL_NO(SecurityChecker, checkHook)
DEF_BOOL_NO(SecurityChecker, detectHook)
DEF_BOOL_NO(SecurityChecker, antiHookCheck)
DEF_BOOL_NO(SecurityChecker, isTampered)
DEF_BOOL_NO(SecurityChecker, checkTamper)
DEF_BOOL_NO(SecurityChecker, antiTamperCheck)
DEF_BOOL_NO(SecurityChecker, isInjected)
DEF_BOOL_NO(SecurityChecker, isLibraryInjected)
DEF_BOOL_NO(SecurityChecker, checkInjection)
DEF_BOOL_NO(SecurityChecker, antiInjectionCheck)
DEF_BOOL_NO(SecurityChecker, isReversingDetected)
DEF_BOOL_NO(SecurityChecker, checkReversing)
DEF_BOOL_NO(SecurityChecker, antiReversingCheck)
DEF_BOOL_NO(SecurityChecker, isBlocked)
DEF_BOOL_NO(SecurityChecker, antiBlockingCheck)
DEF_BOOL_YES(SecurityChecker, verifyIntegrity)
DEF_BOOL_YES(SecurityChecker, checkTokenValid)
DEF_BOOL_YES(AReachability, isConnectionOnDemand)
DEF_BOOL_YES(AReachability, isConnectionRequired)
DEF_BOOL_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

// --- GAD ---
DEF_VOID_1(GADAppOpenAd, adDidDismissFullScreenContent)
DEF_VOID_1(GADAppOpenAd, adWillDismissFullScreenContent)
DEF_VOID_1(GADAppOpenAd, adDidRecordClick)
DEF_VOID_1(GADAppOpenAd, adDidRecordImpression)
DEF_VOID_1(GADAppOpenAd, adWillPresentFullScreenContent)
DEF_VOID_1(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
DEF_VOID_1(GADAppOpenAd, setPaidEventHandler)
DEF_ID_0(GADAppOpenAd, responseInfo)
DEF_ID_0(GADMobileAds, initializationStatus)
DEF_ID_0(GADAdNetworkResponseInfo, adUnitMapping)

// --- Game ---
static id SBXK_WeaponProcessor_CalculateDamage(id _s, SEL _c, id _t, float _d) {
    (void)_s; (void)_c; (void)_t; (void)_d; return @(0);
}
DEF_BOOL_NO(CharacterMovement, IsSpeedExceeded)
DEF_ID_0(BulletSimulator, CheckWallCollision)
static void SBXK_NetworkManager_SendSecurityReport(id _s, SEL _c, id _r) {
    (void)_s; (void)_c; (void)_r;
}

// --- GSDK ---
DEF_ID_0(GSDKCPU, getSystemCPUCircle)
DEF_ID_0(GSDKMemory, getSystemAvailableMemory)
DEF_ID_0(GSDKInGameManager, GSDKRealTimeDetect)
DEF_ID_0(GSDKInGameSystem, GSDKInnerEnd)
DEF_ID_0(GSDKInGameSystem, GSDKInnerRealTimeDetect)
DEF_ID_0(GSDKPing, ping)
DEF_ID_0(GSDKPing, stopPing)
DEF_ID_0(GSDKPingDetect, ping)
DEF_ID_0(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots)
DEF_ID_0(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP)
DEF_ID_0(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env)
DEF_ID_0(GSDKInitManager, detectOperation)
DEF_ID_0(GSDKPayEvent, GSDKPay_Tag_Status_Msg)
DEF_ID_0(GSDKRealTimeDetect, pingDelayDetect)
DEF_ID_0(GSDKRealTimeDetect, updDelayDetect_Port)
DEF_ID_0(GSDKUdpDetect, isUDPConnect_Port)
DEF_ID_0(GSDKWIFI, ping)
DEF_ID_0(GSDKDetectPort, isConnection_Port)
DEF_ID_0(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error)
DEF_ID_0(GSDKPing, simplePing_didFailWithError)
DEF_ID_0(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber)
DEF_ID_0(GSDKPing, simplePing_didReceiveUnexpectedPacket)
DEF_ID_0(GSDKPing, simplePing_didSendPacket_sequenceNumber)
DEF_ID_0(GSDKPing, simplePing_didStartWithAddress)
DEF_ID_0(GSDKPingDetect, simplePing_didFailToSendPacket_sequenceNumber_error)
DEF_ID_0(GSDKPingDetect, simplePing_didFailWithError)
DEF_ID_0(GSDKPingDetect, simplePing_didReceivePingResponsePacket_sequenceNumber)
DEF_ID_0(GSDKPingDetect, simplePing_didReceiveUnexpectedPacket)
DEF_ID_0(GSDKPingDetect, simplePing_didSendPacket_sequenceNumber)
DEF_ID_0(GSDKPingDetect, simplePing_didStartWithAddress)
DEF_ID_0(PingDelegate, pingTimer)
DEF_ID_0(PingDelegate, simplePing_didFailToSendPacket_sequenceNumber_error)
DEF_ID_0(PingDelegate, simplePing_didSendPacket_sequenceNumber)
DEF_ID_0(SimplePing, start)
DEF_ID_0(SimplePing, startWithHostAddress)
DEF_ID_0(SimplePing, readData)
DEF_ID_0(SimplePing, didFailWithError)
DEF_ID_0(SimplePing, sendPingWithData)
DEF_ID_0(SimplePing, validatePingResponsePacket_sequenceNumber)
DEF_ID_0(SimplePing, pingPacketWithType_payload_requiresChecksum)

// --- Voice ---
DEF_ID_0(GVGCloudVoice, openMic)
DEF_ID_0(GVGCloudVoice, openSpeaker)
DEF_VOID_3(GVGCloudVoice, setAppInfo_withKey_andOpenID)
DEF_ID_0(GVGCloudVoiceExtension, GetBGMPlayState)
DEF_ID_0(GVGCloudVoiceExtension, GetMicState)
DEF_ID_0(GVGCloudVoiceExtension, GetSpeakerState)
DEF_ID_0(GVGCloudVoiceExtension, EnableKeyWordsDetect)
DEF_ID_0(GVoiceMuteSwitch, detectMuteSwitch)
DEF_ID_0(GCloudVoiceEngine, StartTve)
DEF_ID_0(GCloudVoiceEngine, StopRecording)
DEF_ID_0(GCloudVoiceEngine, TestMic)
DEF_ID_0(GCloudVoiceEngine, StartBGMPlay)
DEF_ID_0(GCloudVoiceEngine, StopBGMPlay)
DEF_ID_0(GCloudVoiceEngine, PauseBGMPlay)
DEF_ID_0(GCloudVoiceEngine, ResumeBGMPlay)
DEF_ID_0(GCloudVoiceEngine, RSTSStopRecording)
DEF_ID_0(GCloudVoiceEngine, TextToStreamSpeechStop)
DEF_ID_0(GCloudVoiceEngine, StartPreview)
DEF_ID_0(GCloudVoiceEngine, StopPreview)
DEF_ID_0(GCloudVoiceEngine, PauseKaraoke)
DEF_ID_0(GCloudVoiceEngine, ResumeKaraoke)
DEF_ID_0(GCloudVoiceEngine, GetMicLevel)
DEF_ID_0(GCloudVoiceEngine, GetSpeakerLevel)
DEF_ID_0(GCloudVoiceEngine, GetBGMLevel)
DEF_ID_0(GCloudVoiceEngine, GetBGMFileTime)
DEF_ID_0(GCloudVoiceEngine, GetBGMPlayTime)
DEF_ID_0(GCloudVoiceEngine, GetRecordKaraokeTotalTime)
DEF_ID_0(GCloudVoiceEngine, StopKaraokeRecording)
DEF_ID_0(GCloudVoiceEngine, GetFileParam_data_time)
DEF_ID_0(GCloudCoreRemoteConfig, updateConfig)
DEF_ID_0(GCloudCoreRemoteConfig, getConfig)
DEF_ID_0(GCloudUnityPlugin, Initialize)
DEF_ID_0(GCloudUnityPlugin, ReportEvent)
DEF_ID_0(GCloudUnityPlugin, SetGameObjectName)
DEF_VOID_3I(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout)
DEF_VOID_2I(GCloudVoiceEngine, QuitRoom_Scenes_timeout)
DEF_VOID_2B(GCloudVoiceEngine, EnableMultiRoom)
DEF_VOID_2B(GCloudVoiceEngine, EnableRoomMicrophone_enable)
DEF_VOID_2B(GCloudVoiceEngine, EnableRoomSpeaker_enable)
DEF_VOID_3I(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout)
DEF_VOID_1(GCloudVoiceEngine, StartRecording)
DEF_VOID_1(GCloudVoiceEngine, SetBGMPath)
DEF_VOID_1(GCloudVoiceEngine, SetLogCallBack)
DEF_VOID_2I(GCloudVoiceEngine, SetMicVolume)
DEF_VOID_2I(GCloudVoiceEngine, SetSpeakerVolume)
DEF_VOID_2I(GCloudVoiceEngine, SetBitRate)
DEF_VOID_2I(GCloudVoiceEngine, SetDataFree)
DEF_VOID_2I(GCloudVoiceEngine, SetReportBufferTime)
DEF_VOID_2I(GCloudVoiceEngine, SetBGMPlayTime)
DEF_VOID_2I(GCloudVoiceEngine, SetKaraokeVoiceVol)
DEF_VOID_2I(GCloudVoiceEngine, SetKaraokeAccVol)
DEF_VOID_2I(GCloudVoiceEngine, SetKaraokeVoiceDelay)
DEF_VOID_2I(GCloudVoiceEngine, SeekTimeMsForPreview)
DEF_VOID_2I(GCloudVoiceEngine, SeekTimeMsForAcc)
DEF_VOID_2B(GCloudVoiceEngine, EnableLog)
DEF_VOID_2B(GCloudVoiceEngine, EnableNativeBGMPlay)
DEF_VOID_2B(GCloudVoiceEngine, EnableRecvMagicVoice)
DEF_VOID_2B(GCloudVoiceEngine, EnableReportALL)
DEF_VOID_2B(GCloudVoiceEngine, EnableReportALLAbroad)
DEF_VOID_2B(GCloudVoiceEngine, EnableReportForAbroad)
DEF_VOID_2B(GCloudVoiceEngine, EnableCivilFile)
DEF_VOID_2B(GCloudVoiceEngine, EnableCivilVoice)
DEF_VOID_2B(GCloudVoiceEngine, EnableEarBack)
DEF_VOID_2B(GCloudVoiceEngine, EnableAccFilePlay)

// --- Firebase / Ads ---
DEF_ID_0(FIRMessagingRmqManager, openDatabase)
DEF_ID_0(FIRMessaging, retrieveFCMTokenForSenderID_completion)
DEF_ID_0(FIRMessaging, deleteFCMTokenForSenderID_completion)
DEF_ID_0(FIRMessaging, subscribeToTopic_completion)
DEF_ID_0(FIRMessaging, unsubscribeFromTopic_completion)
DEF_ID_0(FIRMessaging, setAPNSToken_withUserInfo)
DEF_ID_0(FIRMessaging, APNSToken)
DEF_ID_0(FBAdViewabilityValidator, checkViewability)
DEF_ID_0(FBAdMonitor, startMonitoringAd)
DEF_ID_0(FBAdViewabilityValidator, stopMonitoring)
DEF_ID_0(FBAdMonitor, stopMonitoring)
DEF_ID_0(FBAdEvent, logEvent_withParameters)
DEF_ID_0(FBAdLogger, logMessage_withLevel)

// --- QQ ---
DEF_ID_0(QQApiInterface, sendReq_resultBlock)
DEF_ID_0(QQApiInterface, sendThirdAppBindGroupReq_resultBlock)
DEF_ID_0(QQApiInterface, sendThirdAppUnBindGroupReq_resultBlock)
DEF_ID_0(QQApiInterface, sendThirdAppJoinGroupReq_resultBlock)
DEF_ID_0(QQApiInterface, sendQueryQQGroupProInfo_resultBlock)
DEF_ID_0(QQApiInterface, sendMessageToQQAuthWithReq)
DEF_ID_0(QQApiInterface, sendMessageToQQAvatarWithReq)
DEF_ID_0(QQApiInterface, sendMessageToFaceCollectionWithReq)
DEF_ID_0(QQOpenApiUtility, cgiRequestGetSdkConfig)
DEF_ID_0(TDataMasterApplication, handleOpenURL)
DEF_ID_0(TDataMasterApplication, reportEventWithSrcID_eventName_AndEventKVArray)
DEF_ID_0(TcApiTool, openUniversallinkIfNeed)
DEF_ID_0(GTMSessionFetcher, setSystemCompletionHandler_forSessionIdentifier)

// --- IMSDK ---
DEF_ID_0(IMSDKNoticeIMSDKManager, getImageCache_imagePath_imageHash_queue_completeHandle)
DEF_ID_0(IMSDKNoticeIMSDKManager, imsdkCoreKitNoticeImageFileHash)
DEF_ID_0(IMSDKStatAdjustManager, reportEvent_eventBody_isRealtime)
DEF_ID_0(IMSDKStatAdjustManager, reportEvent_params_isRealtime)
DEF_ID_0(IMSDKStatAdjustManager, reportPurchase_currentCode_expense_isRealTime)
DEF_ID_0(IMSDKStatAdjustManager, reportRevenue_currencyCode_revenueValue_params_extraJson)
DEF_ID_0(INTLWebViewManager, openURL_observerID_baseParams)

// --- APM ---
DEF_ID_0(APMMonitor, handleEvent)
DEF_ID_0(APMMonitor, startMonitoring)
DEF_ID_0(APMDeviceInfoSupport, getBatteryState)
DEF_ID_0(APMDeviceInfoSupport, getThermalState)
DEF_ID_0(APMCollector, collectMetrics)
DEF_ID_0(APMCollector, reportNow)
DEF_ID_0(TApmSceneMarker, markLoadLevel)
DEF_ID_0(TApmSceneMarker, markLevelFin)
DEF_ID_0(TApmSceneMarker, postStepEvent)
DEF_ID_0(TApmSceneMarker, postStreamEvent)

// --- Misc ---
DEF_ID_0(serviceCommunication, getValueForKeypath)
DEF_ID_0(AudioDeviceMgr, GetAudioDeviceConnectState)
DEF_ID_0(AudioDeviceMgr, UpdateDeviceState)
DEF_ID_0(TikTokAuth, authorizeWithPermissions)
DEF_ID_0(TikTokAuth, handleOpenURL)
DEF_ID_0(VKAuth, authorizeWithPermissions)
DEF_ID_0(VKAuth, logout)
DEF_ID_0(SCSDKLoginClient, loginWithCompletion)
DEF_ID_0(SCSDKLoginClient, logout)

// --- Advertising ---
static NSString *SBXK_ASIdentifierManager_advertisingIdentifier(id _s, SEL _c) {
    (void)_s; (void)_c; return @"00000000-0000-0000-0000-000000000000";
}
static NSInteger SBXK_ATTrackingManager_trackingAuthorizationStatus(id _s, SEL _c) {
    (void)_s; (void)_c; return 3;
}

#pragma mark =========================================================
#pragma mark 4. HOOK TABLE
#pragma mark =========================================================

static const sbxk_hook_t g_hooks[] = {
    {"IntegrityChecker", "integrity_detect", (IMP)SBXK_IntegrityChecker_integrity_detect, "B"},
    {"IntegrityChecker", "MTML_INTEGRITY_DETECT", (IMP)SBXK_IntegrityChecker_MTML_INTEGRITY_DETECT, "B"},
    {"JailbreakDetector", "isJailbroken", (IMP)SBXK_JailbreakDetector_isJailbroken, "B"},
    {"JailbreakDetector", "isJailbreak", (IMP)SBXK_JailbreakDetector_isJailbreak, "B"},
    {"JailbreakDetector", "checkJailbreak", (IMP)SBXK_JailbreakDetector_checkJailbreak, "B"},
    {"JailbreakDetector", "jailbreakDetection", (IMP)SBXK_JailbreakDetector_jailbreakDetection, "B"},
    {"SimulatorDetector", "isSimulator", (IMP)SBXK_SimulatorDetector_isSimulator, "B"},
    {"SimulatorDetector", "isSimulatorDevice", (IMP)SBXK_SimulatorDetector_isSimulatorDevice, "B"},
    {"SimulatorDetector", "checkSimulator", (IMP)SBXK_SimulatorDetector_checkSimulator, "B"},
    {"SecurityChecker", "IsFileSystemModified", (IMP)SBXK_SecurityChecker_IsFileSystemModified, "B"},
    {"SecurityChecker", "isDebuggerAttached", (IMP)SBXK_SecurityChecker_isDebuggerAttached, "B"},
    {"SecurityChecker", "isDebugged", (IMP)SBXK_SecurityChecker_isDebugged, "B"},
    {"SecurityChecker", "checkDebugger", (IMP)SBXK_SecurityChecker_checkDebugger, "B"},
    {"SecurityChecker", "amIBeingDebugged", (IMP)SBXK_SecurityChecker_amIBeingDebugged, "B"},
    {"SecurityChecker", "checkDebuggerAttach", (IMP)SBXK_SecurityChecker_checkDebuggerAttach, "B"},
    {"SecurityChecker", "isHooked", (IMP)SBXK_SecurityChecker_isHooked, "B"},
    {"SecurityChecker", "isHookDetected", (IMP)SBXK_SecurityChecker_isHookDetected, "B"},
    {"SecurityChecker", "checkHook", (IMP)SBXK_SecurityChecker_checkHook, "B"},
    {"SecurityChecker", "detectHook", (IMP)SBXK_SecurityChecker_detectHook, "B"},
    {"SecurityChecker", "antiHookCheck", (IMP)SBXK_SecurityChecker_antiHookCheck, "B"},
    {"SecurityChecker", "isTampered", (IMP)SBXK_SecurityChecker_isTampered, "B"},
    {"SecurityChecker", "checkTamper", (IMP)SBXK_SecurityChecker_checkTamper, "B"},
    {"SecurityChecker", "antiTamperCheck", (IMP)SBXK_SecurityChecker_antiTamperCheck, "B"},
    {"SecurityChecker", "isInjected", (IMP)SBXK_SecurityChecker_isInjected, "B"},
    {"SecurityChecker", "isLibraryInjected", (IMP)SBXK_SecurityChecker_isLibraryInjected, "B"},
    {"SecurityChecker", "checkInjection", (IMP)SBXK_SecurityChecker_checkInjection, "B"},
    {"SecurityChecker", "antiInjectionCheck", (IMP)SBXK_SecurityChecker_antiInjectionCheck, "B"},
    {"SecurityChecker", "isReversingDetected", (IMP)SBXK_SecurityChecker_isReversingDetected, "B"},
    {"SecurityChecker", "checkReversing", (IMP)SBXK_SecurityChecker_checkReversing, "B"},
    {"SecurityChecker", "antiReversingCheck", (IMP)SBXK_SecurityChecker_antiReversingCheck, "B"},
    {"SecurityChecker", "isBlocked", (IMP)SBXK_SecurityChecker_isBlocked, "B"},
    {"SecurityChecker", "antiBlockingCheck", (IMP)SBXK_SecurityChecker_antiBlockingCheck, "B"},
    {"SecurityChecker", "verifyIntegrity", (IMP)SBXK_SecurityChecker_verifyIntegrity, "B"},
    {"SecurityChecker", "checkTokenValid", (IMP)SBXK_SecurityChecker_checkTokenValid, "B"},
    {"AReachability", "isConnectionOnDemand", (IMP)SBXK_AReachability_isConnectionOnDemand, "B"},
    {"AReachability", "isConnectionRequired", (IMP)SBXK_AReachability_isConnectionRequired, "B"},
    {"GVGCloudVoiceExtension", "CheckDeviceMuteStat", (IMP)SBXK_GVGCloudVoiceExtension_CheckDeviceMuteStat, "B"},

    {"GADAppOpenAd", "adDidDismissFullScreenContent:", (IMP)SBXK_GADAppOpenAd_adDidDismissFullScreenContent, "v"},
    {"GADAppOpenAd", "adWillDismissFullScreenContent:", (IMP)SBXK_GADAppOpenAd_adWillDismissFullScreenContent, "v"},
    {"GADAppOpenAd", "adDidRecordClick:", (IMP)SBXK_GADAppOpenAd_adDidRecordClick, "v"},
    {"GADAppOpenAd", "adDidRecordImpression:", (IMP)SBXK_GADAppOpenAd_adDidRecordImpression, "v"},
    {"GADAppOpenAd", "adWillPresentFullScreenContent:", (IMP)SBXK_GADAppOpenAd_adWillPresentFullScreenContent, "v"},
    {"GADAppOpenAd", "adDidFailToPresentFullScreenContentWithError:", (IMP)SBXK_GADAppOpenAd_adDidFailToPresentFullScreenContentWithError, "v"},
    {"GADAppOpenAd", "setPaidEventHandler:", (IMP)SBXK_GADAppOpenAd_setPaidEventHandler, "v"},
    {"GADAppOpenAd", "responseInfo", (IMP)SBXK_GADAppOpenAd_responseInfo, "@"},
    {"GADMobileAds", "initializationStatus", (IMP)SBXK_GADMobileAds_initializationStatus, "@"},
    {"GADAdNetworkResponseInfo", "adUnitMapping", (IMP)SBXK_GADAdNetworkResponseInfo_adUnitMapping, "@"},

    {"WeaponProcessor", "CalculateDamage:distance:", (IMP)SBXK_WeaponProcessor_CalculateDamage, "@"},
    {"CharacterMovement", "IsSpeedExceeded", (IMP)SBXK_CharacterMovement_IsSpeedExceeded, "B"},
    {"BulletSimulator", "CheckWallCollision", (IMP)SBXK_BulletSimulator_CheckWallCollision, "@"},
    {"NetworkManager", "SendSecurityReport:", (IMP)SBXK_NetworkManager_SendSecurityReport, "v"},

    {"GSDKCPU", "getSystemCPUCircle", (IMP)SBXK_GSDKCPU_getSystemCPUCircle, "@"},
    {"GSDKMemory", "getSystemAvailableMemory", (IMP)SBXK_GSDKMemory_getSystemAvailableMemory, "@"},
    {"GSDKInGameManager", "GSDKRealTimeDetect", (IMP)SBXK_GSDKInGameManager_GSDKRealTimeDetect, "@"},
    {"GSDKInGameSystem", "GSDKInnerEnd", (IMP)SBXK_GSDKInGameSystem_GSDKInnerEnd, "@"},
    {"GSDKInGameSystem", "GSDKInnerRealTimeDetect", (IMP)SBXK_GSDKInGameSystem_GSDKInnerRealTimeDetect, "@"},
    {"GSDKInGameSystem", "GSDKInnerSaveFPS:FpsDots:", (IMP)SBXK_GSDKInGameSystem_GSDKInnerSaveFPS_FpsDots, "@"},
    {"GSDKInGameSystem", "GSDKInnerStart:SceneID:RoomIP:", (IMP)SBXK_GSDKInGameSystem_GSDKInnerStart_SceneID_RoomIP, "@"},
    {"GSDKHttpRequest", "requestControl:Openid:Acctype:Zoneid:Env:", (IMP)SBXK_GSDKHttpRequest_requestControl_Openid_Acctype_Zoneid_Env, "@"},
    {"GSDKInitManager", "detectOperation:", (IMP)SBXK_GSDKInitManager_detectOperation, "@"},
    {"GSDKPayEvent", "GSDKPay:Tag:Status:Msg:", (IMP)SBXK_GSDKPayEvent_GSDKPay_Tag_Status_Msg, "@"},
    {"GSDKRealTimeDetect", "pingDelayDetect:", (IMP)SBXK_GSDKRealTimeDetect_pingDelayDetect, "@"},
    {"GSDKRealTimeDetect", "updDelayDetect:Port:", (IMP)SBXK_GSDKRealTimeDetect_updDelayDetect_Port, "@"},
    {"GSDKUdpDetect", "isUDPConnect:Port:", (IMP)SBXK_GSDKUdpDetect_isUDPConnect_Port, "@"},
    {"GSDKWIFI", "ping:", (IMP)SBXK_GSDKWIFI_ping, "@"},
    {"GSDKDetectPort", "isConnection:Port:", (IMP)SBXK_GSDKDetectPort_isConnection_Port, "@"},
    {"GSDKPing", "ping", (IMP)SBXK_GSDKPing_ping, "@"},
    {"GSDKPing", "stopPing", (IMP)SBXK_GSDKPing_stopPing, "@"},
    {"GSDKPing", "simplePing:didFailToSendPacket:sequenceNumber:error:", (IMP)SBXK_GSDKPing_simplePing_didFailToSendPacket_sequenceNumber_error, "@"},
    {"GSDKPing", "simplePing:didFailWithError:", (IMP)SBXK_GSDKPing_simplePing_didFailWithError, "@"},
    {"GSDKPing", "simplePing:didReceivePingResponsePacket:sequenceNumber:", (IMP)SBXK_GSDKPing_simplePing_didReceivePingResponsePacket_sequenceNumber, "@"},
    {"GSDKPing", "simplePing:didReceiveUnexpectedPacket:", (IMP)SBXK_GSDKPing_simplePing_didReceiveUnexpectedPacket, "@"},
    {"GSDKPing", "simplePing:didSendPacket:sequenceNumber:", (IMP)SBXK_GSDKPing_simplePing_didSendPacket_sequenceNumber, "@"},
    {"GSDKPing", "simplePing:didStartWithAddress:", (IMP)SBXK_GSDKPing_simplePing_didStartWithAddress, "@"},
    {"GSDKPingDetect", "ping", (IMP)SBXK_GSDKPingDetect_ping, "@"},
    {"GSDKPingDetect", "simplePing:didFailToSendPacket:sequenceNumber:error:", (IMP)SBXK_GSDKPingDetect_simplePing_didFailToSendPacket_sequenceNumber_error, "@"},
    {"GSDKPingDetect", "simplePing:didFailWithError:", (IMP)SBXK_GSDKPingDetect_simplePing_didFailWithError, "@"},
    {"GSDKPingDetect", "simplePing:didReceivePingResponsePacket:sequenceNumber:", (IMP)SBXK_GSDKPingDetect_simplePing_didReceivePingResponsePacket_sequenceNumber, "@"},
    {"GSDKPingDetect", "simplePing:didReceiveUnexpectedPacket:", (IMP)SBXK_GSDKPingDetect_simplePing_didReceiveUnexpectedPacket, "@"},
    {"GSDKPingDetect", "simplePing:didSendPacket:sequenceNumber:", (IMP)SBXK_GSDKPingDetect_simplePing_didSendPacket_sequenceNumber, "@"},
    {"GSDKPingDetect", "simplePing:didStartWithAddress:", (IMP)SBXK_GSDKPingDetect_simplePing_didStartWithAddress, "@"},
    {"PingDelegate", "pingTimer", (IMP)SBXK_PingDelegate_pingTimer, "@"},
    {"PingDelegate", "simplePing:didFailToSendPacket:sequenceNumber:error:", (IMP)SBXK_PingDelegate_simplePing_didFailToSendPacket_sequenceNumber_error, "@"},
    {"PingDelegate", "simplePing:didSendPacket:sequenceNumber:", (IMP)SBXK_PingDelegate_simplePing_didSendPacket_sequenceNumber, "@"},
    {"SimplePing", "start", (IMP)SBXK_SimplePing_start, "@"},
    {"SimplePing", "startWithHostAddress", (IMP)SBXK_SimplePing_startWithHostAddress, "@"},
    {"SimplePing", "readData", (IMP)SBXK_SimplePing_readData, "@"},
    {"SimplePing", "didFailWithError:", (IMP)SBXK_SimplePing_didFailWithError, "@"},
    {"SimplePing", "sendPingWithData:", (IMP)SBXK_SimplePing_sendPingWithData, "@"},
    {"SimplePing", "validatePingResponsePacket:sequenceNumber:", (IMP)SBXK_SimplePing_validatePingResponsePacket_sequenceNumber, "@"},
    {"SimplePing", "pingPacketWithType:payload:requiresChecksum:", (IMP)SBXK_SimplePing_pingPacketWithType_payload_requiresChecksum, "@"},

    {"GVGCloudVoice", "openMic", (IMP)SBXK_GVGCloudVoice_openMic, "@"},
    {"GVGCloudVoice", "openSpeaker", (IMP)SBXK_GVGCloudVoice_openSpeaker, "@"},
    {"GVGCloudVoice", "setAppInfo:withKey:andOpenID:", (IMP)SBXK_GVGCloudVoice_setAppInfo_withKey_andOpenID, "v"},
    {"GVGCloudVoiceExtension", "GetBGMPlayState", (IMP)SBXK_GVGCloudVoiceExtension_GetBGMPlayState, "@"},
    {"GVGCloudVoiceExtension", "GetMicState", (IMP)SBXK_GVGCloudVoiceExtension_GetMicState, "@"},
    {"GVGCloudVoiceExtension", "GetSpeakerState", (IMP)SBXK_GVGCloudVoiceExtension_GetSpeakerState, "@"},
    {"GVGCloudVoiceExtension", "EnableKeyWordsDetect:", (IMP)SBXK_GVGCloudVoiceExtension_EnableKeyWordsDetect, "@"},
    {"GVoiceMuteSwitch", "detectMuteSwitch", (IMP)SBXK_GVoiceMuteSwitch_detectMuteSwitch, "@"},
    {"GCloudVoiceEngine", "StartTve", (IMP)SBXK_GCloudVoiceEngine_StartTve, "@"},
    {"GCloudVoiceEngine", "StopRecording", (IMP)SBXK_GCloudVoiceEngine_StopRecording, "@"},
    {"GCloudVoiceEngine", "TestMic", (IMP)SBXK_GCloudVoiceEngine_TestMic, "@"},
    {"GCloudVoiceEngine", "StartBGMPlay", (IMP)SBXK_GCloudVoiceEngine_StartBGMPlay, "@"},
    {"GCloudVoiceEngine", "StopBGMPlay", (IMP)SBXK_GCloudVoiceEngine_StopBGMPlay, "@"},
    {"GCloudVoiceEngine", "PauseBGMPlay", (IMP)SBXK_GCloudVoiceEngine_PauseBGMPlay, "@"},
    {"GCloudVoiceEngine", "ResumeBGMPlay", (IMP)SBXK_GCloudVoiceEngine_ResumeBGMPlay, "@"},
    {"GCloudVoiceEngine", "RSTSStopRecording", (IMP)SBXK_GCloudVoiceEngine_RSTSStopRecording, "@"},
    {"GCloudVoiceEngine", "TextToStreamSpeechStop", (IMP)SBXK_GCloudVoiceEngine_TextToStreamSpeechStop, "@"},
    {"GCloudVoiceEngine", "StartPreview", (IMP)SBXK_GCloudVoiceEngine_StartPreview, "@"},
    {"GCloudVoiceEngine", "StopPreview", (IMP)SBXK_GCloudVoiceEngine_StopPreview, "@"},
    {"GCloudVoiceEngine", "PauseKaraoke", (IMP)SBXK_GCloudVoiceEngine_PauseKaraoke, "@"},
    {"GCloudVoiceEngine", "ResumeKaraoke", (IMP)SBXK_GCloudVoiceEngine_ResumeKaraoke, "@"},
    {"GCloudVoiceEngine", "GetMicLevel", (IMP)SBXK_GCloudVoiceEngine_GetMicLevel, "@"},
    {"GCloudVoiceEngine", "GetSpeakerLevel", (IMP)SBXK_GCloudVoiceEngine_GetSpeakerLevel, "@"},
    {"GCloudVoiceEngine", "GetBGMLevel", (IMP)SBXK_GCloudVoiceEngine_GetBGMLevel, "@"},
    {"GCloudVoiceEngine", "GetBGMFileTime", (IMP)SBXK_GCloudVoiceEngine_GetBGMFileTime, "@"},
    {"GCloudVoiceEngine", "GetBGMPlayTime", (IMP)SBXK_GCloudVoiceEngine_GetBGMPlayTime, "@"},
    {"GCloudVoiceEngine", "GetRecordKaraokeTotalTime", (IMP)SBXK_GCloudVoiceEngine_GetRecordKaraokeTotalTime, "@"},
    {"GCloudVoiceEngine", "StopKaraokeRecording", (IMP)SBXK_GCloudVoiceEngine_StopKaraokeRecording, "@"},
    {"GCloudVoiceEngine", "GetFileParam:data:time:", (IMP)SBXK_GCloudVoiceEngine_GetFileParam_data_time, "@"},
    {"GCloudVoiceEngine", "JoinTeamRoom:Scenes:roomName:timeout:", (IMP)SBXK_GCloudVoiceEngine_JoinTeamRoom_Scenes_roomName_timeout, "v"},
    {"GCloudVoiceEngine", "QuitRoom:Scenes:timeout:", (IMP)SBXK_GCloudVoiceEngine_QuitRoom_Scenes_timeout, "v"},
    {"GCloudVoiceEngine", "EnableMultiRoom:", (IMP)SBXK_GCloudVoiceEngine_EnableMultiRoom, "v"},
    {"GCloudVoiceEngine", "EnableRoomMicrophone:enable:", (IMP)SBXK_GCloudVoiceEngine_EnableRoomMicrophone_enable, "v"},
    {"GCloudVoiceEngine", "EnableRoomSpeaker:enable:", (IMP)SBXK_GCloudVoiceEngine_EnableRoomSpeaker_enable, "v"},
    {"GCloudVoiceEngine", "ApplyMessageKey:timestamp:timeout:", (IMP)SBXK_GCloudVoiceEngine_ApplyMessageKey_timestamp_timeout, "v"},
    {"GCloudVoiceEngine", "StartRecording:", (IMP)SBXK_GCloudVoiceEngine_StartRecording, "v"},
    {"GCloudVoiceEngine", "SetBGMPath:", (IMP)SBXK_GCloudVoiceEngine_SetBGMPath, "v"},
    {"GCloudVoiceEngine", "SetLogCallBack:", (IMP)SBXK_GCloudVoiceEngine_SetLogCallBack, "v"},
    {"GCloudVoiceEngine", "SetMicVolume:", (IMP)SBXK_GCloudVoiceEngine_SetMicVolume, "v"},
    {"GCloudVoiceEngine", "SetSpeakerVolume:", (IMP)SBXK_GCloudVoiceEngine_SetSpeakerVolume, "v"},
    {"GCloudVoiceEngine", "SetBitRate:", (IMP)SBXK_GCloudVoiceEngine_SetBitRate, "v"},
    {"GCloudVoiceEngine", "SetDataFree:", (IMP)SBXK_GCloudVoiceEngine_SetDataFree, "v"},
    {"GCloudVoiceEngine", "SetReportBufferTime:", (IMP)SBXK_GCloudVoiceEngine_SetReportBufferTime, "v"},
    {"GCloudVoiceEngine", "SetBGMPlayTime:", (IMP)SBXK_GCloudVoiceEngine_SetBGMPlayTime, "v"},
    {"GCloudVoiceEngine", "SetKaraokeVoiceVol:", (IMP)SBXK_GCloudVoiceEngine_SetKaraokeVoiceVol, "v"},
    {"GCloudVoiceEngine", "SetKaraokeAccVol:", (IMP)SBXK_GCloudVoiceEngine_SetKaraokeAccVol, "v"},
    {"GCloudVoiceEngine", "SetKaraokeVoiceDelay:", (IMP)SBXK_GCloudVoiceEngine_SetKaraokeVoiceDelay, "v"},
    {"GCloudVoiceEngine", "SeekTimeMsForPreview:", (IMP)SBXK_GCloudVoiceEngine_SeekTimeMsForPreview, "v"},
    {"GCloudVoiceEngine", "SeekTimeMsForAcc:", (IMP)SBXK_GCloudVoiceEngine_SeekTimeMsForAcc, "v"},
    {"GCloudVoiceEngine", "EnableLog:", (IMP)SBXK_GCloudVoiceEngine_EnableLog, "v"},
    {"GCloudVoiceEngine", "EnableNativeBGMPlay:", (IMP)SBXK_GCloudVoiceEngine_EnableNativeBGMPlay, "v"},
    {"GCloudVoiceEngine", "EnableRecvMagicVoice:", (IMP)SBXK_GCloudVoiceEngine_EnableRecvMagicVoice, "v"},
    {"GCloudVoiceEngine", "EnableReportALL:", (IMP)SBXK_GCloudVoiceEngine_EnableReportALL, "v"},
    {"GCloudVoiceEngine", "EnableReportALLAbroad:", (IMP)SBXK_GCloudVoiceEngine_EnableReportALLAbroad, "v"},
    {"GCloudVoiceEngine", "EnableReportForAbroad:", (IMP)SBXK_GCloudVoiceEngine_EnableReportForAbroad, "v"},
    {"GCloudVoiceEngine", "EnableCivilFile:", (IMP)SBXK_GCloudVoiceEngine_EnableCivilFile, "v"},
    {"GCloudVoiceEngine", "EnableCivilVoice:", (IMP)SBXK_GCloudVoiceEngine_EnableCivilVoice, "v"},
    {"GCloudVoiceEngine", "EnableEarBack:", (IMP)SBXK_GCloudVoiceEngine_EnableEarBack, "v"},
    {"GCloudVoiceEngine", "EnableAccFilePlay:", (IMP)SBXK_GCloudVoiceEngine_EnableAccFilePlay, "v"},
    {"GCloudCoreRemoteConfig", "updateConfig:", (IMP)SBXK_GCloudCoreRemoteConfig_updateConfig, "@"},
    {"GCloudCoreRemoteConfig", "getConfig:", (IMP)SBXK_GCloudCoreRemoteConfig_getConfig, "@"},
    {"GCloudUnityPlugin", "Initialize", (IMP)SBXK_GCloudUnityPlugin_Initialize, "@"},
    {"GCloudUnityPlugin", "ReportEvent", (IMP)SBXK_GCloudUnityPlugin_ReportEvent, "@"},
    {"GCloudUnityPlugin", "SetGameObjectName:", (IMP)SBXK_GCloudUnityPlugin_SetGameObjectName, "@"},

    {"FIRMessagingRmqManager", "openDatabase", (IMP)SBXK_FIRMessagingRmqManager_openDatabase, "@"},
    {"FIRMessaging", "retrieveFCMTokenForSenderID:completion:", (IMP)SBXK_FIRMessaging_retrieveFCMTokenForSenderID_completion, "@"},
    {"FIRMessaging", "deleteFCMTokenForSenderID:completion:", (IMP)SBXK_FIRMessaging_deleteFCMTokenForSenderID_completion, "@"},
    {"FIRMessaging", "subscribeToTopic:completion:", (IMP)SBXK_FIRMessaging_subscribeToTopic_completion, "@"},
    {"FIRMessaging", "unsubscribeFromTopic:completion:", (IMP)SBXK_FIRMessaging_unsubscribeFromTopic_completion, "@"},
    {"FIRMessaging", "setAPNSToken:withUserInfo:", (IMP)SBXK_FIRMessaging_setAPNSToken_withUserInfo, "@"},
    {"FIRMessaging", "APNSToken", (IMP)SBXK_FIRMessaging_APNSToken, "@"},
    {"FBAdViewabilityValidator", "checkViewability:", (IMP)SBXK_FBAdViewabilityValidator_checkViewability, "@"},
    {"FBAdMonitor", "startMonitoringAd:", (IMP)SBXK_FBAdMonitor_startMonitoringAd, "@"},
    {"FBAdViewabilityValidator", "stopMonitoring", (IMP)SBXK_FBAdViewabilityValidator_stopMonitoring, "@"},
    {"FBAdMonitor", "stopMonitoring", (IMP)SBXK_FBAdMonitor_stopMonitoring, "@"},
    {"FBAdEvent", "logEvent:withParameters:", (IMP)SBXK_FBAdEvent_logEvent_withParameters, "@"},
    {"FBAdLogger", "logMessage:withLevel:", (IMP)SBXK_FBAdLogger_logMessage_withLevel, "@"},

    {"QQApiInterface", "sendReq:resultBlock:", (IMP)SBXK_QQApiInterface_sendReq_resultBlock, "@"},
    {"QQApiInterface", "sendThirdAppBindGroupReq:resultBlock:", (IMP)SBXK_QQApiInterface_sendThirdAppBindGroupReq_resultBlock, "@"},
    {"QQApiInterface", "sendThirdAppUnBindGroupReq:resultBlock:", (IMP)SBXK_QQApiInterface_sendThirdAppUnBindGroupReq_resultBlock, "@"},
    {"QQApiInterface", "sendThirdAppJoinGroupReq:resultBlock:", (IMP)SBXK_QQApiInterface_sendThirdAppJoinGroupReq_resultBlock, "@"},
    {"QQApiInterface", "sendQueryQQGroupProInfo:resultBlock:", (IMP)SBXK_QQApiInterface_sendQueryQQGroupProInfo_resultBlock, "@"},
    {"QQApiInterface", "sendMessageToQQAuthWithReq:", (IMP)SBXK_QQApiInterface_sendMessageToQQAuthWithReq, "@"},
    {"QQApiInterface", "sendMessageToQQAvatarWithReq:", (IMP)SBXK_QQApiInterface_sendMessageToQQAvatarWithReq, "@"},
    {"QQApiInterface", "sendMessageToFaceCollectionWithReq:", (IMP)SBXK_QQApiInterface_sendMessageToFaceCollectionWithReq, "@"},
    {"QQOpenApiUtility", "cgiRequestGetSdkConfig:", (IMP)SBXK_QQOpenApiUtility_cgiRequestGetSdkConfig, "@"},
    {"TDataMasterApplication", "handleOpenURL:", (IMP)SBXK_TDataMasterApplication_handleOpenURL, "@"},
    {"TDataMasterApplication", "reportEventWithSrcID:eventName:AndEventKVArray:", (IMP)SBXK_TDataMasterApplication_reportEventWithSrcID_eventName_AndEventKVArray, "@"},
    {"TcApiTool", "openUniversallinkIfNeed:", (IMP)SBXK_TcApiTool_openUniversallinkIfNeed, "@"},
    {"GTMSessionFetcher", "setSystemCompletionHandler:forSessionIdentifier:", (IMP)SBXK_GTMSessionFetcher_setSystemCompletionHandler_forSessionIdentifier, "@"},

    {"IMSDKNoticeIMSDKManager", "getImageCache:imagePath:imageHash:queue:completeHandle:", (IMP)SBXK_IMSDKNoticeIMSDKManager_getImageCache_imagePath_imageHash_queue_completeHandle, "@"},
    {"IMSDKNoticeIMSDKManager", "imsdkCoreKitNoticeImageFileHash:", (IMP)SBXK_IMSDKNoticeIMSDKManager_imsdkCoreKitNoticeImageFileHash, "@"},
    {"IMSDKStatAdjustManager", "reportEvent:eventBody:isRealtime:", (IMP)SBXK_IMSDKStatAdjustManager_reportEvent_eventBody_isRealtime, "@"},
    {"IMSDKStatAdjustManager", "reportEvent:params:isRealtime:", (IMP)SBXK_IMSDKStatAdjustManager_reportEvent_params_isRealtime, "@"},
    {"IMSDKStatAdjustManager", "reportPurchase:currentCode:expense:isRealTime:", (IMP)SBXK_IMSDKStatAdjustManager_reportPurchase_currentCode_expense_isRealTime, "@"},
    {"IMSDKStatAdjustManager", "reportRevenue:currencyCode:revenueValue:params:extraJson:", (IMP)SBXK_IMSDKStatAdjustManager_reportRevenue_currencyCode_revenueValue_params_extraJson, "@"},
    {"INTLWebViewManager", "openURL:observerID:baseParams:", (IMP)SBXK_INTLWebViewManager_openURL_observerID_baseParams, "@"},

    {"APMMonitor", "handleEvent:", (IMP)SBXK_APMMonitor_handleEvent, "@"},
    {"APMMonitor", "startMonitoring:", (IMP)SBXK_APMMonitor_startMonitoring, "@"},
    {"APMDeviceInfoSupport", "getBatteryState", (IMP)SBXK_APMDeviceInfoSupport_getBatteryState, "@"},
    {"APMDeviceInfoSupport", "getThermalState", (IMP)SBXK_APMDeviceInfoSupport_getThermalState, "@"},
    {"APMCollector", "collectMetrics:", (IMP)SBXK_APMCollector_collectMetrics, "@"},
    {"APMCollector", "reportNow:", (IMP)SBXK_APMCollector_reportNow, "@"},
    {"TApmSceneMarker", "markLoadLevel:", (IMP)SBXK_TApmSceneMarker_markLoadLevel, "@"},
    {"TApmSceneMarker", "markLevelFin", (IMP)SBXK_TApmSceneMarker_markLevelFin, "@"},
    {"TApmSceneMarker", "postStepEvent:", (IMP)SBXK_TApmSceneMarker_postStepEvent, "@"},
    {"TApmSceneMarker", "postStreamEvent:", (IMP)SBXK_TApmSceneMarker_postStreamEvent, "@"},

    {"serviceCommunication", "getValueForKeypath", (IMP)SBXK_serviceCommunication_getValueForKeypath, "@"},
    {"AudioDeviceMgr", "GetAudioDeviceConnectState", (IMP)SBXK_AudioDeviceMgr_GetAudioDeviceConnectState, "@"},
    {"AudioDeviceMgr", "UpdateDeviceState:", (IMP)SBXK_AudioDeviceMgr_UpdateDeviceState, "@"},
    {"TikTokAuth", "authorizeWithPermissions:", (IMP)SBXK_TikTokAuth_authorizeWithPermissions, "@"},
    {"TikTokAuth", "handleOpenURL:", (IMP)SBXK_TikTokAuth_handleOpenURL, "@"},
    {"VKAuth", "authorizeWithPermissions:", (IMP)SBXK_VKAuth_authorizeWithPermissions, "@"},
    {"VKAuth", "logout", (IMP)SBXK_VKAuth_logout, "@"},
    {"SCSDKLoginClient", "loginWithCompletion:", (IMP)SBXK_SCSDKLoginClient_loginWithCompletion, "@"},
    {"SCSDKLoginClient", "logout", (IMP)SBXK_SCSDKLoginClient_logout, "@"},

    {"ASIdentifierManager", "advertisingIdentifier", (IMP)SBXK_ASIdentifierManager_advertisingIdentifier, "@"},
    {"ATTrackingManager", "trackingAuthorizationStatus", (IMP)SBXK_ATTrackingManager_trackingAuthorizationStatus, "q"},
};

#pragma mark =========================================================
#pragma mark 5. CRASH LOGGER
#pragma mark =========================================================

static void sbxk_signal_handler(int sig, siginfo_t *info, void *ctx) {
    (void)ctx;
    if (g_crash_path[0] == 0) { signal(sig, SIG_DFL); raise(sig); return; }

    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sbxk_wr(fd, "\n=== SBXK CRASH ===\n");
        sbxk_wr(fd, "signal="); sbxk_wrn(fd, sig); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "phase=");  sbxk_wrn(fd, g_phase); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "hook_idx="); sbxk_wrn(fd, g_current_hook); sbxk_wr(fd, "\n");
        if (g_current_hook >= 0) {
            size_t n = sizeof(g_hooks) / sizeof(g_hooks[0]);
            if ((size_t)g_current_hook < n) {
                sbxk_wr(fd, "hook_cls="); sbxk_wr(fd, g_hooks[g_current_hook].cls); sbxk_wr(fd, "\n");
                sbxk_wr(fd, "hook_sel="); sbxk_wr(fd, g_hooks[g_current_hook].sel); sbxk_wr(fd, "\n");
            }
        }
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
        close(fd);
    }

    // إعادة تشغيل الإشارة الافتراضية بعد كتابة السجل
    signal(sig, SIG_DFL);
    raise(sig);
}

static void sbxk_uncaught_exception(NSException *e) {
    if (g_crash_path[0] == 0) return;

    int fd = open(g_crash_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        sbxk_wr(fd, "\n=== SBXK EXCEPTION ===\n");
        sbxk_wr(fd, "phase="); sbxk_wrn(fd, g_phase); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "hook_idx="); sbxk_wrn(fd, g_current_hook); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "name="); sbxk_wr(fd, [[e name] UTF8String]); sbxk_wr(fd, "\n");
        sbxk_wr(fd, "reason="); sbxk_wr(fd, [[e reason] UTF8String]); sbxk_wr(fd, "\n");
        if (backtrace && backtrace_symbols_fd) {
            sbxk_wr(fd, "--- backtrace ---\n");
            void *frames[64];
            int nf = backtrace(frames, 64);
            backtrace_symbols_fd(frames, nf, fd);
        }
        sbxk_wr(fd, "=== END EXCEPTION ===\n");
        close(fd);
    }
}

static void SBXK_InitCrashPaths(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *c = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *p = [docs stringByAppendingPathComponent:@"sbxk_phase.log"];
    strncpy(g_crash_path, c.UTF8String, sizeof(g_crash_path) - 1);
    strncpy(g_phase_path, p.UTF8String, sizeof(g_phase_path) - 1);
}

static void SBXK_InstallCrashHandlers(void) {
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

static void SBXK_MarkPhase(int p, const char *msg) {
    g_phase = p;
    if (g_phase_path[0] == 0) return;
    int fd = open(g_phase_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return;
    sbxk_wr(fd, "phase="); sbxk_wrn(fd, p);
    if (msg) { sbxk_wr(fd, " msg="); sbxk_wr(fd, msg); }
    sbxk_wr(fd, "\n");
    close(fd);
}

static void SBXK_FlushPreviousCrash(void) {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *current = [docs stringByAppendingPathComponent:@"sbxk_crash.log"];
    NSString *prev    = [docs stringByAppendingPathComponent:@"sbxk_crash_prev.log"];

    if (![[NSFileManager defaultManager] fileExistsAtPath:current]) return;
    NSData *data = [NSData dataWithContentsOfFile:current];
    if (data.length > 0) {
        NSString *s = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        if (s) SBXK_LOG(@"PREVIOUS CRASH LOG:\n%@", s);
    }
    [[NSFileManager defaultManager] removeItemAtPath:prev error:nil];
    [[NSFileManager defaultManager] moveItemAtPath:current toPath:prev error:nil];
}

#pragma mark =========================================================
#pragma mark 6. INSTALL DRIVER
#pragma mark =========================================================

static const char *SBXK_ReturnTypeForMethod(Class c, SEL s, BOOL *isClassMethod) {
    Method m = class_getInstanceMethod(c, s);
    if (m) { if (isClassMethod) *isClassMethod = NO; }
    else {
        m = class_getClassMethod(c, s);
        if (m) { if (isClassMethod) *isClassMethod = YES; }
        else return NULL;
    }
    Class holder = *isClassMethod ? object_getClass(c) : c;
    NSMethodSignature *sig = [holder instanceMethodSignatureForSelector:s];
    if (sig) return [sig methodReturnType];
    return method_getTypeEncoding(m);
}

static void SBXK_InstallOneHook(const sbxk_hook_t *h) {
    Class c = objc_getClass(h->cls);
    if (!c) {
        if (g_pendingClasses) [g_pendingClasses addObject:[NSString stringWithUTF8String:h->cls]];
        return;
    }
    SEL s = sel_registerName(h->sel);
    BOOL isClassMethod = NO;
    const char *ret = SBXK_ReturnTypeForMethod(c, s, &isClassMethod);
    if (!ret) return;
    if (strcmp(ret, h->expectedRet) != 0) {
        SBXK_LOG(@"skip %s -%s (ret='%s' want='%s')", h->cls, h->sel, ret, h->expectedRet);
        return;
    }
    Method m = isClassMethod ? class_getClassMethod(c, s) : class_getInstanceMethod(c, s);
    if (!m) return;
    Class target = isClassMethod ? object_getClass(c) : c;
    class_replaceMethod(target, s, h->imp, method_getTypeEncoding(m));
}

static void SBXK_InstallAllSwizzles(void) {
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ SBXK_InstallAllSwizzles(); });
        return;
    }
    size_t n = sizeof(g_hooks) / sizeof(g_hooks[0]);
    size_t missing = 0;
    for (size_t i = 0; i < n; i++) {
        g_current_hook = (int)i;
        if (!objc_getClass(g_hooks[i].cls)) { missing++; continue; }
        SBXK_InstallOneHook(&g_hooks[i]);
    }
    g_current_hook = -1;
    SBXK_LOG(@"install pass: total=%zu missing_classes=%zu", n, missing);
}

#pragma mark =========================================================
#pragma mark 7. NSFileManager SWIZZLE
#pragma mark =========================================================

static NSArray<NSString *> *SBXK_JailbreakPrefixes(void) {
    static NSArray *arr; static dispatch_once_t once;
    dispatch_once(&once, ^{
        arr = @[@"/Applications/Cydia.app",@"/Applications/Sileo.app",@"/Applications/Zebra.app",
                @"/bin/bash",@"/bin/sh",@"/etc/apt",@"/usr/bin/ssh",@"/usr/sbin/sshd",
                @"/private/var/lib/apt",@"/Library/MobileSubstrate",@"/var/log/syslog"];
    });
    return arr;
}

static BOOL SBXK_NSFileManager_fileExistsAtPath_(id self, SEL _cmd, NSString *path) {
    for (NSString *p in SBXK_JailbreakPrefixes())
        if ([path isEqualToString:p] || [path hasPrefix:p]) return NO;
    IMP orig = class_getMethodImplementation([NSFileManager class], @selector(SBXK_orig_fileExistsAtPath:));
    if (orig) { BOOL (*fn)(id, SEL, NSString *) = (void *)orig;
        return fn(self, @selector(SBXK_orig_fileExistsAtPath:), path); }
    return NO;
}
static BOOL SBXK_NSFileManager_fileExistsAtPath_isDirectory_(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    for (NSString *p in SBXK_JailbreakPrefixes())
        if ([path isEqualToString:p] || [path hasPrefix:p]) { if (isDir) *isDir = NO; return NO; }
    IMP orig = class_getMethodImplementation([NSFileManager class], @selector(SBXK_orig_fileExistsAtPath:isDirectory:));
    if (orig) { BOOL (*fn)(id, SEL, NSString *, BOOL *) = (void *)orig;
        return fn(self, @selector(SBXK_orig_fileExistsAtPath:isDirectory:), path, isDir); }
    return NO;
}

static void SBXK_InstallFileManagerSwizzle(void) {
    Class fm = [NSFileManager class];
    Method m1 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:));
    if (m1) {
        class_addMethod(fm, @selector(SBXK_orig_fileExistsAtPath:),
                        method_getImplementation(m1), method_getTypeEncoding(m1));
        method_setImplementation(m1, (IMP)SBXK_NSFileManager_fileExistsAtPath_);
    }
    Method m2 = class_getInstanceMethod(fm, @selector(fileExistsAtPath:isDirectory:));
    if (m2) {
        class_addMethod(fm, @selector(SBXK_orig_fileExistsAtPath:isDirectory:),
                        method_getImplementation(m2), method_getTypeEncoding(m2));
        method_setImplementation(m2, (IMP)SBXK_NSFileManager_fileExistsAtPath_isDirectory_);
    }
}

#pragma mark =========================================================
#pragma mark 8. FILE CLEANUP
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
        if (![fm fileExistsAtPath:p]) continue;
        NSError *e = nil;
        [fm removeItemAtPath:p error:&e];
    }
}

static void SBXK_StartCleanupTimer(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSTimer scheduledTimerWithTimeInterval:30.0 repeats:YES block:^(NSTimer *t) {
            (void)t; SBXK_DeleteSensitiveFiles();
        }];
    });
}

#pragma mark =========================================================
#pragma mark 9. RETRY — dyld callback + periodic timer
#pragma mark =========================================================

static void sbxk_image_added_cb(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    g_retry_pending = true;   // simple flag — no locks, no dispatch
}

static void SBXK_StartRetryTimer(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSTimer scheduledTimerWithTimeInterval:5.0 repeats:YES block:^(NSTimer *t) {
            (void)t;
            if (g_retry_pending) {
                g_retry_pending = false;
                SBXK_InstallAllSwizzles();
            }
        }];
    });
}

#pragma mark =========================================================
#pragma mark 10. ENTRY
#pragma mark =========================================================

static void SBXK_RunInstalls(void) {
    SBXK_MarkPhase(20, "install_start");
    SBXK_InstallAllSwizzles();
    SBXK_MarkPhase(30, "swizzle_done");
    SBXK_InstallFileManagerSwizzle();
    SBXK_MarkPhase(40, "filemanager_done");
    SBXK_StartCleanupTimer();
    SBXK_StartRetryTimer();
    SBXK_MarkPhase(50, "install_done");
}

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        // 1) Paths + crash handlers FIRST — قبل أي شيء آخر
        SBXK_InitCrashPaths();
        SBXK_InstallCrashHandlers();
        SBXK_MarkPhase(1, "boot");

        // 2) طبع أي crash سابق في system log
        SBXK_FlushPreviousCrash();
        SBXK_MarkPhase(2, "flushed");

        SBXK_LOG(@"v6.1.2 boot");
        g_pendingClasses = [NSMutableSet set];

        // 3) dyld retry
        _dyld_register_func_for_add_image(sbxk_image_added_cb);
        SBXK_MarkPhase(3, "dyld_registered");

        // 4) install pass بعد 7s
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { SBXK_RunInstalls(); }
        });
    }
}
