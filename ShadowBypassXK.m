// ============================================================================
// ShadowBypass XK v6.1 — iOS 14+, arm64/arm64e, no jailbreak
//
// Fixes over v6 (from audit):
//   [1] كل Selectors متعددة الوسائط أصبحت تحتوي النقطتين ":" الفعليتين
//       — كان كل hook يُسكَب بسبب _ بدل :
//   [2] Banner: بدل swizzle على didFinishLaunching (الذي استُدعي بالفعل عند
//       t=7s)، نستخدم UIApplicationDidFinishLaunchingNotification المثبَّت
//       في الـ constructor قبل أن يُستدعى.
//   [3] إزالة كل hooks dealloc — لا يمكن استبدال dealloc بـ no-op دون تسرّب.
//   [4] install لـ class methods أيضاً (trackingAuthorizationStatus).
//   [5] استبدال @synchronized داخل dyld callback بـ os_unfair_lock.
//   [6] فحص نوع الإرجاع بـ NSMethodSignature (full return type) بدل الحرف الأول.
//   [7] تشخيص runtime: يُسجَّل سبب كل skip.
//   [8] إزالة أو تصحيح مدخلات كان توقيعها الداخلي متناقضاً.
//
// Build:
//   SDK="$(xcrun --sdk iphoneos --show-sdk-path)"
//   clang -arch arm64 -arch arm64e -isysroot "$SDK" -miphoneos-version-min=14.0 \
//         -fobjc-arc -O2 -dynamiclib \
//         -Wno-nullability-completeness \
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
#import <os/lock.h>
#import <string.h>

#define SBXK_LOG(fmt, ...) NSLog(@"[SBXK] " fmt, ##__VA_ARGS__)

#pragma mark =========================================================
#pragma mark 1. HOOK TABLE TYPES
#pragma mark =========================================================

// expectedRet هي السلسلة الكاملة التي يُرجعها NSMethodSignature.methodReturnType
// مثل: "v", "B", "c", "i", "q", "d", "@", "#". المقارنة تتم على السلسلة كاملة.
typedef struct {
    const char *cls;
    const char *sel;
    IMP         imp;
    const char *expectedRet;
} sbxk_hook_t;

static NSMutableSet<NSString *> *g_pendingClasses = nil;  // main queue only
static os_unfair_lock g_retry_lock = OS_UNFAIR_LOCK_INIT;
static volatile bool  g_retry_pending = false;

#pragma mark =========================================================
#pragma mark 2. IMP DEFINITION MACROS
#pragma mark =========================================================
//
// التسمية: D_<kind>_<args>(Class, c_safe_name, ...)
// الـ c_safe_name هو اسم صالح كـ C identifier (قد يحتوي _)
// Selector الحقيقي بالنقطتين يُعطى لاحقاً في g_hooks[].

#define D_NO(cls, name)  static BOOL SBXK_##cls##_##name(id s, SEL _cmd) { (void)s;(void)_cmd; return NO; }
#define D_YES(cls, name) static BOOL SBXK_##cls##_##name(id s, SEL _cmd) { (void)s;(void)_cmd; return YES; }

#define D_ID(cls, name)             static id SBXK_##cls##_##name(id s, SEL _cmd) { (void)s;(void)_cmd; return @(0); }
#define D_ID_A(cls, name, a)        static id SBXK_##cls##_##name(id s, SEL _cmd, id a) { (void)s;(void)_cmd;(void)a; return @(0); }
#define D_ID_AA(cls, name, a, b)    static id SBXK_##cls##_##name(id s, SEL _cmd, id a, id b) { (void)s;(void)_cmd;(void)a;(void)b; return @(0); }
#define D_ID_AAA(cls, name, a, b, c) static id SBXK_##cls##_##name(id s, SEL _cmd, id a, id b, id c) { (void)s;(void)_cmd;(void)a;(void)b;(void)c; return @(0); }
#define D_ID_AB(cls, name, a, b)    static id SBXK_##cls##_##name(id s, SEL _cmd, id a, BOOL b) { (void)s;(void)_cmd;(void)a;(void)b; return @(0); }

#define D_V(cls, name)              static void SBXK_##cls##_##name(id s, SEL _cmd) { (void)s;(void)_cmd; }
#define D_V_A(cls, name, a)         static void SBXK_##cls##_##name(id s, SEL _cmd, id a) { (void)s;(void)_cmd;(void)a; }
#define D_V_AA(cls, name, a, b)     static void SBXK_##cls##_##name(id s, SEL _cmd, id a, id b) { (void)s;(void)_cmd;(void)a;(void)b; }
#define D_V_AB(cls, name, a, b)     static void SBXK_##cls##_##name(id s, SEL _cmd, id a, BOOL b) { (void)s;(void)_cmd;(void)a;(void)b; }
#define D_V_AI(cls, name, a, b)     static void SBXK_##cls##_##name(id s, SEL _cmd, id a, int b) { (void)s;(void)_cmd;(void)a;(void)b; }
#define D_V_AII(cls, name, a, b, c) static void SBXK_##cls##_##name(id s, SEL _cmd, id a, int b, int c) { (void)s;(void)_cmd;(void)a;(void)b;(void)c; }

#pragma mark =========================================================
#pragma mark 3. IMPLEMENTATIONS
#pragma mark =========================================================

// --- Detection — كلها BOOL / (id, SEL) ---
D_NO(IntegrityChecker, integrity_detect)
D_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
D_NO(JailbreakDetector, isJailbroken)
D_NO(JailbreakDetector, isJailbreak)
D_NO(JailbreakDetector, checkJailbreak)
D_NO(JailbreakDetector, jailbreakDetection)
D_NO(SimulatorDetector, isSimulator)
D_NO(SimulatorDetector, isSimulatorDevice)
D_NO(SimulatorDetector, checkSimulator)
D_NO(SecurityChecker, IsFileSystemModified)
D_NO(SecurityChecker, isDebuggerAttached)
D_NO(SecurityChecker, isDebugged)
D_NO(SecurityChecker, checkDebugger)
D_NO(SecurityChecker, amIBeingDebugged)
D_NO(SecurityChecker, checkDebuggerAttach)
D_NO(SecurityChecker, isHooked)
D_NO(SecurityChecker, isHookDetected)
D_NO(SecurityChecker, checkHook)
D_NO(SecurityChecker, detectHook)
D_NO(SecurityChecker, antiHookCheck)
D_NO(SecurityChecker, isTampered)
D_NO(SecurityChecker, checkTamper)
D_NO(SecurityChecker, antiTamperCheck)
D_NO(SecurityChecker, isInjected)
D_NO(SecurityChecker, isLibraryInjected)
D_NO(SecurityChecker, checkInjection)
D_NO(SecurityChecker, antiInjectionCheck)
D_NO(SecurityChecker, isReversingDetected)
D_NO(SecurityChecker, checkReversing)
D_NO(SecurityChecker, antiReversingCheck)
D_NO(SecurityChecker, isBlocked)
D_NO(SecurityChecker, antiBlockingCheck)
D_YES(SecurityChecker, verifyIntegrity)
D_YES(SecurityChecker, checkTokenValid)
D_YES(AReachability, isConnectionOnDemand)
D_YES(AReachability, isConnectionRequired)
D_YES(GVGCloudVoiceExtension, CheckDeviceMuteStat)

// --- GAD callbacks — كلها void (id, SEL, id) ---
D_V_A(GADAppOpenAd, adDidDismissFullScreenContent)
D_V_A(GADAppOpenAd, adWillDismissFullScreenContent)
D_V_A(GADAppOpenAd, adDidRecordClick)
D_V_A(GADAppOpenAd, adDidRecordImpression)
D_V_A(GADAppOpenAd, adWillPresentFullScreenContent)
D_V_A(GADAppOpenAd, adDidFailToPresentFullScreenContentWithError)
D_V_A(GADAppOpenAd, setPaidEventHandler)
D_ID(GADAppOpenAd, responseInfo)
D_ID(GADMobileAds, initializationStatus)
D_ID(GADAdNetworkResponseInfo, adUnitMapping)

// --- Game logic ---
static id SBXK_WeaponProcessor_CalculateDamage(id s, SEL _cmd, id target, float dist) {
    (void)s; (void)_cmd; (void)target; (void)dist; return @(0);
}
D_NO(CharacterMovement, IsSpeedExceeded)
static id SBXK_BulletSimulator_CheckWallCollision(id s, SEL _cmd) { (void)s;(void)_cmd; return nil; }
static void SBXK_NetworkManager_SendSecurityReport(id s, SEL _cmd, id r) {
    (void)s; (void)_cmd; (void)r; SBXK_LOG(@"suppressed SecurityReport");
}

// --- GSDK ---
D_ID(GSDKCPU, getSystemCPUCircle)
D_ID(GSDKMemory, getSystemAvailableMemory)
D_ID(GSDKInGameManager, GSDKRealTimeDetect)
D_ID(GSDKInGameSystem, GSDKInnerEnd)
D_ID(GSDKInGameSystem, GSDKInnerRealTimeDetect)
D_ID(GSDKPing, ping)
D_ID(GSDKPing, stopPing)
D_ID(GSDKPingDetect, ping)
D_ID(GSDKHttpRequest, requestControl_Openid_Acctype_Zoneid_Env)
D_ID(GSDKInGameSystem, GSDKInnerSaveFPS_FpsDots)
D_ID(GSDKInGameSystem, GSDKInnerStart_SceneID_RoomIP)
D_ID(GSDKPing, simplePing_didFailToSendPacket_sequenceNumber_error)
D_ID(GSDKPing, simplePing_didFailWithError)
D_ID(GSDKPing, simplePing_didReceivePingResponsePacket_sequenceNumber)
D_ID(GSDKPing, simplePing_didReceiveUnexpectedPacket)
D_ID(GSDKPing, simplePing_didSendPacket_sequenceNumber)
D_ID(GSDKPing, simplePing_didStartWithAddress)
D_ID(GSDKPingDetect, simplePing_didFailToSendPacket_sequenceNumber_error)
D_ID(GSDKPingDetect, simplePing_didFailWithError)
D_ID(GSDKPingDetect, simplePing_didReceivePingResponsePacket_sequenceNumber)
D_ID(GSDKPingDetect, simplePing_didReceiveUnexpectedPacket)
D_ID(GSDKPingDetect, simplePing_didSendPacket_sequenceNumber)
D_ID(GSDKPingDetect, simplePing_didStartWithAddress)
D_ID(GSDKRealTimeDetect, pingDelayDetect)
D_ID(GSDKRealTimeDetect, updDelayDetect_Port)
D_ID(GSDKUdpDetect, isUDPConnect_Port)
D_ID(GSDKWIFI, ping)
D_ID(GSDKDetectPort, isConnection_Port)
D_ID(GSDKInitManager, detectOperation)
D_ID(GSDKPayEvent, GSDKPay_Tag_Status_Msg)
D_ID(PingDelegate, pingTimer)
D_ID(PingDelegate, simplePing_didFailToSendPacket_sequenceNumber_error)
D_ID(PingDelegate, simplePing_didSendPacket_sequenceNumber)
D_ID(SimplePing, start)
D_ID(SimplePing, startWithHostAddress)
D_ID(SimplePing, readData)
D_ID(SimplePing, didFailWithError)
D_ID(SimplePing, sendPingWithData)
D_ID(SimplePing, validatePingResponsePacket_sequenceNumber)
D_ID(SimplePing, pingPacketWithType_payload_requiresChecksum)

// --- Voice ---
D_ID(GVGCloudVoice, openMic)
D_ID(GVGCloudVoice, openSpeaker)
D_V_AAA(GVGCloudVoice, setAppInfo_withKey_andOpenID, a, b, c)  // macro مخصص أدناه
D_ID(GVGCloudVoiceExtension, GetBGMPlayState)
D_ID(GVGCloudVoiceExtension, GetMicState)
D_ID(GVGCloudVoiceExtension, GetSpeakerState)
D_ID(GVGCloudVoiceExtension, EnableKeyWordsDetect)
D_ID(GVoiceMuteSwitch, detectMuteSwitch)
D_ID(GCloudVoiceEngine, StartTve)
D_ID(GCloudVoiceEngine, StopRecording)
D_ID(GCloudVoiceEngine, TestMic)
D_ID(GCloudVoiceEngine, StartBGMPlay)
D_ID(GCloudVoiceEngine, StopBGMPlay)
D_ID(GCloudVoiceEngine, PauseBGMPlay)
D_ID(GCloudVoiceEngine, ResumeBGMPlay)
D_ID(GCloudVoiceEngine, RSTSStopRecording)
D_ID(GCloudVoiceEngine, TextToStreamSpeechStop)
D_ID(GCloudVoiceEngine, StartPreview)
D_ID(GCloudVoiceEngine, StopPreview)
D_ID(GCloudVoiceEngine, PauseKaraoke)
D_ID(GCloudVoiceEngine, ResumeKaraoke)
D_ID(GCloudVoiceEngine, GetMicLevel)
D_ID(GCloudVoiceEngine, GetSpeakerLevel)
D_ID(GCloudVoiceEngine, GetBGMLevel)
D_ID(GCloudVoiceEngine, GetBGMFileTime)
D_ID(GCloudVoiceEngine, GetBGMPlayTime)
D_ID(GCloudVoiceEngine, GetRecordKaraokeTotalTime)
D_ID(GCloudVoiceEngine, StopKaraokeRecording)
D_ID(GCloudVoiceEngine, GetFileParam_data_time)
D_ID(GCloudCoreRemoteConfig, updateConfig)
D_ID(GCloudCoreRemoteConfig, getConfig)
D_ID(GCloudUnityPlugin, Initialize)
D_ID(GCloudUnityPlugin, ReportEvent)
D_ID(GCloudUnityPlugin, SetGameObjectName)
D_V_AII(GCloudVoiceEngine, JoinTeamRoom_Scenes_roomName_timeout, a, b, c)
D_V_AI(GCloudVoiceEngine, QuitRoom_Scenes_timeout, a, b)
D_V_AB(GCloudVoiceEngine, EnableMultiRoom, a, b)
D_V_AB(GCloudVoiceEngine, EnableRoomMicrophone_enable, a, b)
D_V_AB(GCloudVoiceEngine, EnableRoomSpeaker_enable, a, b)
D_V_AII(GCloudVoiceEngine, ApplyMessageKey_timestamp_timeout, a, b, c)
D_V_A(GCloudVoiceEngine, StartRecording, a)
D_V_A(GCloudVoiceEngine, SetBGMPath, a)
D_V_A(GCloudVoiceEngine, SetLogCallBack, a)
D_V_AI(GCloudVoiceEngine, SetMicVolume, a, b)
D_V_AI(GCloudVoiceEngine, SetSpeakerVolume, a, b)
D_V_AI(GCloudVoiceEngine, SetBitRate, a, b)
D_V_AI(GCloudVoiceEngine, SetDataFree, a, b)
D_V_AI(GCloudVoiceEngine, SetReportBufferTime, a, b)
D_V_AI(GCloudVoiceEngine, SetBGMPlayTime, a, b)
D_V_AI(GCloudVoiceEngine, SetKaraokeVoiceVol, a, b)
D_V_AI(GCloudVoiceEngine, SetKaraokeAccVol, a, b)
D_V_AI(GCloudVoiceEngine, SetKaraokeVoiceDelay, a, b)
D_V_AI(GCloudVoiceEngine, SeekTimeMsForPreview, a, b)
D_V_AI(GCloudVoiceEngine, SeekTimeMsForAcc, a, b)
D_V_AB(GCloudVoiceEngine, EnableLog, a, b)
D_V_AB(GCloudVoiceEngine, EnableNativeBGMPlay, a, b)
D_V_AB(GCloudVoiceEngine, EnableRecvMagicVoice, a, b)
D_V_AB(GCloudVoiceEngine, EnableReportALL, a, b)
D_V_AB(GCloudVoiceEngine, EnableReportALLAbroad, a, b)
D_V_AB(GCloudVoiceEngine, EnableReportForAbroad, a, b)
D_V_AB(GCloudVoiceEngine, EnableCivilFile, a, b)
D_V_AB(GCloudVoiceEngine, EnableCivilVoice, a, b)
D_V_AB(GCloudVoiceEngine, EnableEarBack, a, b)
D_V_AB(GCloudVoiceEngine, EnableAccFilePlay, a, b)

// --- Firebase / Ads SDK ---
D_ID(FIRMessagingRmqManager, openDatabase)
D_ID(FIRMessaging, retrieveFCMTokenForSenderID_completion)
D_ID(FIRMessaging, deleteFCMTokenForSenderID_completion)
D_ID(FIRMessaging, subscribeToTopic_completion)
D_ID(FIRMessaging, unsubscribeFromTopic_completion)
D_ID(FIRMessaging, setAPNSToken_withUserInfo)
D_ID(FIRMessaging, APNSToken)
D_ID(FBAdViewabilityValidator, checkViewability)
D_ID(FBAdMonitor, startMonitoringAd)
D_ID(FBAdViewabilityValidator, stopMonitoring)
D_ID(FBAdMonitor, stopMonitoring)
D_ID(FBAdEvent, logEvent_withParameters)
D_ID(FBAdLogger, logMessage_withLevel)

// --- QQ SDK ---
D_ID(QQApiInterface, sendReq_resultBlock)
D_ID(QQApiInterface, sendThirdAppBindGroupReq_resultBlock)
D_ID(QQApiInterface, sendThirdAppUnBindGroupReq_resultBlock)
D_ID(QQApiInterface, sendThirdAppJoinGroupReq_resultBlock)
D_ID(QQApiInterface, sendQueryQQGroupProInfo_resultBlock)
D_ID(QQApiInterface, sendMessageToQQAuthWithReq)
D_ID(QQApiInterface, sendMessageToQQAvatarWithReq)
D_ID(QQApiInterface, sendMessageToFaceCollectionWithReq)
D_ID(QQOpenApiUtility, cgiRequestGetSdkConfig)
D_ID(TDataMasterApplication, handleOpenURL)
D_ID(TDataMasterApplication, reportEventWithSrcID_eventName_AndEventKVArray)
D_ID(TcApiTool, openUniversallinkIfNeed)
D_ID(GTMSessionFetcher, setSystemCompletionHandler_forSessionIdentifier)

// --- IMSDK ---
D_ID(IMSDKNoticeIMSDKManager, getImageCache_imagePath_imageHash_queue_completeHandle)
D_ID(IMSDKNoticeIMSDKManager, imsdkCoreKitNoticeImageFileHash)
D_ID(IMSDKStatAdjustManager, reportEvent_eventBody_isRealtime)
D_ID(IMSDKStatAdjustManager, reportEvent_params_isRealtime)
D_ID(IMSDKStatAdjustManager, reportPurchase_currentCode_expense_isRealTime)
D_ID(IMSDKStatAdjustManager, reportRevenue_currencyCode_revenueValue_params_extraJson)
D_ID(INTLWebViewManager, openURL_observerID_baseParams)

// --- APM ---
D_ID(APMMonitor, handleEvent)
D_ID(APMMonitor, startMonitoring)
D_ID(APMDeviceInfoSupport, getBatteryState)
D_ID(APMDeviceInfoSupport, getThermalState)
D_ID(APMCollector, collectMetrics)
D_ID(APMCollector, reportNow)
D_ID(TApmSceneMarker, markLoadLevel)
D_ID(TApmSceneMarker, markLevelFin)
D_ID(TApmSceneMarker, postStepEvent)
D_ID(TApmSceneMarker, postStreamEvent)

// --- Misc ---
D_ID(serviceCommunication, getValueForKeypath)
D_ID(AudioDeviceMgr, GetAudioDeviceConnectState)
D_ID(AudioDeviceMgr, UpdateDeviceState)
D_ID(TikTokAuth, authorizeWithPermissions)
D_ID(TikTokAuth, handleOpenURL)
D_ID(VKAuth, authorizeWithPermissions)
D_ID(VKAuth, logout)
D_ID(SCSDKLoginClient, loginWithCompletion)
D_ID(SCSDKLoginClient, logout)

// --- Advertising ---
static NSString *SBXK_ASIdentifierManager_advertisingIdentifier(id s, SEL _cmd) {
    (void)s; (void)_cmd; return @"00000000-0000-0000-0000-000000000000";
}
static NSInteger SBXK_ATTrackingManager_trackingAuthorizationStatus(id s, SEL _cmd) {
    (void)s; (void)_cmd; return 3;  // ATTrackingManagerAuthorizationStatusAuthorized
}

#pragma mark =========================================================
#pragma mark 4. HOOK TABLE — selectors بالنقطتين الحقيقية
#pragma mark =========================================================

static const sbxk_hook_t g_hooks[] = {
    // ------- Detection -------
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

    // ------- GAD -------
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

    // ------- Game -------
    {"WeaponProcessor", "CalculateDamage:distance:", (IMP)SBXK_WeaponProcessor_CalculateDamage, "@"},
    {"CharacterMovement", "IsSpeedExceeded", (IMP)SBXK_CharacterMovement_IsSpeedExceeded, "B"},
    {"BulletSimulator", "CheckWallCollision", (IMP)SBXK_BulletSimulator_CheckWallCollision, "@"},
    {"NetworkManager", "SendSecurityReport:", (IMP)SBXK_NetworkManager_SendSecurityReport, "v"},

    // ------- GSDK -------
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

    // ------- Voice -------
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

    // ------- Firebase / Ads SDK -------
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

    // ------- QQ -------
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

    // ------- IMSDK -------
    {"IMSDKNoticeIMSDKManager", "getImageCache:imagePath:imageHash:queue:completeHandle:", (IMP)SBXK_IMSDKNoticeIMSDKManager_getImageCache_imagePath_imageHash_queue_completeHandle, "@"},
    {"IMSDKNoticeIMSDKManager", "imsdkCoreKitNoticeImageFileHash:", (IMP)SBXK_IMSDKNoticeIMSDKManager_imsdkCoreKitNoticeImageFileHash, "@"},
    {"IMSDKStatAdjustManager", "reportEvent:eventBody:isRealtime:", (IMP)SBXK_IMSDKStatAdjustManager_reportEvent_eventBody_isRealtime, "@"},
    {"IMSDKStatAdjustManager", "reportEvent:params:isRealtime:", (IMP)SBXK_IMSDKStatAdjustManager_reportEvent_params_isRealtime, "@"},
    {"IMSDKStatAdjustManager", "reportPurchase:currentCode:expense:isRealTime:", (IMP)SBXK_IMSDKStatAdjustManager_reportPurchase_currentCode_expense_isRealTime, "@"},
    {"IMSDKStatAdjustManager", "reportRevenue:currencyCode:revenueValue:params:extraJson:", (IMP)SBXK_IMSDKStatAdjustManager_reportRevenue_currencyCode_revenueValue_params_extraJson, "@"},
    {"INTLWebViewManager", "openURL:observerID:baseParams:", (IMP)SBXK_INTLWebViewManager_openURL_observerID_baseParams, "@"},

    // ------- APM -------
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

    // ------- Misc -------
    {"serviceCommunication", "getValueForKeypath", (IMP)SBXK_serviceCommunication_getValueForKeypath, "@"},
    {"AudioDeviceMgr", "GetAudioDeviceConnectState", (IMP)SBXK_AudioDeviceMgr_GetAudioDeviceConnectState, "@"},
    {"AudioDeviceMgr", "UpdateDeviceState:", (IMP)SBXK_AudioDeviceMgr_UpdateDeviceState, "@"},
    {"TikTokAuth", "authorizeWithPermissions:", (IMP)SBXK_TikTokAuth_authorizeWithPermissions, "@"},
    {"TikTokAuth", "handleOpenURL:", (IMP)SBXK_TikTokAuth_handleOpenURL, "@"},
    {"VKAuth", "authorizeWithPermissions:", (IMP)SBXK_VKAuth_authorizeWithPermissions, "@"},
    {"VKAuth", "logout", (IMP)SBXK_VKAuth_logout, "@"},
    {"SCSDKLoginClient", "loginWithCompletion:", (IMP)SBXK_SCSDKLoginClient_loginWithCompletion, "@"},
    {"SCSDKLoginClient", "logout", (IMP)SBXK_SCSDKLoginClient_logout, "@"},

    // ------- Advertising -------
    {"ASIdentifierManager", "advertisingIdentifier", (IMP)SBXK_ASIdentifierManager_advertisingIdentifier, "@"},
    {"ATTrackingManager", "trackingAuthorizationStatus", (IMP)SBXK_ATTrackingManager_trackingAuthorizationStatus, "q"},
};

#pragma mark =========================================================
#pragma mark 5. INSTALL DRIVER — type-checked, class + instance methods
#pragma mark =========================================================

static const char *SBXK_FullReturnType(Class c, SEL s, BOOL *isClassMethod) {
    Method m = class_getInstanceMethod(c, s);
    if (m) { if (isClassMethod) *isClassMethod = NO; }
    else {
        m = class_getClassMethod(c, s);
        if (m) { if (isClassMethod) *isClassMethod = YES; }
        else return NULL;
    }
    // Use NSMethodSignature to get full return type
    NSMethodSignature *sig = nil;
    if (!*isClassMethod) sig = [c instanceMethodSignatureForSelector:s];
    else {
        Class meta = object_getClass(c);
        sig = [meta instanceMethodSignatureForSelector:s];
    }
    if (!sig) {
        // Fallback: first char
        return method_getTypeEncoding(m);
    }
    return [sig methodReturnType];
}

static void SBXK_InstallOneHook(const sbxk_hook_t *h) {
    Class c = objc_getClass(h->cls);
    if (!c) {
        if (g_pendingClasses) {
            // main-queue-only access
            [g_pendingClasses addObject:[NSString stringWithUTF8String:h->cls]];
        }
        return;
    }
    SEL s = sel_registerName(h->sel);

    BOOL isClassMethod = NO;
    const char *ret = SBXK_FullReturnType(c, s, &isClassMethod);
    if (!ret) {
        SBXK_LOG(@"skip -[%s %s] (method not found)", h->cls, h->sel);
        return;
    }

    if (strcmp(ret, h->expectedRet) != 0) {
        SBXK_LOG(@"skip -[%s %s] (ret='%s', want='%s')",
                 h->cls, h->sel, ret, h->expectedRet);
        return;
    }

    Method m = isClassMethod ? class_getClassMethod(c, s) : class_getInstanceMethod(c, s);
    if (!m) { SBXK_LOG(@"skip -[%s %s] (race)", h->cls, h->sel); return; }

    Class target = isClassMethod ? object_getClass(c) : c;
    if (!class_replaceMethod(target, s, h->imp, method_getTypeEncoding(m))) {
        SBXK_LOG(@"skip -[%s %s] (replace failed)", h->cls, h->sel);
    }
}

static void SBXK_InstallAllSwizzles(void) {
    // يجب أن يُستدعى على main queue
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{ SBXK_InstallAllSwizzles(); });
        return;
    }
    size_t n = sizeof(g_hooks) / sizeof(g_hooks[0]);
    size_t ok = 0, skipped = 0;
    for (size_t i = 0; i < n; i++) {
        Class c = objc_getClass(g_hooks[i].cls);
        if (!c) { skipped++; continue; }
        SBXK_InstallOneHook(&g_hooks[i]);
        ok++;
    }
    SBXK_LOG(@"install pass: %zu installed attempts, %zu classes missing, total=%zu",
             ok, skipped, n);
}

#pragma mark =========================================================
#pragma mark 6. NSFileManager SWIZZLE
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
    IMP orig = class_getMethodImplementation([NSFileManager class],
                                              @selector(SBXK_orig_fileExistsAtPath:));
    if (orig) { BOOL (*fn)(id, SEL, NSString *) = (void *)orig;
        return fn(self, @selector(SBXK_orig_fileExistsAtPath:), path); }
    return NO;
}
static BOOL SBXK_NSFileManager_fileExistsAtPath_isDirectory_(id self, SEL _cmd, NSString *path, BOOL *isDir) {
    for (NSString *p in SBXK_JailbreakPrefixes())
        if ([path isEqualToString:p] || [path hasPrefix:p]) { if (isDir) *isDir = NO; return NO; }
    IMP orig = class_getMethodImplementation([NSFileManager class],
                                              @selector(SBXK_orig_fileExistsAtPath:isDirectory:));
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
#pragma mark 7. BANNER — عبر Notification (لا swizzle على didFinishLaunching)
#pragma mark =========================================================

@interface SBXK_Banner : NSObject
@end

@implementation SBXK_Banner

+ (void)installObserver {
    // يُستدعى من constructor قبل main() — قبل أن يُطلق didFinishLaunching
    [[NSNotificationCenter defaultCenter]
        addObserver:self
           selector:@selector(onFinishLaunching:)
               name:UIApplicationDidFinishLaunchingNotification
             object:nil];
}

+ (void)onFinishLaunching:(NSNotification *)note {
    (void)note;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self show]; });
}

+ (void)show {
    UIWindow *w = nil;
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in [UIApplication sharedApplication].connectedScenes) {
            if (s.activationState == UISceneActivationStateForegroundActive &&
                [s isKindOfClass:[UIWindowScene class]]) {
                for (UIWindow *win in ((UIWindowScene *)s).windows)
                    if (win.isKeyWindow) { w = win; break; }
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
    if (w.rootViewController.presentedViewController) return;   // لا تعطّل present آخر

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
#pragma mark 8. FILE CLEANUP (مع فحص الوجود)
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
#pragma mark 9. DYLD CALLBACK — os_unfair_lock
#pragma mark =========================================================

static void sbxk_image_added_cb(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    os_unfair_lock_lock(&g_retry_lock);
    g_retry_pending = true;
    os_unfair_lock_unlock(&g_retry_lock);
    dispatch_async(dispatch_get_main_queue(), ^{
        os_unfair_lock_lock(&g_retry_lock);
        bool run = g_retry_pending;
        g_retry_pending = false;
        os_unfair_lock_unlock(&g_retry_lock);
        if (run) SBXK_InstallAllSwizzles();
    });
}

#pragma mark =========================================================
#pragma mark 10. ENTRY
#pragma mark =========================================================

static void SBXK_RunInstalls(void) {
    SBXK_LOG(@"v6.1 install pass — start");
    SBXK_InstallAllSwizzles();
    SBXK_InstallFileManagerSwizzle();
    SBXK_StartCleanupTimer();
    SBXK_LOG(@"v6.1 install pass — done");
}

__attribute__((constructor))
static void SBXK_Bootstrap(void) {
    @autoreleasepool {
        SBXK_LOG(@"v6.1 boot");

        g_pendingClasses = [NSMutableSet set];

        // Observer للـ Banner يُثبّت الآن — قبل didFinishLaunching
        [SBXK_Banner installObserver];

        // Retry queue عبر dyld
        _dyld_register_func_for_add_image(sbxk_image_added_cb);

        // Hooks تُثبَّت بعد استقرار التطبيق
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool { SBXK_RunInstalls(); }
        });
    }
}
