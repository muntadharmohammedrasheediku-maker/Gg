// ==========================================================================
// MyHook.mm — Tweak كامل بدون OpenSSL وبدون private APIs
// Build: Theos + clang (C++20)
// Target: iOS 15+ / arm64 + arm64e
// ==========================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonRandom.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dispatch/dispatch.h>
#import <sys/types.h>
#import <sys/sysctl.h>
#import <mach-o/dyld.h>

#include <cstring>
#include <cstdint>
#include <cstddef>
#include <chrono>
#include <mutex>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <random>

// ==========================================================================
// SECTION 1 — AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
// Format: IV(16) || ciphertext || HMAC-SHA256(32)
// ==========================================================================

static const size_t kAESKeyLen  = 32;   // AES-256
static const size_t kAESIVLen   = 16;   // CBC block size
static const size_t kAESMacLen  = 32;   // HMAC-SHA256 output

// Constant-time comparison — يمنع timing attacks
static bool AEGIS_ConstantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (uint8_t)(a[i] ^ b[i]);
    }
    return diff == 0;
}

static NSData *AEGIS_HMAC_SHA256(NSData *key, NSData *data) {
    uint8_t out[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256,
           key.bytes, key.length,
           data.bytes, data.length,
           out);
    return [NSData dataWithBytes:out length:CC_SHA256_DIGEST_LENGTH];
}

@interface AESGCM : NSObject
@property (nonatomic, copy, readonly) NSData *key;

+ (instancetype)randomKey;
- (instancetype)initWithKey:(NSData *)key;

// Layout: IV(16) || ciphertext || HMAC(32)
- (nullable NSData *)seal:(NSData *)plaintext error:(NSError **)error;
- (nullable NSData *)open:(NSData *)sealed    error:(NSError **)error;
@end

@implementation AESGCM

+ (instancetype)randomKey {
    uint8_t bytes[kAESKeyLen];
    if (CCRandomGenerateBytes(bytes, kAESKeyLen) != kCCSuccess) {
        return nil;
    }
    return [[AESGCM alloc] initWithKey:[NSData dataWithBytes:bytes
                                                      length:kAESKeyLen]];
}

- (instancetype)initWithKey:(NSData *)key {
    if (key.length != kAESKeyLen) {
        [NSException raise:@"AESGCM"
                    format:@"bad key length: %lu (expected 32)",
                           (unsigned long)key.length];
    }
    if ((self = [super init])) {
        _key = [key copy];
    }
    return self;
}

// Derive subkeys via HMAC(master, label)
- (NSData *)deriveEncKey {
    static NSData *label = nil;
    if (!label) label = [@"aegis.enc.v1" dataUsingEncoding:NSUTF8StringEncoding];
    return AEGIS_HMAC_SHA256(_key, label);
}

- (NSData *)deriveMacKey {
    static NSData *label = nil;
    if (!label) label = [@"aegis.mac.v1" dataUsingEncoding:NSUTF8StringEncoding];
    return AEGIS_HMAC_SHA256(_key, label);
}

- (NSData *)seal:(NSData *)plaintext error:(NSError **)error {
    // 1) Random IV
    uint8_t iv[kAESIVLen];
    if (CCRandomGenerateBytes(iv, kAESIVLen) != kCCSuccess) {
        if (error) *error = [NSError errorWithDomain:@"AEGIS" code:-10 userInfo:nil];
        return nil;
    }

    // 2) Derive subkeys
    NSData *encKey = [self deriveEncKey];
    NSData *macKey = [self deriveMacKey];

    // 3) Encrypt with AES-256-CBC + PKCS7 padding
    const size_t bufSize = plaintext.length + kCCBlockSizeAES128;
    NSMutableData *ct = [NSMutableData dataWithLength:bufSize];
    size_t written = 0;

    CCCryptorStatus st = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        encKey.bytes, encKey.length,
        iv,
        plaintext.bytes, plaintext.length,
        ct.mutableBytes, bufSize,
        &written);
    if (st != kCCSuccess) {
        if (error) *error = [NSError errorWithDomain:@"AEGIS" code:st userInfo:nil];
        return nil;
    }
    ct.length = written;

    // 4) HMAC over IV || ciphertext
    NSMutableData *macInput = [NSMutableData dataWithCapacity:kAESIVLen + ct.length];
    [macInput appendBytes:iv length:kAESIVLen];
    [macInput appendData:ct];
    NSData *tag = AEGIS_HMAC_SHA256(macKey, macInput);

    // 5) Output: IV || ciphertext || tag
    NSMutableData *out = [NSMutableData dataWithCapacity:
                          kAESIVLen + ct.length + kAESMacLen];
    [out appendBytes:iv length:kAESIVLen];
    [out appendData:ct];
    [out appendData:tag];
    return out;
}

- (NSData *)open:(NSData *)sealed error:(NSError **)error {
    if (sealed.length < kAESIVLen + kAESMacLen) {
        if (error) *error = [NSError errorWithDomain:@"AEGIS"
                                                code:-11
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                       @"short input"}];
        return nil;
    }

    const uint8_t *base = (const uint8_t *)sealed.bytes;
    const uint8_t *iv   = base;
    const size_t   ctLen = sealed.length - kAESIVLen - kAESMacLen;
    const uint8_t *ct   = base + kAESIVLen;
    const uint8_t *tag  = ct + ctLen;

    // 1) Derive subkeys
    NSData *encKey = [self deriveEncKey];
    NSData *macKey = [self deriveMacKey];

    // 2) Verify HMAC BEFORE decryption
    NSMutableData *macInput = [NSMutableData dataWithCapacity:kAESIVLen + ctLen];
    [macInput appendBytes:iv length:kAESIVLen];
    [macInput appendBytes:ct length:ctLen];
    NSData *expected = AEGIS_HMAC_SHA256(macKey, macInput);

    if (expected.length != kAESMacLen ||
        !AEGIS_ConstantTimeEqual((const uint8_t *)expected.bytes, tag, kAESMacLen)) {
        if (error) *error = [NSError errorWithDomain:@"AEGIS"
                                                code:-12
                                            userInfo:@{NSLocalizedDescriptionKey:
                                                       @"auth failed"}];
        return nil;
    }

    // 3) Decrypt
    const size_t bufSize = ctLen + kCCBlockSizeAES128;
    NSMutableData *pt = [NSMutableData dataWithLength:bufSize];
    size_t written = 0;

    CCCryptorStatus st = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        encKey.bytes, encKey.length,
        iv,
        ct, ctLen,
        pt.mutableBytes, bufSize,
        &written);
    if (st != kCCSuccess) {
        if (error) *error = [NSError errorWithDomain:@"AEGIS" code:st userInfo:nil];
        return nil;
    }
    pt.length = written;
    return pt;
}

@end

// ==========================================================================
// SECTION 2 — SHA-256 / HMAC helpers
// ==========================================================================

static NSData *AEGIS_SHA256(NSData *data) {
    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    return [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
}

// ==========================================================================
// SECTION 3 — Types (C++20)
// ==========================================================================

struct AEGISFrame {
    double  t{0};
    float   aim_x{0};
    float   aim_y{0};
    float   aim_speed{0};
    float   aim_jerk{0};
    float   fire_interval{0};
    float   move_speed{0};
    float   reaction_time{0};
    float   fov_visible{0};
    float   kill_distance{0};
};

static constexpr size_t kSeqLen  = 30;
static constexpr size_t kFeature = 10;

// ==========================================================================
// SECTION 4 — Session
// ==========================================================================

@interface AEGISSession : NSObject
@property (nonatomic, copy, readonly) NSString *sid;
@property (nonatomic, assign, readonly) NSUInteger count;

- (instancetype)initWithID:(NSString *)sid;
- (void)ingest:(const AEGISFrame&)f;
- (std::vector<AEGISFrame>)snapshot:(size_t)n;
@end

@implementation AEGISSession {
    std::mutex _m;
    std::vector<AEGISFrame> _frames;
    NSUInteger _total;
}

- (instancetype)initWithID:(NSString *)sid {
    if ((self = [super init])) {
        _sid = [sid copy];
        _total = 0;
    }
    return self;
}

- (void)ingest:(const AEGISFrame&)f {
    std::lock_guard<std::mutex> lk(_m);
    if (_frames.size() >= 512) {
        _frames.erase(_frames.begin());
    }
    _frames.push_back(f);
    _total++;
}

- (std::vector<AEGISFrame>)snapshot:(size_t)n {
    std::lock_guard<std::mutex> lk(_m);
    const size_t take = std::min(n, _frames.size());
    return std::vector<AEGISFrame>(_frames.end() - (ptrdiff_t)take,
                                   _frames.end());
}

- (NSUInteger)count {
    std::lock_guard<std::mutex> lk(_m);
    return _total;
}

@end

// ==========================================================================
// SECTION 5 — Statistics
// ==========================================================================

namespace aegis {

static double median(std::vector<double> v) {
    if (v.empty()) return 0.0;
    size_t mid = v.size() / 2;
    std::nth_element(v.begin(), v.begin() + (ptrdiff_t)mid, v.end());
    double hi = v[mid];
    if (v.size() % 2) return hi;
    std::nth_element(v.begin(), v.begin() + (ptrdiff_t)(mid - 1),
                     v.begin() + (ptrdiff_t)mid);
    return (v[mid - 1] + hi) * 0.5;
}

static double robust_sigma(const std::vector<double>& xs) {
    if (xs.size() < 3) return 0.0;
    double med = median(xs);
    std::vector<double> dev(xs.size());
    for (size_t i = 0; i < xs.size(); ++i) dev[i] = std::fabs(xs[i] - med);
    return 1.4826 * median(dev);
}

static double mad_zscore(const std::vector<double>& xs) {
    if (xs.size() < 3) return 0.0;
    double med = median(xs);
    double sig = robust_sigma(xs);
    if (sig < 1e-9) return 0.0;
    return (xs.back() - med) / sig;
}

static double isolation_score(const std::vector<double>& xs, unsigned seed = 42) {
    if (xs.size() < 4) return 0.0;
    const size_t subsample = std::min<size_t>(xs.size(), 32);
    const size_t trees     = 50;
    const double max_depth = std::log2((double)subsample);

    std::mt19937 rng(seed);
    double total_depth = 0.0;

    for (size_t t = 0; t < trees; ++t) {
        std::vector<double> s(subsample);
        std::uniform_int_distribution<size_t> idx(0, xs.size() - 1);
        for (auto& v : s) v = xs[idx(rng)];

        double lo = *std::min_element(s.begin(), s.end());
        double hi = *std::max_element(s.begin(), s.end());
        if (hi - lo < 1e-12) { total_depth += 1.0; continue; }

        const double pivot  = lo + (hi - lo) *
                              std::uniform_real_distribution<double>(0, 1)(rng);
        const double target = xs.back();
        double depth = 0.0;
        while (depth < max_depth) {
            if (target < pivot) hi = pivot; else lo = pivot;
            if (hi - lo < 1e-12) break;
            depth += 1.0;
        }
        total_depth += depth;
    }
    const double avg_depth = total_depth / (double)trees;
    const double c = 2.0 * (std::log(subsample - 1.0) + 0.5772156649)
                   - (2.0 * (subsample - 1.0) / subsample);
    double score = std::pow(2.0, -avg_depth / std::max(1e-9, c));
    return 2.0 * score - 1.0;
}

} // namespace aegis

// ==========================================================================
// SECTION 6 — Analyzer
// ==========================================================================

struct AEGISVerdict {
    float       human{0.5f};
    float       anomaly{0.0f};
    float       iso{0.0f};
    bool        integrity{true};
    size_t      frames{0};
    NSUInteger  total{0};
    std::vector<std::string> reasons;

    bool suspicious() const {
        return human < 0.30f || anomaly < -0.5f || iso < -0.4f || !integrity;
    }
};

@interface AEGISAnalyzer : NSObject
- (AEGISVerdict)evaluate:(const std::vector<AEGISFrame>&)frames
                   total:(NSUInteger)total;
- (NSString *)toJSON:(const AEGISVerdict&)v sid:(NSString *)sid;
@end

@implementation AEGISAnalyzer

- (AEGISVerdict)evaluate:(const std::vector<AEGISFrame>&)frames
                   total:(NSUInteger)total {
    AEGISVerdict v;
    v.frames = frames.size();
    v.total  = total;

    if (frames.empty()) return v;

    v.human = 0.5f;

    std::vector<double> speeds, jerks, reacts, fires;
    speeds.reserve(frames.size());
    jerks.reserve(frames.size());
    reacts.reserve(frames.size());
    fires.reserve(frames.size());
    for (const auto& f : frames) {
        speeds.push_back(f.aim_speed);
        jerks.push_back(f.aim_jerk);
        reacts.push_back(f.reaction_time);
        fires.push_back(f.fire_interval);
    }

    double combined = 0.0;
    combined += aegis::mad_zscore(speeds);
    combined += aegis::mad_zscore(jerks);
    combined += aegis::mad_zscore(reacts);
    combined += aegis::mad_zscore(fires);
    v.anomaly = (float)std::clamp(-combined / 6.0, -1.0, 1.0);
    v.iso     = (float)aegis::isolation_score(speeds);

    if (v.human < 0.30f)   v.reasons.push_back("ml.human=" + std::to_string(v.human));
    if (v.anomaly < -0.5f) v.reasons.push_back("stat.anomaly=" + std::to_string(v.anomaly));
    if (v.iso < -0.4f)     v.reasons.push_back("iso=" + std::to_string(v.iso));
    if (!reacts.empty()) {
        double minr = *std::min_element(reacts.begin(), reacts.end());
        if (minr < 0.08) v.reasons.push_back("react.min=" + std::to_string(minr));
    }
    if (!fires.empty()) {
        double minf = *std::min_element(fires.begin(), fires.end());
        if (minf < 0.02) v.reasons.push_back("fire.min=" + std::to_string(minf));
    }

    return v;
}

- (NSString *)toJSON:(const AEGISVerdict&)v sid:(NSString *)sid {
    NSMutableString *r = [NSMutableString stringWithString:@"["];
    for (size_t i = 0; i < v.reasons.size(); ++i) {
        if (i) [r appendString:@","];
        NSString *s = [NSString stringWithUTF8String:v.reasons[i].c_str()];
        [r appendFormat:@"\"%@\"", s];
    }
    [r appendString:@"]"];

    return [NSString stringWithFormat:
            @"{"
             "\"status\":\"%s\","
             "\"session\":\"%@\","
             "\"human\":%.4f,"
             "\"anomaly\":%.4f,"
             "\"iso\":%.4f,"
             "\"frames\":%zu,"
             "\"total\":%lu,"
             "\"reasons\":%@"
             "}",
            v.suspicious() ? "flagged" : "clean",
            sid,
            v.human, v.anomaly, v.iso,
            v.frames, (unsigned long)v.total,
            r];
}

@end

// ==========================================================================
// SECTION 7 — Session Registry
// ==========================================================================

@interface AEGISRegistry : NSObject
- (AEGISSession *)getOrCreate:(NSString *)sid;
@end

@implementation AEGISRegistry {
    std::mutex _m;
    NSMutableDictionary<NSString *, AEGISSession *> *_map;
}

- (instancetype)init {
    if ((self = [super init])) {
        _map = [NSMutableDictionary dictionary];
    }
    return self;
}

- (AEGISSession *)getOrCreate:(NSString *)sid {
    std::lock_guard<std::mutex> lk(_m);
    AEGISSession *s = _map[sid];
    if (!s) {
        s = [[AEGISSession alloc] initWithID:sid];
        _map[sid] = s;
    }
    return s;
}

@end

// ==========================================================================
// SECTION 8 — Integrity
// ==========================================================================

static bool AEGIS_HasDebugger(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

static bool AEGIS_HasSuspiciousDylibs(void) {
    static const char *banned[] = {
        "MobileSubstrate", "CydiaSubstrate", "SubstrateLoader",
        "FridaGadget", "frida-agent", "cynject"
    };
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        for (auto b : banned) {
            if (strstr(name, b)) return true;
        }
    }
    return false;
}

static bool AEGIS_HasSuspiciousEnv(void) {
    const char *keys[] = { "DYLD_INSERT_LIBRARIES", "DYLD_FORCE_FLAT_NAMESPACE" };
    for (auto k : keys) if (getenv(k)) return true;
    return false;
}

static bool AEGIS_IntegrityOK(void) {
    if (AEGIS_HasDebugger())         return false;
    if (AEGIS_HasSuspiciousDylibs()) return false;
    if (AEGIS_HasSuspiciousEnv())    return false;
    return true;
}

// ==========================================================================
// SECTION 9 — Global State
// ==========================================================================

static AEGISRegistry *gRegistry = nil;
static AEGISAnalyzer *gAnalyzer = nil;
static AESGCM        *gCipher   = nil;
static dispatch_queue_t gQueue  = nil;

static void AEGIS_Bootstrap(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gRegistry = [[AEGISRegistry alloc] init];
        gAnalyzer = [[AEGISAnalyzer alloc] init];
        gCipher   = [AESGCM randomKey];
        gQueue    = dispatch_queue_create("aegis.queue", DISPATCH_QUEUE_SERIAL);
        NSLog(@"[AEGIS] bootstrap ok, key len=%lu",
              (unsigned long)gCipher.key.length);
    });
}

// ==========================================================================
// SECTION 10 — Public API
// ==========================================================================

void AEGIS_IngestFrame(NSString *sessionID, const AEGISFrame& f) {
    AEGIS_Bootstrap();
    AEGISSession *s = [gRegistry getOrCreate:sessionID ?: @"unknown"];
    [s ingest:f];

    if (s.count % 30 == 0) {
        auto frames = [s snapshot:kSeqLen];
        AEGISVerdict v = [gAnalyzer evaluate:frames total:s.count];

        if (v.suspicious()) {
            NSLog(@"[AEGIS] FLAGGED session=%@ %@",
                  sessionID, [gAnalyzer toJSON:v sid:sessionID]);
        } else {
            NSLog(@"[AEGIS] clean session=%@ human=%.3f anomaly=%.3f",
                  sessionID, v.human, v.anomaly);
        }
    }
}

NSData *AEGIS_Seal(NSData *plaintext) {
    AEGIS_Bootstrap();
    NSError *e = nil;
    NSData *out = [gCipher seal:plaintext error:&e];
    if (!out) NSLog(@"[AEGIS] seal error: %@", e);
    return out;
}

NSData *AEGIS_Open(NSData *sealed) {
    AEGIS_Bootstrap();
    NSError *e = nil;
    NSData *out = [gCipher open:sealed error:&e];
    if (!out) NSLog(@"[AEGIS] open error: %@", e);
    return out;
}

bool AEGIS_CheckIntegrity(void) {
    return AEGIS_IntegrityOK();
}

// ==========================================================================
// SECTION 11 — Constructor
// ==========================================================================

__attribute__((constructor))
static void MyHook_Init(void) {
    @autoreleasepool {
        AEGIS_Bootstrap();
        NSLog(@"[MyHook] loaded — integrity=%s",
              AEGIS_IntegrityOK() ? "OK" : "FAIL");

        Class VC = objc_getClass("UIViewController");
        if (VC) {
            SEL orig = @selector(viewDidAppear:);
            SEL swiz = @selector(aegis_viewDidAppear:);
            Method m1 = class_getInstanceMethod(VC, orig);
            Method m2 = class_getInstanceMethod(VC, swiz);
            if (m1 && m2) {
                method_exchangeImplementations(m1, m2);
                NSLog(@"[MyHook] UIViewController hooked");
            }
        }
    }
}

// ==========================================================================
// SECTION 12 — Swizzled Category
// ==========================================================================

@interface UIViewController (AEGISHook)
@end

@implementation UIViewController (AEGISHook)

- (void)aegis_viewDidAppear:(BOOL)animated {
    [self aegis_viewDidAppear:animated];

    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *hello = @"AEGIS handshake";
        NSData *pt = [hello dataUsingEncoding:NSUTF8StringEncoding];
        NSData *ct = AEGIS_Seal(pt);
        NSData *rt = AEGIS_Open(ct);
        NSString *back = [[NSString alloc] initWithData:rt
                                               encoding:NSUTF8StringEncoding];
        NSLog(@"[MyHook] crypto roundtrip: %@",
              [back isEqualToString:hello] ? @"PASS" : @"FAIL");
    });
}

@end
