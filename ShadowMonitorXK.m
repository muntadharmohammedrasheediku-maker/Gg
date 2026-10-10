// ============================================================================
// ShadowMonitor XK v2.0 — iOS 14+ arm64 — تشفير مدمج
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <string.h>
#import <stdint.h>
#import <stdatomic.h>
#import <sys/mman.h>
#import <unistd.h>
#import <sys/socket.h>
#import "defcrypto_bridge.h"

static const NSInteger kSMMaxEntries    = 800;
static const NSInteger kSMSockSampleCap = 80;
static const NSInteger kSMDyldSampleCap = 60;
static const NSInteger kSMMaxDetail     = 220;

// ============================================================================
// 0b. مساعد التشفير
// ============================================================================

static NSString *SMEncryptText(NSString *text) {
    if (!text.length || text.length > 4000) return text;
    const char *bid = [[NSBundle mainBundle].bundleIdentifier ?: @"sbxk"] UTF8String;
    const uint8_t *pwd = (const uint8_t *)bid;
    size_t pwd_len = strlen(bid);
    const uint8_t *pt = (const uint8_t *)text.UTF8String;
    size_t pt_len = strlen((const char *)pt);
    uint8_t buf[8192];
    size_t blen = 0;
    if (sbxk_encrypt_pwd(pt, pt_len, pwd, pwd_len, NULL, 0,
                         buf, sizeof(buf), &blen) == 0) {
        NSMutableString *hex = [NSMutableString stringWithCapacity:blen * 2];
        for (size_t i = 0; i < blen && i < 24; i++) {
            [hex appendFormat:@"%02x", buf[i]];
        }
        return [NSString stringWithFormat:@"[🔒 %luB %@…]",
                (unsigned long)blen, hex];
    }
    return @"[enc-fail]";
}

// ============================================================================
// 1. fishhook مصغّر
// ============================================================================

struct sm_rb { const char *name; void *repl; void **replaced; };

static int sm_rebind_image(const struct mach_header *mh, intptr_t slide,
                           struct sm_rb *b, int nb)
{
    if (!mh || mh->magic != MH_MAGIC_64) return 0;
    const struct mach_header_64 *h = (const struct mach_header_64 *)mh;
    const struct segment_command_64 *le = NULL;
    const struct symtab_command *st = NULL;
    const struct dysymtab_command *dy = NULL;
    const struct load_command *lc = (const struct load_command *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            if (strcmp(sg->segname, "__LINKEDIT") == 0) le = sg;
        } else if (lc->cmd == LC_SYMTAB) st = (const struct symtab_command *)lc;
        else if (lc->cmd == LC_DYSYMTAB) dy = (const struct dysymtab_command *)lc;
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    if (!le || !st || !dy) return 0;

    uintptr_t sl = (uintptr_t)slide;
    intptr_t lb = (intptr_t)(slide + le->vmaddr - le->fileoff);
    const struct nlist_64 *sym = (const struct nlist_64 *)(lb + st->symoff);
    const char *str = (const char *)(lb + st->stroff);
    const uint32_t *ind = (const uint32_t *)(lb + dy->indirectsymoff);
    uint32_t nsyms = st->nsyms;

    int done = 0;
    lc = (const struct load_command *)(h + 1);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64 *)lc;
            const struct section_64 *sec = (const struct section_64 *)(sg + 1);
            for (uint32_t j = 0; j < sg->nsects; j++, sec++) {
                uint8_t ft = sec->flags & SECTION_TYPE;
                if (ft != S_LAZY_SYMBOL_POINTERS && ft != S_NON_LAZY_SYMBOL_POINTERS) continue;
                uint32_t cnt = (uint32_t)(sec->size / sizeof(void *));
                uint32_t start = sec->reserved1;
                for (uint32_t k = 0; k < cnt; k++) {
                    uint32_t si = ind[start + k];
                    if (si == 0 || si == 0x80000000u || si >= nsyms) continue;
                    const char *nm = str + sym[si].n_un.n_strx;
                    if (!nm || nm[0] != '_') continue;
                    const char *cl = nm + 1;
                    for (int x = 0; x < nb; x++) {
                        if (strcmp(b[x].name, cl) != 0) continue;
                        void **slot = (void **)(sl + sec->addr + k * sizeof(void *));
                        if (!slot) continue;
                        if (b[x].replaced && *b[x].replaced == NULL) *b[x].replaced = *slot;
                        uintptr_t pg = (uintptr_t)slot & ~(PAGE_SIZE - 1);
                        kern_return_t kr = vm_protect(mach_task_self_, pg, PAGE_SIZE,
                                                      false, VM_PROT_READ | VM_PROT_WRITE);
                        if (kr != KERN_SUCCESS) continue;
                        *slot = b[x].repl;
                        vm_protect(mach_task_self_, pg, PAGE_SIZE, false, VM_PROT_READ);
                        done++;
                    }
                }
            }
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return done;
}

static int sm_rebind_all(struct sm_rb *b, int nb) {
    int t = 0;
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        t += sm_rebind_image(mh, _dyld_get_image_vmaddr_slide(i), b, nb);
    }
    return t;
}

// ============================================================================
// 2. السجل المركزي
// ============================================================================

typedef NS_ENUM(NSInteger, SMKind) {
    SMKindURL  = 0,
    SMKindSSL  = 1,
    SMKindDyld = 2,
    SMKindSock = 3,
    SMKindInfo = 4,
};

@interface SMEntry : NSObject
@property (nonatomic, assign) SMKind kind;
@property (nonatomic, copy)   NSString *text;
@property (nonatomic, copy)   NSString *detail;
@property (nonatomic, strong) NSDate *time;
@property (nonatomic, assign) BOOL flagged;
@property (nonatomic, assign) BOOL encrypted;
@end
@implementation SMEntry @end

@protocol SMLogObserver <NSObject>
- (void)smLogDidChange;
@end

@interface SMLog : NSObject
@property (nonatomic, strong, readonly) NSMutableArray<SMEntry *> *entries;
@property (nonatomic, assign) BOOL paused;
@property (nonatomic, assign, readonly) NSInteger cntURL;
@property (nonatomic, assign, readonly) NSInteger cntSSL;
@property (nonatomic, assign, readonly) NSInteger cntDyld;
@property (nonatomic, assign, readonly) NSInteger cntSock;
+ (instancetype)shared;
- (void)add:(SMKind)k text:(NSString *)t detail:(NSString *)d flagged:(BOOL)f;
- (void)clear;
- (void)addObserver:(id<SMLogObserver>)o;
- (void)removeObserver:(id<SMLogObserver>)o;
@end

@implementation SMLog {
    NSHashTable<id<SMLogObserver>> *_observers;
    NSInteger _cntURL, _cntSSL, _cntDyld, _cntSock;
}

+ (instancetype)shared {
    static SMLog *s; static dispatch_once_t o;
    dispatch_once(&o, ^{
        s = [SMLog new];
        s->_entries = [NSMutableArray array];
        s->_observers = [NSHashTable weakObjectsHashTable];
    });
    return s;
}

- (NSInteger)cntURL  { return _cntURL; }
- (NSInteger)cntSSL  { return _cntSSL; }
- (NSInteger)cntDyld { return _cntDyld; }
- (NSInteger)cntSock { return _cntSock; }

- (void)addObserver:(id<SMLogObserver>)o {
    @synchronized (_observers) { [_observers addObject:o]; }
}

- (void)removeObserver:(id<SMLogObserver>)o {
    @synchronized (_observers) { [_observers removeObject:o]; }
}

- (void)_notify {
    NSArray *snapshot;
    @synchronized (_observers) { snapshot = _observers.allObjects; }
    for (id<SMLogObserver> o in snapshot) {
        @try { [o smLogDidChange]; }
        @catch (__unused NSException *e) {}
    }
}

- (void)add:(SMKind)k text:(NSString *)t detail:(NSString *)d flagged:(BOOL)f {
    if (self.paused) return;

    // تشفير النص الحساس
    NSString *storedDetail = d ?: @"";
    BOOL encrypted = NO;
    if (d.length > 0 && d.length < 4000) {
        NSString *enc = SMEncryptText(d);
        if (![enc hasPrefix:@"[enc-fail]"]) {
            storedDetail = enc;
            encrypted = YES;
        }
    }

    SMEntry *e = [SMEntry new];
    e.kind = k;
    e.text = t ?: @"";
    e.detail = storedDetail;
    e.flagged = f;
    e.encrypted = encrypted;
    e.time = [NSDate date];
    @synchronized (self) {
        [_entries insertObject:e atIndex:0];
        if (_entries.count > kSMMaxEntries) [_entries removeLastObject];
        switch (k) {
            case SMKindURL:  _cntURL++;  break;
            case SMKindSSL:  _cntSSL++;  break;
            case SMKindDyld: _cntDyld++; break;
            case SMKindSock: _cntSock++; break;
            default: break;
        }
    }
    dispatch_async(dispatch_get_main_queue(), ^{ [self _notify]; });
}

- (void)clear {
    @synchronized (self) {
        [_entries removeAllObjects];
        _cntURL = _cntSSL = _cntDyld = _cntSock = 0;
    }
    dispatch_async(dispatch_get_main_queue(), ^{ [self _notify]; });
}
@end

// ============================================================================
// 3. NSURLProtocol
// ============================================================================

static BOOL sm_isAntiCheatPath(NSString *path) {
    if (!path.length) return NO;
    NSString *low = path.lowercaseString;
    NSArray *kw = @[@"report", @"ano", @"uqm", @"crashsight", @"qapm",
                    @"heartbeat", @"attribution", @"core_report",
                    @"tss", @"security", @"anticheat", @"integrity",
                    @"risk", @"scan", @"ban"];
    for (NSString *s in kw) if ([low containsString:s]) return YES;
    return NO;
}

@interface SMURLProtocol : NSURLProtocol @end

@implementation SMURLProtocol

+ (BOOL)canInitWithRequest:(NSURLRequest *)request {
    NSString *url = request.URL.absoluteString ?: @"";
    if (!url.length) return NO;
    if ([NSURLProtocol propertyForKey:@"sm_handled" inRequest:request]) return NO;

    NSString *method = request.HTTPMethod ?: @"GET";
    NSString *host   = request.URL.host ?: @"?";
    NSString *path   = request.URL.path ?: @"/";
    if (path.length > 70) path = [[path substringToIndex:70] stringByAppendingString:@"…"];

    BOOL isAC = sm_isAntiCheatPath(path);
    NSString *line = [NSString stringWithFormat:@"%@ %@", method, path];
    NSString *det  = [NSString stringWithFormat:@"host=%@", host];

    NSData *body = request.HTTPBody;
    if (body.length) {
        size_t n = body.length < 120 ? body.length : 120;
        NSString *b = [[NSString alloc] initWithData:[body subdataWithRange:NSMakeRange(0, n)]
                                            encoding:NSUTF8StringEncoding];
        if (!b) b = [[NSString alloc] initWithData:[body subdataWithRange:NSMakeRange(0, n)]
                                          encoding:NSISOLatin1StringEncoding];
        if (b.length) {
            NSString *clean = [[b stringByReplacingOccurrencesOfString:@"\n" withString:@" "]
                                  stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
            det = [NSString stringWithFormat:@"%@  body=%@", det, clean];
        }
    }
    if (det.length > kSMMaxDetail) det = [det substringToIndex:kSMMaxDetail];

    [[SMLog shared] add:SMKindURL text:line detail:det flagged:isAC];
    return NO;
}

+ (NSURLRequest *)canonicalRequestForRequest:(NSURLRequest *)request {
    return request;
}
@end

// ============================================================================
// 4. اعتراض SSLWrite / write / send
// ============================================================================

typedef OSStatus (*SSLWrite_t)(void *, const void *, size_t, size_t *);
typedef ssize_t  (*write_t)(int, const void *, size_t);
typedef ssize_t  (*send_t)(int, const void *, size_t, int);

static SSLWrite_t orig_SSLWrite;
static write_t    orig_write;
static send_t     orig_send;

static atomic_int g_sockSample = 0;
static atomic_int g_sslSample  = 0;

static BOOL sm_isTCP(int fd) {
    int type = 0; socklen_t len = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &len) != 0) return NO;
    return type == SOCK_STREAM;
}

static BOOL sm_shouldSample(atomic_int *ctr, int cap) {
    int c = atomic_fetch_add(ctr, 1);
    return c < cap;
}

static OSStatus SM_SSLWrite(void *ctx, const void *data, size_t len, size_t *processed) {
    if (!orig_SSLWrite) return -1;
    if (!data || len == 0) return orig_SSLWrite(ctx, data, len, processed);

    if (sm_shouldSample(&g_sslSample, 100)) {
        size_t n = len < 160 ? len : 160;
        NSData *d = [NSData dataWithBytes:data length:n];
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!s) s = [[NSString alloc] initWithData:d encoding:NSISOLatin1StringEncoding];
        if (!s) s = @"";
        NSString *clean = [[s stringByReplacingOccurrencesOfString:@"\n" withString:@" "]
                              stringByReplacingOccurrencesOfString:@"\r" withString:@" "];
        NSString *low = clean.lowercaseString;
        BOOL sens = NO;
        for (NSString *kw in @[@"jailbreak", @"frida", @"substrate", @"rooted",
                                @"inject", @"cheat", @"modified", @"shadow",
                                @"tamper", @"hook", @"debug"]) {
            if ([low containsString:kw]) { sens = YES; break; }
        }
        if (clean.length > kSMMaxDetail) clean = [clean substringToIndex:kSMMaxDetail];
        [[SMLog shared] add:SMKindSSL
                       text:[NSString stringWithFormat:@"SSLWrite %zu bytes", len]
                     detail:clean flagged:sens];
    }
    return orig_SSLWrite(ctx, data, len, processed);
}

static ssize_t SM_write(int fd, const void *buf, size_t n) {
    if (!orig_write) return -1;
    if (fd >= 0 && buf && n > 0 && sm_shouldSample(&g_sockSample, kSMSockSampleCap)) {
        if (sm_isTCP(fd)) {
            [[SMLog shared] add:SMKindSock
                           text:[NSString stringWithFormat:@"write fd=%d n=%zu", fd, n]
                         detail:@"TCP stream" flagged:NO];
        }
    }
    return orig_write(fd, buf, n);
}

static ssize_t SM_send(int fd, const void *buf, size_t n, int flags) {
    if (!orig_send) return -1;
    if (fd >= 0 && buf && n > 0 && sm_shouldSample(&g_sockSample, kSMSockSampleCap * 2)) {
        if (sm_isTCP(fd)) {
            [[SMLog shared] add:SMKindSock
                           text:[NSString stringWithFormat:@"send fd=%d n=%zu", fd, n]
                         detail:@"TCP stream" flagged:NO];
        }
    }
    return orig_send(fd, buf, n, flags);
}

// ============================================================================
// 5. dyld image APIs
// ============================================================================

typedef uint32_t (*dyld_count_t)(void);
typedef const char *(*dyld_name_t)(uint32_t);
typedef const struct mach_header *(*dyld_hdr_t)(uint32_t);

static dyld_count_t orig_dyld_count;
static dyld_name_t  orig_dyld_name;
static dyld_hdr_t   orig_dyld_hdr;
static atomic_int   g_dyldSample = 0;

static uint32_t SM_dyld_count(void) {
    uint32_t r = orig_dyld_count ? orig_dyld_count() : 0;
    if (sm_shouldSample(&g_dyldSample, kSMDyldSampleCap)) {
        [[SMLog shared] add:SMKindDyld
                       text:[NSString stringWithFormat:@"_dyld_image_count → %u", r]
                     detail:@"فحص قائمة الصور" flagged:NO];
    }
    return r;
}

static const char *SM_dyld_name(uint32_t idx) {
    const char *r = orig_dyld_name ? orig_dyld_name(idx) : NULL;
    if (r && sm_shouldSample(&g_dyldSample, kSMDyldSampleCap * 2)) {
        NSString *nm = [NSString stringWithUTF8String:r];
        if (nm.length > 70) nm = [[nm substringToIndex:70] stringByAppendingString:@"…"];
        BOOL sus = NO;
        NSString *low = nm.lowercaseString;
        for (NSString *kw in @[@"frida", @"substrate", @"ellekit", @"substitute",
                                @"tweak", @"shadow", @"cheat", @"hack"]) {
            if ([low containsString:kw]) { sus = YES; break; }
        }
        [[SMLog shared] add:SMKindDyld
                       text:[NSString stringWithFormat:@"_dyld_get_image_name(%u)", idx]
                     detail:nm flagged:sus];
    }
    return r;
}

static const struct mach_header *SM_dyld_hdr(uint32_t idx) {
    const struct mach_header *r = orig_dyld_hdr ? orig_dyld_hdr(idx) : NULL;
    if (r && sm_shouldSample(&g_dyldSample, kSMDyldSampleCap * 3)) {
        [[SMLog shared] add:SMKindDyld
                       text:[NSString stringWithFormat:@"_dyld_get_image_header(%u)", idx]
                     detail:@"قراءة بنية Mach-O" flagged:NO];
    }
    return r;
}

static NSArray<NSDictionary *> *SMHookedFunctions(void) {
    return @[
        @{@"name": @"NSURLProtocol.canInitWithRequest:", @"lib": @"Foundation", @"cat": @"URL"},
        @{@"name": @"SSLWrite",                          @"lib": @"Security",   @"cat": @"SSL"},
        @{@"name": @"write",                             @"lib": @"libSystem",  @"cat": @"Socket"},
        @{@"name": @"send",                              @"lib": @"libSystem",  @"cat": @"Socket"},
        @{@"name": @"_dyld_image_count",                 @"lib": @"dyld",       @"cat": @"dyld"},
        @{@"name": @"_dyld_get_image_name",              @"lib": @"dyld",       @"cat": @"dyld"},
        @{@"name": @"_dyld_get_image_header",            @"lib": @"dyld",       @"cat": @"dyld"},
        @{@"name": @"defcrypto.sbxk_encrypt_pwd",        @"lib": @"OpenSSL",    @"cat": @"Crypto"},
        @{@"name": @"defcrypto.sbxk_decrypt_pwd",        @"lib": @"OpenSSL",    @"cat": @"Crypto"},
    ];
}

// ============================================================================
// 6. الخلية
// ============================================================================

@interface SMCell : UITableViewCell
@property (nonatomic, strong) UIView *dot;
@property (nonatomic, strong) UILabel *timeLbl;
@property (nonatomic, strong) UILabel *textLbl;
@property (nonatomic, strong) UILabel *detailLbl;
- (void)bind:(SMEntry *)e;
@end

@implementation SMCell

- (instancetype)initWithStyle:(UITableViewCellStyle)style reuseIdentifier:(NSString *)reuseIdentifier {
    self = [super initWithStyle:style reuseIdentifier:reuseIdentifier];
    if (!self) return nil;
    self.backgroundColor = [UIColor clearColor];
    self.selectionStyle = UITableViewCellSelectionStyleNone;

    _dot = [UIView new];
    _dot.translatesAutoresizingMaskIntoConstraints = NO;
    _dot.layer.cornerRadius = 4;

    _timeLbl = [UILabel new];
    _timeLbl.translatesAutoresizingMaskIntoConstraints = NO;
    _timeLbl.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightMedium];
    _timeLbl.textColor = [UIColor colorWithWhite:0.55 alpha:1];
    _timeLbl.textAlignment = NSTextAlignmentCenter;

    _textLbl = [UILabel new];
    _textLbl.translatesAutoresizingMaskIntoConstraints = NO;
    _textLbl.font = [UIFont monospacedSystemFontOfSize:12 weight:UIFontWeightSemibold];
    _textLbl.textColor = [UIColor whiteColor];
    _textLbl.numberOfLines = 1;

    _detailLbl = [UILabel new];
    _detailLbl.translatesAutoresizingMaskIntoConstraints = NO;
    _detailLbl.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    _detailLbl.textColor = [UIColor colorWithWhite:0.65 alpha:1];
    _detailLbl.numberOfLines = 2;

    [self.contentView addSubview:_dot];
    [self.contentView addSubview:_timeLbl];
    [self.contentView addSubview:_textLbl];
    [self.contentView addSubview:_detailLbl];

    [NSLayoutConstraint activateConstraints:@[
        [_dot.leadingAnchor  constraintEqualToAnchor:self.contentView.leadingAnchor constant:14],
        [_dot.topAnchor      constraintEqualToAnchor:self.contentView.topAnchor constant:10],
        [_dot.widthAnchor    constraintEqualToConstant:8],
        [_dot.heightAnchor   constraintEqualToConstant:8],

        [_timeLbl.leadingAnchor constraintEqualToAnchor:_dot.trailingAnchor constant:6],
        [_timeLbl.centerYAnchor constraintEqualToAnchor:_dot.centerYAnchor],
        [_timeLbl.widthAnchor   constraintEqualToConstant:56],

        [_textLbl.leadingAnchor constraintEqualToAnchor:_timeLbl.trailingAnchor constant:8],
        [_textLbl.trailingAnchor constraintEqualToAnchor:self.contentView.trailingAnchor constant:-14],
        [_textLbl.centerYAnchor constraintEqualToAnchor:_dot.centerYAnchor],

        [_detailLbl.leadingAnchor constraintEqualToAnchor:_textLbl.leadingAnchor],
        [_detailLbl.trailingAnchor constraintEqualToAnchor:_textLbl.trailingAnchor],
        [_detailLbl.topAnchor   constraintEqualToAnchor:_textLbl.bottomAnchor constant:3],
    ]];
    return self;
}

- (void)bind:(SMEntry *)e {
    static NSDateFormatter *df = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        df = [NSDateFormatter new];
        df.dateFormat = @"HH:mm:ss";
    });
    _timeLbl.text = [df stringFromDate:e.time];
    _textLbl.text = e.text;
    _detailLbl.text = e.detail;

    UIColor *c;
    switch (e.kind) {
        case SMKindURL:  c = [UIColor colorWithRed:0.04 green:0.52 blue:1.0 alpha:1]; break;
        case SMKindSSL:  c = [UIColor colorWithRed:0.20 green:0.78 blue:0.35 alpha:1]; break;
        case SMKindDyld: c = [UIColor colorWithRed:1.0  green:0.58 blue:0.00 alpha:1]; break;
        case SMKindSock: c = [UIColor colorWithRed:0.68 green:0.32 blue:0.87 alpha:1]; break;
        default:         c = [UIColor colorWithWhite:0.5 alpha:1]; break;
    }
    _dot.backgroundColor = c;

    if (e.encrypted) {
        _detailLbl.textColor = [UIColor colorWithRed:0.40 green:0.90 blue:0.90 alpha:1];
    } else {
        _detailLbl.textColor = [UIColor colorWithWhite:0.65 alpha:1];
    }

    if (e.flagged) {
        _textLbl.textColor = [UIColor colorWithRed:1.0 green:0.36 blue:0.32 alpha:1];
    } else {
        _textLbl.textColor = [UIColor whiteColor];
    }
}
@end

// ============================================================================
// 7. الزر العائم
// ============================================================================

@interface SMFab : UIView
@property (nonatomic, copy) void(^onTap)(void);
- (void)setBadge:(NSInteger)n;
@end

@implementation SMFab {
    UIView  *_inner;
    UILabel *_glyph;
    UILabel *_badge;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (!self) return nil;
    self.backgroundColor = [UIColor clearColor];

    _inner = [UIView new];
    _inner.translatesAutoresizingMaskIntoConstraints = NO;
    _inner.backgroundColor = [UIColor colorWithRed:0.04 green:0.52 blue:1.0 alpha:0.95];
    _inner.layer.cornerRadius = 28;
    _inner.layer.shadowColor = [UIColor blackColor].CGColor;
    _inner.layer.shadowOpacity = 0.5;
    _inner.layer.shadowRadius = 12;
    _inner.layer.shadowOffset = CGSizeMake(0, 4);

    _glyph = [UILabel new];
    _glyph.translatesAutoresizingMaskIntoConstraints = NO;
    _glyph.text = @"◉";
    _glyph.textAlignment = NSTextAlignmentCenter;
    _glyph.textColor = [UIColor whiteColor];
    _glyph.font = [UIFont systemFontOfSize:26 weight:UIFontWeightBold];

    _badge = [UILabel new];
    _badge.translatesAutoresizingMaskIntoConstraints = NO;
    _badge.text = @"0";
    _badge.textAlignment = NSTextAlignmentCenter;
    _badge.textColor = [UIColor whiteColor];
    _badge.backgroundColor = [UIColor colorWithRed:1.0 green:0.27 blue:0.23 alpha:1];
    _badge.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightBold];
    _badge.layer.cornerRadius = 9;
    _badge.layer.masksToBounds = YES;
    _badge.hidden = YES;
    _badge.userInteractionEnabled = NO;

    [self addSubview:_inner];
    [_inner addSubview:_glyph];
    [self addSubview:_badge];

    [NSLayoutConstraint activateConstraints:@[
        [_inner.topAnchor      constraintEqualToAnchor:self.topAnchor],
        [_inner.bottomAnchor   constraintEqualToAnchor:self.bottomAnchor],
        [_inner.leadingAnchor  constraintEqualToAnchor:self.leadingAnchor],
        [_inner.trailingAnchor constraintEqualToAnchor:self.trailingAnchor],
        [_glyph.centerXAnchor constraintEqualToAnchor:_inner.centerXAnchor],
        [_glyph.centerYAnchor constraintEqualToAnchor:_inner.centerYAnchor],
        [_badge.topAnchor       constraintEqualToAnchor:self.topAnchor constant:-4],
        [_badge.trailingAnchor  constraintEqualToAnchor:self.trailingAnchor constant:4],
        [_badge.heightAnchor     constraintEqualToConstant:18],
        [_badge.widthAnchor      constraintGreaterThanOrEqualToConstant:18],
    ]];

    UITapGestureRecognizer *tap = [[UITapGestureRecognizer alloc]
                                    initWithTarget:self action:@selector(_handleTap)];
    [self addGestureRecognizer:tap];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
                                    initWithTarget:self action:@selector(_handlePan:)];
    [self addGestureRecognizer:pan];
    return self;
}

- (void)_handleTap {
    UIImpactFeedbackGenerator *h = [[UIImpactFeedbackGenerator alloc] initWithStyle:UIImpactFeedbackStyleLight];
    [h impactOccurred];
    if (self.onTap) self.onTap();
}

- (void)_handlePan:(UIPanGestureRecognizer *)g {
    UIView *sv = self.superview; if (!sv) return;
    CGPoint t = [g translationInView:sv];
    CGPoint c = self.center;
    c.x += t.x; c.y += t.y;
    CGFloat hw = self.bounds.size.width / 2;
    CGFloat hh = self.bounds.size.height / 2;
    c.x = MAX(hw + 8, MIN(sv.bounds.size.width - hw - 8, c.x));
    c.y = MAX(hh + 80, MIN(sv.bounds.size.height - hh - 40, c.y));
    self.center = c;
    [g setTranslation:CGPointZero inView:sv];
}

- (void)setBadge:(NSInteger)n {
    _badge.hidden = (n == 0);
    _badge.text = n > 999 ? @"999+" : [NSString stringWithFormat:@"%ld", (long)n];
}
@end

// ============================================================================
// 8. اللوحة الرئيسية
// ============================================================================

@interface SMPanel : UIViewController <UITableViewDataSource, UITableViewDelegate, SMLogObserver>
@property (nonatomic, strong) UITableView *table;
@property (nonatomic, strong) UIVisualEffectView *blur;
@property (nonatomic, strong) UILabel *titleLbl;
@property (nonatomic, strong) UILabel *statusLbl;
@property (nonatomic, strong) UISegmentedControl *filter;
@property (nonatomic, strong) UILabel *cntURLLbl;
@property (nonatomic, strong) UILabel *cntSSLLbl;
@property (nonatomic, strong) UILabel *cntDyldLbl;
@property (nonatomic, strong) UILabel *cntSockLbl;
@property (nonatomic, strong) UIButton *pauseBtn;
@property (nonatomic, assign) NSInteger filterIdx;
@end

@implementation SMPanel

- (void)dealloc { [[SMLog shared] removeObserver:self]; }

- (void)viewDidLoad {
    [super viewDidLoad];
    [[SMLog shared] addObserver:self];

    UIBlurEffect *be = [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterialDark];
    _blur = [[UIVisualEffectView alloc] initWithEffect:be];
    _blur.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:_blur];

    UIView *bg = [UIView new];
    bg.translatesAutoresizingMaskIntoConstraints = NO;
    bg.backgroundColor = [UIColor colorWithWhite:0.03 alpha:0.5];
    [_blur.contentView addSubview:bg];

    _titleLbl = [UILabel new];
    _titleLbl.translatesAutoresizingMaskIntoConstraints = NO;
    _titleLbl.text = @"SBXK Monitor";
    _titleLbl.font = [UIFont systemFontOfSize:22 weight:UIFontWeightBold];
    _titleLbl.textColor = [UIColor whiteColor];
    [_blur.contentView addSubview:_titleLbl];

    _statusLbl = [UILabel new];
    _statusLbl.translatesAutoresizingMaskIntoConstraints = NO;
    _statusLbl.text = @"● نشط";
    _statusLbl.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightMedium];
    _statusLbl.textColor = [UIColor colorWithRed:0.20 green:0.85 blue:0.35 alpha:1];
    [_blur.contentView addSubview:_statusLbl];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close setTitle:@"✕" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor colorWithWhite:0.7 alpha:1] forState:UIControlStateNormal];
    close.titleLabel.font = [UIFont systemFontOfSize:20 weight:UIFontWeightMedium];
    [close addTarget:self action:@selector(_close) forControlEvents:UIControlEventTouchUpInside];
    [_blur.contentView addSubview:close];

    UIStackView *statStack = [UIStackView new];
    statStack.translatesAutoresizingMaskIntoConstraints = NO;
    statStack.axis = UILayoutConstraintAxisHorizontal;
    statStack.distribution = UIStackViewDistributionFillEqually;
    statStack.spacing = 8;
    [_blur.contentView addSubview:statStack];

    UIColor *cURL  = [UIColor colorWithRed:0.04 green:0.52 blue:1.0 alpha:1];
    UIColor *cSSL  = [UIColor colorWithRed:0.20 green:0.78 blue:0.35 alpha:1];
    UIColor *cDyld = [UIColor colorWithRed:1.0  green:0.58 blue:0.00 alpha:1];
    UIColor *cSock = [UIColor colorWithRed:0.68 green:0.32 blue:0.87 alpha:1];

    _cntURLLbl  = [self _statPillInStack:statStack color:cURL  title:@"URL"];
    _cntSSLLbl  = [self _statPillInStack:statStack color:cSSL  title:@"SSL"];
    _cntDyldLbl = [self _statPillInStack:statStack color:cDyld title:@"dyld"];
    _cntSockLbl = [self _statPillInStack:statStack color:cSock title:@"sock"];

    _filter = [[UISegmentedControl alloc] initWithItems:@[@"الكل", @"URL", @"SSL", @"dyld", @"sock"]];
    _filter.translatesAutoresizingMaskIntoConstraints = NO;
    _filter.selectedSegmentIndex = 0;
    _filter.selectedSegmentTintColor = cURL;
    [_filter setTitleTextAttributes:@{NSForegroundColorAttributeName:[UIColor whiteColor]}
                            forState:UIControlStateSelected];
    [_filter setTitleTextAttributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:0.7 alpha:1]}
                            forState:UIControlStateNormal];
    [_filter addTarget:self action:@selector(_filterChanged) forControlEvents:UIControlEventValueChanged];
    [_blur.contentView addSubview:_filter];

    _table = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    _table.translatesAutoresizingMaskIntoConstraints = NO;
    _table.backgroundColor = [UIColor clearColor];
    _table.separatorStyle = UITableViewCellSeparatorStyleNone;
    _table.dataSource = self;
    _table.delegate = self;
    _table.rowHeight = 50;
    [_table registerClass:[SMCell class] forCellReuseIdentifier:@"c"];
    [_blur.contentView addSubview:_table];

    UIStackView *toolStack = [UIStackView new];
    toolStack.translatesAutoresizingMaskIntoConstraints = NO;
    toolStack.axis = UILayoutConstraintAxisHorizontal;
    toolStack.distribution = UIStackViewDistributionFillEqually;
    toolStack.spacing = 8;
    [_blur.contentView addSubview:toolStack];

    UIButton *clearB = [self _toolButton:@"مسح" color:[UIColor colorWithRed:1.0 green:0.27 blue:0.23 alpha:1]
                                   action:@selector(_clear)];
    _pauseBtn = [self _toolButton:@"إيقاف" color:[UIColor colorWithRed:1.0 green:0.58 blue:0.00 alpha:1]
                           action:@selector(_pause)];
    UIButton *copyB = [self _toolButton:@"نسخ JSON" color:cURL action:@selector(_copy)];
    [toolStack addArrangedSubview:clearB];
    [toolStack addArrangedSubview:_pauseBtn];
    [toolStack addArrangedSubview:copyB];

    UILayoutGuide *safe = _blur.contentView.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [_blur.topAnchor      constraintEqualToAnchor:self.view.topAnchor],
        [_blur.bottomAnchor   constraintEqualToAnchor:self.view.bottomAnchor],
        [_blur.leadingAnchor  constraintEqualToAnchor:self.view.leadingAnchor],
        [_blur.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [bg.topAnchor      constraintEqualToAnchor:_blur.contentView.topAnchor],
        [bg.bottomAnchor   constraintEqualToAnchor:_blur.contentView.bottomAnchor],
        [bg.leadingAnchor  constraintEqualToAnchor:_blur.contentView.leadingAnchor],
        [bg.trailingAnchor constraintEqualToAnchor:_blur.contentView.trailingAnchor],
        [_titleLbl.topAnchor     constraintEqualToAnchor:safe.topAnchor constant:16],
        [_titleLbl.leadingAnchor constraintEqualToAnchor:_blur.contentView.leadingAnchor constant:20],
        [_statusLbl.topAnchor     constraintEqualToAnchor:_titleLbl.bottomAnchor constant:2],
        [_statusLbl.leadingAnchor constraintEqualToAnchor:_titleLbl.leadingAnchor],
        [close.topAnchor     constraintEqualToAnchor:_titleLbl.topAnchor],
        [close.trailingAnchor constraintEqualToAnchor:_blur.contentView.trailingAnchor constant:-16],
        [close.widthAnchor   constraintEqualToConstant:36],
        [close.heightAnchor  constraintEqualToConstant:36],
        [statStack.topAnchor      constraintEqualToAnchor:_statusLbl.bottomAnchor constant:16],
        [statStack.leadingAnchor  constraintEqualToAnchor:_blur.contentView.leadingAnchor constant:16],
        [statStack.trailingAnchor constraintEqualToAnchor:_blur.contentView.trailingAnchor constant:-16],
        [statStack.heightAnchor   constraintEqualToConstant:64],
        [_filter.topAnchor      constraintEqualToAnchor:statStack.bottomAnchor constant:12],
        [_filter.leadingAnchor  constraintEqualToAnchor:_blur.contentView.leadingAnchor constant:16],
        [_filter.trailingAnchor constraintEqualToAnchor:_blur.contentView.trailingAnchor constant:-16],
        [_table.topAnchor      constraintEqualToAnchor:_filter.bottomAnchor constant:8],
        [_table.leadingAnchor  constraintEqualToAnchor:_blur.contentView.leadingAnchor],
        [_table.trailingAnchor constraintEqualToAnchor:_blur.contentView.trailingAnchor],
        [_table.bottomAnchor   constraintEqualToAnchor:toolStack.topAnchor constant:-8],
        [toolStack.leadingAnchor   constraintEqualToAnchor:_blur.contentView.leadingAnchor constant:16],
        [toolStack.trailingAnchor  constraintEqualToAnchor:_blur.contentView.trailingAnchor constant:-16],
        [toolStack.bottomAnchor    constraintEqualToAnchor:safe.bottomAnchor constant:-12],
        [toolStack.heightAnchor    constraintEqualToConstant:44],
    ]];

    [self _refresh];
}

- (UILabel *)_statPillInStack:(UIStackView *)stack color:(UIColor *)color title:(NSString *)title {
    UIView *pill = [UIView new];
    pill.translatesAutoresizingMaskIntoConstraints = NO;
    pill.backgroundColor = [UIColor colorWithWhite:1 alpha:0.06];
    pill.layer.cornerRadius = 14;
    pill.layer.borderWidth = 1;
    pill.layer.borderColor = [color colorWithAlphaComponent:0.35].CGColor;

    UIView *dot = [UIView new];
    dot.translatesAutoresizingMaskIntoConstraints = NO;
    dot.backgroundColor = color;
    dot.layer.cornerRadius = 4;
    [pill addSubview:dot];

    UILabel *t = [UILabel new];
    t.translatesAutoresizingMaskIntoConstraints = NO;
    t.text = title;
    t.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightMedium];
    t.textColor = [UIColor colorWithWhite:0.7 alpha:1];
    [pill addSubview:t];

    UILabel *v = [UILabel new];
    v.translatesAutoresizingMaskIntoConstraints = NO;
    v.text = @"0";
    v.font = [UIFont monospacedSystemFontOfSize:16 weight:UIFontWeightBold];
    v.textColor = [UIColor whiteColor];
    [pill addSubview:v];

    [NSLayoutConstraint activateConstraints:@[
        [dot.leadingAnchor constraintEqualToAnchor:pill.leadingAnchor constant:10],
        [dot.topAnchor     constraintEqualToAnchor:pill.topAnchor constant:12],
        [dot.widthAnchor   constraintEqualToConstant:8],
        [dot.heightAnchor  constraintEqualToConstant:8],
        [t.leadingAnchor constraintEqualToAnchor:dot.trailingAnchor constant:6],
        [t.centerYAnchor constraintEqualToAnchor:dot.centerYAnchor],
        [v.leadingAnchor constraintEqualToAnchor:pill.leadingAnchor constant:10],
        [v.topAnchor     constraintEqualToAnchor:dot.bottomAnchor constant:6],
    ]];
    [stack addArrangedSubview:pill];
    return v;
}

- (UIButton *)_toolButton:(NSString *)title color:(UIColor *)color action:(SEL)sel {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeSystem];
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:color forState:UIControlStateNormal];
    b.titleLabel.font = [UIFont systemFontOfSize:14 weight:UIFontWeightSemibold];
    b.backgroundColor = [color colorWithAlphaComponent:0.15];
    b.layer.cornerRadius = 10;
    b.layer.borderWidth = 1;
    b.layer.borderColor = [color colorWithAlphaComponent:0.4].CGColor;
    [b addTarget:self action:sel forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (void)smLogDidChange { [self _refresh]; }

- (void)_refresh {
    SMLog *L = [SMLog shared];
    _cntURLLbl.text  = [NSString stringWithFormat:@"%ld", (long)L.cntURL];
    _cntSSLLbl.text  = [NSString stringWithFormat:@"%ld", (long)L.cntSSL];
    _cntDyldLbl.text = [NSString stringWithFormat:@"%ld", (long)L.cntDyld];
    _cntSockLbl.text = [NSString stringWithFormat:@"%ld", (long)L.cntSock];
    _statusLbl.text = L.paused
        ? @"◉ موقوف مؤقتاً"
        : [NSString stringWithFormat:@"● نشط — %lu حدث", (unsigned long)L.entries.count];
    _statusLbl.textColor = L.paused
        ? [UIColor colorWithRed:1.0 green:0.58 blue:0.00 alpha:1]
        : [UIColor colorWithRed:0.20 green:0.85 blue:0.35 alpha:1];
    [_table reloadData];
}

- (void)_filterChanged { _filterIdx = _filter.selectedSegmentIndex; [_table reloadData]; }
- (void)_close { [self dismissViewControllerAnimated:YES completion:nil]; }
- (void)_clear { [[SMLog shared] clear]; }

- (void)_pause {
    SMLog *L = [SMLog shared];
    L.paused = !L.paused;
    [_pauseBtn setTitle:(L.paused ? @"متابعة" : @"إيقاف") forState:UIControlStateNormal];
    [self _refresh];
}

- (void)_copy {
    NSMutableArray *arr = [NSMutableArray array];
    NSDateFormatter *df = [NSDateFormatter new];
    df.dateFormat = @"HH:mm:ss";
    NSString *cats[] = {@"url", @"ssl", @"dyld", @"sock", @"info"};
    for (SMEntry *e in [SMLog shared].entries) {
        [arr addObject:@{
            @"t":  [df stringFromDate:e.time],
            @"k":  cats[e.kind],
            @"x":  e.text,
            @"d":  e.detail,
            @"f":  @(e.flagged),
            @"e":  @(e.encrypted),
        }];
    }
    NSData *d = [NSJSONSerialization dataWithJSONObject:arr
                                                 options:NSJSONWritingPrettyPrinted error:nil];
    NSString *s = d ? [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding] : @"[]";
    [UIPasteboard generalPasteboard].string = s;
    UINotificationFeedbackGenerator *h = [UINotificationFeedbackGenerator new];
    [h notificationOccurred:UINotificationFeedbackTypeSuccess];
}

- (NSInteger)tableView:(UITableView *)tableView numberOfRowsInSection:(NSInteger)section {
    SMLog *L = [SMLog shared];
    if (_filterIdx == 0) return L.entries.count;
    NSInteger n = 0;
    SMKind want = (SMKind)(_filterIdx - 1);
    for (SMEntry *e in L.entries) if (e.kind == want) n++;
    return n;
}

- (UITableViewCell *)tableView:(UITableView *)tableView cellForRowAtIndexPath:(NSIndexPath *)indexPath {
    SMCell *c = [tableView dequeueReusableCellWithIdentifier:@"c" forIndexPath:indexPath];
    SMLog *L = [SMLog shared];
    if (_filterIdx == 0) {
        [c bind:L.entries[indexPath.row]];
    } else {
        SMKind want = (SMKind)(_filterIdx - 1);
        NSInteger k = 0;
        for (SMEntry *e in L.entries) {
            if (e.kind == want) {
                if (k == indexPath.row) { [c bind:e]; break; }
                k++;
            }
        }
    }
    return c;
}
@end

// ============================================================================
// 9. مدير الواجهة
// ============================================================================

@interface SMManager : NSObject <SMLogObserver>
@property (nonatomic, strong) UIWindow *overlay;
@property (nonatomic, strong) SMFab    *fab;
@property (nonatomic, assign) BOOL presenting;
+ (instancetype)shared;
- (void)install;
@end

@implementation SMManager

+ (instancetype)shared {
    static SMManager *s; static dispatch_once_t o;
    dispatch_once(&o, ^{ s = [SMManager new]; });
    return s;
}

- (UIWindowScene *)_activeScene {
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if (![sc isKindOfClass:[UIWindowScene class]]) continue;
        if (sc.activationState == UISceneActivationStateForegroundActive) return (UIWindowScene *)sc;
    }
    for (UIScene *sc in [UIApplication sharedApplication].connectedScenes) {
        if ([sc isKindOfClass:[UIWindowScene class]]) return (UIWindowScene *)sc;
    }
    return nil;
}

- (void)install {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ [self _installNow]; });
    [[NSNotificationCenter defaultCenter] addObserver:self
        selector:@selector(_sceneChanged)
            name:UIApplicationDidBecomeActiveNotification object:nil];
}

- (void)_sceneChanged {
    dispatch_async(dispatch_get_main_queue(), ^{ [self _installNow]; });
}

- (void)_installNow {
    if (self.overlay) return;
    UIWindowScene *scene = [self _activeScene];
    if (!scene) return;

    UIWindow *w = [[UIWindow alloc] initWithWindowScene:scene];
    w.frame = scene.coordinateSpace.bounds;
    w.windowLevel = UIWindowLevelAlert + 100;
    w.backgroundColor = [UIColor clearColor];
    w.rootViewController = [UIViewController new];
    w.hidden = NO;

    CGFloat sz = 56;
    CGFloat x = w.bounds.size.width - sz - 16;
    CGFloat y = w.bounds.size.height * 0.35;

    SMFab *fab = [[SMFab alloc] initWithFrame:CGRectMake(x, y, sz, sz)];
    __weak typeof(self) wself = self;
    fab.onTap = ^{ [wself _openPanel]; };
    [w.rootViewController.view addSubview:fab];

    self.overlay = w;
    self.fab = fab;

    [[SMLog shared] addObserver:self];
    [self smLogDidChange];
}

- (void)smLogDidChange {
    SMLog *L = [SMLog shared];
    NSInteger total = L.cntURL + L.cntSSL + L.cntDyld + L.cntSock;
    dispatch_async(dispatch_get_main_queue(), ^{ [self.fab setBadge:total]; });
}

- (void)_openPanel {
    if (self.presenting) return;
    if (!self.overlay) { [self _installNow]; }
    if (!self.overlay) return;

    UIViewController *root = self.overlay.rootViewController;
    if (!root) return;
    if (root.presentedViewController) return;

    self.presenting = YES;

    SMPanel *p = [SMPanel new];
    p.modalPresentationStyle = UIModalPresentationPageSheet;

    if (@available(iOS 15.0, *)) {
        UISheetPresentationController *sc = p.sheetPresentationController;
        if (sc) {
            if (@available(iOS 16.0, *)) {
                UISheetPresentationControllerDetent *big =
                    [UISheetPresentationControllerDetent
                        detentWithIdentifier:@"big"
                        resolver:^CGFloat(id<UISheetPresentationControllerDetentResolutionContext> ctx) {
                            return ctx.maximumDetentValue;
                        }];
                sc.detents = @[big];
            } else {
                sc.detents = @[UISheetPresentationControllerDetent.largeDetent];
            }
            sc.prefersGrabberVisible = YES;
            sc.preferredCornerRadius = 20;
        }
    }

    __weak typeof(self) wself = self;
    [root presentViewController:p animated:YES completion:^{
        wself.presenting = NO;
    }];
}
@end

// ============================================================================
// 10. نقطة الدخول
// ============================================================================

__attribute__((constructor))
static void SM_Boot(void) {
    @autoreleasepool {
        NSLog(@"[SM-XK] v2.0 boot");
        [NSURLProtocol registerClass:[SMURLProtocol class]];

        struct sm_rb rb[] = {
            { "SSLWrite",                (void *)SM_SSLWrite,    (void **)&orig_SSLWrite    },
            { "write",                   (void *)SM_write,       (void **)&orig_write       },
            { "send",                    (void *)SM_send,        (void **)&orig_send        },
            { "_dyld_image_count",       (void *)SM_dyld_count,  (void **)&orig_dyld_count  },
            { "_dyld_get_image_name",    (void *)SM_dyld_name,   (void **)&orig_dyld_name   },
            { "_dyld_get_image_header",  (void *)SM_dyld_hdr,    (void **)&orig_dyld_hdr    },
        };
        int n = sm_rebind_all(rb, (int)(sizeof(rb)/sizeof(rb[0])));
        NSLog(@"[SM-XK] hooked %d/%zu C symbols", n, sizeof(rb)/sizeof(rb[0]));

        for (NSDictionary *d in SMHookedFunctions()) {
            [[SMLog shared] add:SMKindInfo
                           text:d[@"name"]
                         detail:[NSString stringWithFormat:@"من %@ (%@)", d[@"lib"], d[@"cat"]]
                        flagged:NO];
        }
        [[SMManager shared] install];
    }
}
