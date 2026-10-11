// ============================================================================
// ShadowBypass XK v9.0 — iOS 14+ arm64/arm64e
//
// 8 طبقات دفاعية:
//   §0  Crypto          ChaCha20-lite
//   §1  SafeSwizzle     ObjC method hooking (no exceptions)
//   §2  HookEngine      Inline hooking (prologue-aware + RW→RX + MAP_JIT)
//   §3  GOTFallback     fishhook
//   §4  StringShield    Caller-side filtering (recursion-safe)
//   §5  BehaviorMimic   Kernel API emulation
//   §6  TargetRegistry  All detection handlers
//   §7  Lifecycle       Event-driven cleanup
//   §8  Boot            Entry point
// ============================================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/nlist.h>
#import <mach/mach.h>
#import <mach/mach_time.h>
#import <mach/vm_region.h>
#import <mach/vm_page_size.h>
#import <mach/exception_types.h>
#import <signal.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>
#import <stdint.h>
#import <stdatomic.h>
#import <dlfcn.h>
#import <pthread.h>
#import <sys/mman.h>
#import <sys/sysctl.h>
#import <sys/types.h>

// ============================================================================
// §0 SBXK_Crypto — ChaCha20-lite
// ============================================================================

typedef struct { uint32_t state[16]; } SBXK_ChaCha_t;

static inline uint32_t SBXK_rotl(uint32_t v, int c) {
    return (v << c) | (v >> (32 - c));
}

static inline void SBXK_qr(uint32_t *s, int a, int b, int c, int d) {
    s[a] += s[b]; s[d] ^= s[a]; s[d] = SBXK_rotl(s[d], 16);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = SBXK_rotl(s[b], 12);
    s[a] += s[b]; s[d] ^= s[a]; s[d] = SBXK_rotl(s[d],  8);
    s[c] += s[d]; s[b] ^= s[c]; s[b] = SBXK_rotl(s[b],  7);
}

static void SBXK_chacha_block(SBXK_ChaCha_t *c) {
    uint32_t x[16];
    memcpy(x, c->state, sizeof(x));
    for (int i = 0; i < 10; i++) {
        SBXK_qr(x, 0, 4,  8, 12); SBXK_qr(x, 1, 5,  9, 13);
        SBXK_qr(x, 2, 6, 10, 14); SBXK_qr(x, 3, 7, 11, 15);
        SBXK_qr(x, 0, 5, 10, 15); SBXK_qr(x, 1, 6, 11, 12);
        SBXK_qr(x, 2, 7,  8, 13); SBXK_qr(x, 3, 4,  9, 14);
    }
    for (int i = 0; i < 16; i++) c->state[i] += x[i];
}

static uint32_t g_sbxk_key[8] = {0};
static atomic_bool g_sbxk_key_ready = false;

static void SBXK_derive_key(void) {
    if (atomic_load(&g_sbxk_key_ready)) return;
    uint64_t t1 = mach_absolute_time();
    uint64_t t2 = (uint64_t)(uintptr_t)&SBXK_derive_key;
    uint64_t t3 = (uint64_t)getpid();
    uint64_t mix = t1 ^ (t2 * 0x9E3779B97F4A7C15ULL) ^ (t3 << 32);
    for (int i = 0; i < 8; i++) {
        mix ^= mix >> 30; mix *= 0xBF58476D1CE4E5B9ULL;
        mix ^= mix >> 27; mix *= 0x94D049BB133111EBULL;
        mix ^= mix >> 31;
        g_sbxk_key[i] = (uint32_t)(mix ^ (mix >> 32));
    }
    atomic_store(&g_sbxk_key_ready, true);
}

struct sbxk_enc_s {
    uint8_t  iv[8];
    uint16_t len;
    uint8_t  cipher[200];
};

static void SBXK_enc(const char *plain, struct sbxk_enc_s *out) {
    SBXK_derive_key();
    memset(out, 0, sizeof(*out));
    size_t n = strlen(plain) + 1;
    if (n > 200) n = 200;
    out->len = (uint16_t)n;

    uint64_t seed = mach_absolute_time() ^ (uintptr_t)plain ^ (uintptr_t)out;
    for (int i = 0; i < 8; i++) {
        seed ^= seed >> 12; seed ^= seed << 25; seed ^= seed >> 27;
        out->iv[i] = (uint8_t)(seed >> (i * 8));
    }

    SBXK_ChaCha_t c;
    c.state[0] = 0x61707865; c.state[1] = 0x3320646e;
    c.state[2] = 0x79622d32; c.state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) c.state[4 + i] = g_sbxk_key[i];
    c.state[12] = 0; c.state[13] = 0;
    memcpy(&c.state[14], out->iv, 8);

    uint8_t ks[200];
    for (size_t off = 0; off < n; off += 64) {
        SBXK_chacha_block(&c);
        uint8_t *kp = (uint8_t *)c.state;
        size_t take = (n - off) > 64 ? 64 : (n - off);
        memcpy(ks + off, kp, take);
        c.state[12]++;
    }
    for (size_t i = 0; i < n; i++) out->cipher[i] = (uint8_t)plain[i] ^ ks[i];
}

static void SBXK_dec(const struct sbxk_enc_s *in, char *out) {
    SBXK_derive_key();
    uint16_t n = in->len;
    if (n > 200) n = 200;

    SBXK_ChaCha_t c;
    c.state[0] = 0x61707865; c.state[1] = 0x3320646e;
    c.state[2] = 0x79622d32; c.state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) c.state[4 + i] = g_sbxk_key[i];
    c.state[12] = 0; c.state[13] = 0;
    memcpy(&c.state[14], in->iv, 8);

    for (size_t off = 0; off < n; off += 64) {
        SBXK_chacha_block(&c);
        uint8_t *kp = (uint8_t *)c.state;
        size_t take = (n - off) > 64 ? 64 : (n - off);
        for (size_t i = 0; i < take; i++) out[off + i] = (char)(in->cipher[off + i] ^ kp[i]);
        c.state[12]++;
    }
}

#define SBXK_STR(s) (^const char *{ \
    static struct sbxk_enc_s _e; static char _p[200]; static atomic_int _init = 0; \
    int _exp = 0; \
    if (atomic_compare_exchange_strong(&_init, &_exp, 1)) { \
        SBXK_enc(s, &_e); SBXK_dec(&_e, _p); } \
    return _p; }())

// ============================================================================
// §1 SBXK_SafeSwizzle — Safe ObjC method hooking (no @try)
// ============================================================================

typedef struct {
    Class  cls;
    SEL    sel;
    IMP    orig;
    IMP    repl;
    Method m;
    bool   installed;
} SBXK_Hook_t;

static SBXK_Hook_t *g_hooks = NULL;
static size_t g_hooks_cap = 0;
static size_t g_hooks_len = 0;
static pthread_mutex_t g_hooks_lock = PTHREAD_MUTEX_INITIALIZER;

static bool SBXK_hook_add(Class c, SEL s, IMP repl) {
    if (!c || !s || !repl) return false;
    Method m = class_getInstanceMethod(c, s);
    if (!m) m = class_getClassMethod(c, s);
    if (!m) return false;

    IMP orig = method_getImplementation(m);
    if (!orig || orig == repl) return false;

    pthread_mutex_lock(&g_hooks_lock);
    if (g_hooks_len >= g_hooks_cap) {
        size_t nc = g_hooks_cap ? g_hooks_cap * 2 : 64;
        SBXK_Hook_t *nh = (SBXK_Hook_t *)realloc(g_hooks, nc * sizeof(SBXK_Hook_t));
        if (!nh) { pthread_mutex_unlock(&g_hooks_lock); return false; }
        g_hooks = nh; g_hooks_cap = nc;
    }
    g_hooks[g_hooks_len++] = (SBXK_Hook_t){ c, s, orig, repl, m, true };
    pthread_mutex_unlock(&g_hooks_lock);

    method_setImplementation(m, repl);
    return true;
}

static void SBXK_hooks_rollback(void) {
    pthread_mutex_lock(&g_hooks_lock);
    for (size_t i = 0; i < g_hooks_len; i++) {
        if (g_hooks[i].installed && g_hooks[i].m)
            method_setImplementation(g_hooks[i].m, g_hooks[i].orig);
        g_hooks[i].installed = false;
    }
    pthread_mutex_unlock(&g_hooks_lock);
}

// ★ FIX: stringify cls dan name lewat # supaya jadi string literal.
#define HK_B(cls, name)   SBXK_hook_add(objc_getClass(#cls), sel_registerName(#name), (IMP)SBXK_##cls##_##name)

// ============================================================================
// §2 SBXK_HookEngine — Inline hooking (prologue-aware + RW→RX + MAP_JIT)
// ============================================================================

// §2.1 Prologue parser
static int SBXK_prologue_end(const uint32_t *insn, int max_insn) {
    int i = 0;
    while (i < max_insn) {
        uint32_t v = insn[i];
        // PACIASP / PACIBSP
        if ((v & 0xFFFFFF1F) == 0xD503233F) { i++; continue; }
        // STP X29, X30, [SP, #imm]! (pre-index)
        if ((v & 0xFFC003E0) == 0xA98003E0) { i++; continue; }
        // STP X29, X30, [SP, #imm]  (signed offset)
        if ((v & 0xFFC003E0) == 0xA90003E0) { i++; continue; }
        // SUB SP, SP, #imm
        if ((v & 0xFF8003FF) == 0xD10003FF) { i++; continue; }
        // MOV X29, SP
        if (v == 0x910003FD)                { i++; continue; }
        // MOV X29, X29 (PAC)
        if (v == 0xAA1D03FD)                { i++; continue; }
        // NOP
        if (v == 0xD503201F)                { i++; continue; }
        // BTI c
        if ((v & 0xFFFFFF1F) == 0xD503245F) { i++; continue; }
        break;
    }
    return i;
}

// §2.2 Trampoline registry
typedef struct {
    void   *target;
    void   *handler;
    void   *trampoline;
    void   *page;
    size_t  page_sz;
    size_t  offset;
    bool    installed;
} SBXK_Tramp_t;

static SBXK_Tramp_t *g_tramps = NULL;
static size_t g_tramps_cap = 0;
static size_t g_tramps_len = 0;
static pthread_mutex_t g_tramps_lock = PTHREAD_MUTEX_INITIALIZER;

// §2.3 JIT support detection
#if defined(__arm64e__)
#define SBXK_HAS_JIT 1
#else
#define SBXK_HAS_JIT 0
#endif

extern int  pthread_jit_write_protect_supported_np(void);
extern void pthread_jit_write_protect_np(int enabled);

static bool g_jit_supported = false;

static void SBXK_detect_jit(void) {
#if SBXK_HAS_JIT
    g_jit_supported = pthread_jit_write_protect_supported_np() != 0;
#else
    g_jit_supported = false;
#endif
}

// §2.4 Page allocation (RW → RX)
static void *SBXK_alloc_page(size_t sz, bool exec_after) {
    size_t pg = vm_page_size;
    size_t total = ((sz + pg - 1) / pg) * pg;

    int flags = MAP_PRIVATE | MAP_ANON;
#if SBXK_HAS_JIT
    if (g_jit_supported && exec_after) flags |= MAP_JIT;
#endif

    void *p = mmap(NULL, total, PROT_READ | PROT_WRITE, flags, -1, 0);
    if (p == MAP_FAILED) return NULL;
    return p;
}

static bool SBXK_page_seal_rx(void *p, size_t sz) {
    size_t pg = vm_page_size;
    uintptr_t base = (uintptr_t)p & ~(pg - 1);
    size_t total = ((sz + pg - 1) / pg) * pg + ((uintptr_t)p - base);

#if SBXK_HAS_JIT
    if (g_jit_supported) {
        pthread_jit_write_protect_np(1);  // disable write, enable exec
        return true;
    }
#endif

    kern_return_t kr = vm_protect(mach_task_self_, base, total,
                                  false, VM_PROT_READ | VM_PROT_EXECUTE);
    return kr == KERN_SUCCESS;
}

// §2.5 Write jump at offset
static bool SBXK_write_jump_at(void *target, size_t offset, void *dest) {
    size_t pg = vm_page_size;
    uintptr_t addr = (uintptr_t)target + offset;
    uintptr_t base = addr & ~(pg - 1);

    kern_return_t kr = vm_protect(mach_task_self_, base, pg, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) return false;

    uint32_t insn[4];
    insn[0] = 0x58000050;   // LDR X16, #8
    insn[1] = 0xD61F0200;   // BR X16
    insn[2] = (uint32_t)((uintptr_t)dest & 0xFFFFFFFF);
    insn[3] = (uint32_t)(((uintptr_t)dest >> 32) & 0xFFFFFFFF);
    memcpy((void *)addr, insn, sizeof(insn));

    __builtin___clear_cache((char *)addr, (char *)addr + sizeof(insn));

    vm_protect(mach_task_self_, base, pg, false, VM_PROT_READ | VM_PROT_EXECUTE);
    return true;
}

// §2.6 Install trampoline
static bool SBXK_tramp_install(void *target, void *handler) {
    if (!target || !handler) return false;

    uint32_t head[8];
    memcpy(head, target, sizeof(head));
    int pro_insn = SBXK_prologue_end(head, 8);
    size_t offset = (size_t)pro_insn * 4;

    if (offset == 0) return false;
    if (offset > 16) return false;

    vm_region_basic_info_data_64_t info;
    vm_size_t info_sz = sizeof(info);
    mach_port_t obj_name = MACH_PORT_NULL;
    vm_address_t region_addr = (vm_address_t)target & ~(vm_page_size - 1);
    vm_size_t region_sz = 0;
    kern_return_t kr = vm_region_64(mach_task_self_, &region_addr, &region_sz,
                                    VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info,
                                    &info_sz, &obj_name);
    if (obj_name != MACH_PORT_NULL) mach_port_deallocate(mach_task_self_, obj_name);
    if (kr != KERN_SUCCESS) return false;
    if (!(info.protection & VM_PROT_EXECUTE)) return false;

    uint8_t saved[16];
    memcpy(saved, (uint8_t *)target + offset, 16);

    size_t tramp_sz = 32;
    void *tramp = SBXK_alloc_page(tramp_sz, true);
    if (!tramp) return false;

#if SBXK_HAS_JIT
    if (g_jit_supported) pthread_jit_write_protect_np(0);
#endif

    uint8_t *tp = (uint8_t *)tramp;
    memcpy(tp, saved, 16);

    uint32_t jmp[4];
    jmp[0] = 0x58000050;
    jmp[1] = 0xD61F0200;
    void *resume = (void *)((uintptr_t)target + offset + 16);
    jmp[2] = (uint32_t)((uintptr_t)resume & 0xFFFFFFFF);
    jmp[3] = (uint32_t)(((uintptr_t)resume >> 32) & 0xFFFFFFFF);
    memcpy(tp + 16, jmp, 16);

    __builtin___clear_cache((char *)tramp, (char *)tramp + tramp_sz);

    if (!SBXK_page_seal_rx(tramp, tramp_sz)) {
        munmap(tramp, ((tramp_sz + vm_page_size - 1) / vm_page_size) * vm_page_size);
        return false;
    }

    if (!SBXK_write_jump_at(target, offset, handler)) {
        munmap(tramp, ((tramp_sz + vm_page_size - 1) / vm_page_size) * vm_page_size);
        return false;
    }

    pthread_mutex_lock(&g_tramps_lock);
    if (g_tramps_len >= g_tramps_cap) {
        size_t nc = g_tramps_cap ? g_tramps_cap * 2 : 32;
        SBXK_Tramp_t *nt = (SBXK_Tramp_t *)realloc(g_tramps, nc * sizeof(SBXK_Tramp_t));
        if (!nt) { pthread_mutex_unlock(&g_tramps_lock); return false; }
        g_tramps = nt; g_tramps_cap = nc;
    }
    g_tramps[g_tramps_len++] = (SBXK_Tramp_t){
        .target = target, .handler = handler, .trampoline = tramp,
        .page = tramp, .page_sz = tramp_sz, .offset = offset, .installed = true
    };
    pthread_mutex_unlock(&g_tramps_lock);

    return true;
}

static void *SBXK_tramp_orig(void *target) {
    pthread_mutex_lock(&g_tramps_lock);
    void *orig = NULL;
    for (size_t i = 0; i < g_tramps_len; i++) {
        if (g_tramps[i].target == target && g_tramps[i].installed) {
            orig = g_tramps[i].trampoline; break;
        }
    }
    pthread_mutex_unlock(&g_tramps_lock);
    return orig;
}

// ============================================================================
// §3 SBXK_GOTFallback — fishhook
// ============================================================================

struct sbxk_rb { const char *name; void *repl; void **replaced; };

static int SBXK_fh_image(const struct mach_header *mh, intptr_t slide,
                         struct sbxk_rb *b, int nb) {
    if (mh->magic != MH_MAGIC_64) return 0;
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
                if (ft != S_LAZY_SYMBOL_POINTERS &&
                    ft != S_NON_LAZY_SYMBOL_POINTERS) continue;
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
                        if (b[x].replaced && *b[x].replaced == NULL) *b[x].replaced = *slot;
                        uintptr_t pg = (uintptr_t)slot & ~(vm_page_size - 1);
                        vm_protect(mach_task_self_, pg, vm_page_size, false,
                                   VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
                        *slot = b[x].repl;
                        vm_protect(mach_task_self_, pg, vm_page_size, false, VM_PROT_READ);
                        done++;
                    }
                }
            }
        }
        lc = (const struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return done;
}

static int SBXK_fishhook(struct sbxk_rb *b, int nb) {
    int t = 0;
    uint32_t c = _dyld_image_count();
    for (uint32_t i = 0; i < c; i++) {
        const struct mach_header *mh = _dyld_get_image_header(i);
        if (!mh) continue;
        intptr_t sl = _dyld_get_image_vmaddr_slide(i);
        t += SBXK_fh_image(mh, sl, b, nb);
    }
    return t;
}

// ============================================================================
// §4 SBXK_StringShield — Caller-side filtering (recursion-safe)
// ============================================================================

static const char *g_sbxk_blacklist[] = {
    "ShadowBypassXK", "ShadowBypass", "sbxk_", "SBXK_",
    "substrate", "Substrate", "substitute", "Substitute",
    "frida", "Frida", "cydia", "Cydia", "sileo", "Sileo",
    "ellekit", "ElleKit", "libhooker", "Libhooker",
    "tweakinject", "TweakInject",
    "anogs_hook", "AnoSDK_", "CheckSymbolSource",
    "Px_GetQJS", "WGGetHostByName",
    "ilc_open_pipe", "ilc_recv_pipe",
    NULL
};

static __thread int g_in_string_hook = 0;

static bool SBXK_has_blacklisted(const char *buf, size_t len) {
    if (!buf || !len) return false;
    if (len > 4096) return false;
    for (int i = 0; g_sbxk_blacklist[i]; i++) {
        size_t sl = strlen(g_sbxk_blacklist[i]);
        if (sl > len) continue;
        for (size_t p = 0; p + sl <= len; p++) {
            if (memcmp(buf + p, g_sbxk_blacklist[i], sl) == 0) return true;
        }
    }
    return false;
}

// --- strstr ---
typedef char *(*strstr_t)(const char *, const char *);
static strstr_t orig_strstr;

static char *SBXK_strstr(const char *h, const char *n) {
    if (g_in_string_hook) return orig_strstr ? orig_strstr(h, n) : NULL;
    if (!h || !n) return NULL;
    g_in_string_hook++;
    bool bad = SBXK_has_blacklisted(h, strlen(h)) ||
               SBXK_has_blacklisted(n, strlen(n));
    g_in_string_hook--;
    if (bad) return NULL;
    return orig_strstr ? orig_strstr(h, n) : NULL;
}

// --- strcasestr ---
typedef char *(*strcasestr_t)(const char *, const char *);
static strcasestr_t orig_strcasestr;

static char *SBXK_strcasestr(const char *h, const char *n) {
    if (g_in_string_hook) return orig_strcasestr ? orig_strcasestr(h, n) : NULL;
    if (!h || !n) return NULL;
    g_in_string_hook++;
    bool bad = SBXK_has_blacklisted(h, strlen(h)) ||
               SBXK_has_blacklisted(n, strlen(n));
    g_in_string_hook--;
    if (bad) return NULL;
    return orig_strcasestr ? orig_strcasestr(h, n) : NULL;
}

// --- strcmp ---
typedef int (*strcmp_t)(const char *, const char *);
static strcmp_t orig_strcmp;

static int SBXK_strcmp(const char *a, const char *b) {
    if (g_in_string_hook) return orig_strcmp ? orig_strcmp(a, b) : 0;
    if (!a || !b) return a ? 1 : (b ? -1 : 0);
    g_in_string_hook++;
    bool bad = SBXK_has_blacklisted(a, strlen(a)) ||
               SBXK_has_blacklisted(b, strlen(b));
    g_in_string_hook--;
    if (bad) return 1;
    return orig_strcmp ? orig_strcmp(a, b) : 0;
}

// --- strncmp ---
typedef int (*strncmp_t)(const char *, const char *, size_t);
static strncmp_t orig_strncmp;

static int SBXK_strncmp(const char *a, const char *b, size_t n) {
    if (g_in_string_hook) return orig_strncmp ? orig_strncmp(a, b, n) : 0;
    if (!a || !b) return a ? 1 : (b ? -1 : 0);
    g_in_string_hook++;
    bool bad = SBXK_has_blacklisted(a, strnlen(a, n)) ||
               SBXK_has_blacklisted(b, strnlen(b, n));
    g_in_string_hook--;
    if (bad) return 1;
    return orig_strncmp ? orig_strncmp(a, b, n) : 0;
}

// --- memmem ---
typedef void *(*memmem_t)(const void *, size_t, const void *, size_t);
static memmem_t orig_memmem;

static void *SBXK_memmem(const void *h, size_t hl, const void *n, size_t nl) {
    if (g_in_string_hook) return orig_memmem ? orig_memmem(h, hl, n, nl) : NULL;
    if (!h || !n) return NULL;
    g_in_string_hook++;
    bool bad = SBXK_has_blacklisted((const char *)h, hl) ||
               SBXK_has_blacklisted((const char *)n, nl);
    g_in_string_hook--;
    if (bad) return NULL;
    return orig_memmem ? orig_memmem(h, hl, n, nl) : NULL;
}

// --- NSString containsString: ---
static __thread int g_in_nsstring_hook = 0;

static BOOL SBXK_NSString_containsString(id self, SEL _c, NSString *sub) {
    if (g_in_nsstring_hook) return NO;
    NSString *s = (NSString *)self;
    if (!s || !sub) return NO;

    g_in_nsstring_hook++;
    const char *cs = s.UTF8String;
    const char *cn = sub.UTF8String;
    bool bad = (cs && SBXK_has_blacklisted(cs, strlen(cs))) ||
               (cn && SBXK_has_blacklisted(cn, strlen(cn)));
    g_in_nsstring_hook--;

    if (bad) return NO;

    Method m = class_getInstanceMethod([NSString class], @selector(containsString:));
    if (!m) return NO;
    IMP orig = method_getImplementation(m);
    BOOL (*fn)(id, SEL, NSString *) = (void *)orig;
    return fn(self, _c, sub);
}

// ============================================================================
// §5 SBXK_BehaviorMimic — Kernel API emulation
// ============================================================================

typedef kern_return_t (*vm_read_overwrite_t)(vm_map_t, vm_address_t, vm_size_t,
                                              vm_address_t, vm_size_t *);
typedef kern_return_t (*task_get_exception_ports_t)(task_t, exception_mask_t,
                                                    exception_mask_array_t,
                                                    mach_msg_type_number_t *,
                                                    exception_handler_array_t,
                                                    exception_behavior_array_t,
                                                    exception_flavor_array_t);
typedef kern_return_t (*thread_get_exception_ports_t)(thread_act_t,
                                                      exception_mask_t,
                                                      exception_mask_array_t,
                                                      mach_msg_type_number_t *,
                                                      exception_handler_array_t,
                                                      exception_behavior_array_t,
                                                      exception_flavor_array_t);

static vm_read_overwrite_t          orig_vm_read_overwrite;
static task_get_exception_ports_t   orig_task_get_exp;
static thread_get_exception_ports_t orig_thread_get_exp;

static kern_return_t SBXK_vm_read_overwrite(vm_map_t t, vm_address_t a, vm_size_t s,
                                            vm_address_t d, vm_size_t *o) {
    if (!orig_vm_read_overwrite) return KERN_FAILURE;

    pthread_mutex_lock(&g_tramps_lock);
    for (size_t i = 0; i < g_tramps_len; i++) {
        SBXK_Tramp_t *tr = &g_tramps[i];
        uintptr_t ta = (uintptr_t)tr->target;
        if (a >= ta && a < ta + 64) {
            pthread_mutex_unlock(&g_tramps_lock);
            if (o) *o = 0;
            return KERN_SUCCESS;
        }
    }
    pthread_mutex_unlock(&g_tramps_lock);

    return orig_vm_read_overwrite(t, a, s, d, o);
}

static kern_return_t SBXK_task_get_exp(task_t t, exception_mask_t m,
                                       exception_mask_array_t ma,
                                       mach_msg_type_number_t *mc,
                                       exception_handler_array_t ha,
                                       exception_behavior_array_t ba,
                                       exception_flavor_array_t fa) {
    if (!orig_task_get_exp) return KERN_FAILURE;
    kern_return_t kr = orig_task_get_exp(t, m, ma, mc, ha, ba, fa);
    if (kr != KERN_SUCCESS || !mc || !ma) return kr;
    for (mach_msg_type_number_t i = 0; i < *mc; i++)
        ma[i] &= ~EXC_MASK_BREAKPOINT;
    return kr;
}

static kern_return_t SBXK_thread_get_exp(thread_act_t t, exception_mask_t m,
                                         exception_mask_array_t ma,
                                         mach_msg_type_number_t *mc,
                                         exception_handler_array_t ha,
                                         exception_behavior_array_t ba,
                                         exception_flavor_array_t fa) {
    if (!orig_thread_get_exp) return KERN_FAILURE;
    kern_return_t kr = orig_thread_get_exp(t, m, ma, mc, ha, ba, fa);
    if (kr != KERN_SUCCESS || !mc || !ma) return kr;
    for (mach_msg_type_number_t i = 0; i < *mc; i++)
        ma[i] &= ~EXC_MASK_BREAKPOINT;
    return kr;
}

// ============================================================================
// §6 SBXK_TargetRegistry — All detection handlers
// ============================================================================

// --- AnoSDK ---
typedef int (*AnoSDKInit_t)(const char *);
typedef int (*AnoSDKSetUserInfo_t)(const char *);
typedef void *(*AnoSDKGetData_t)(int);
typedef void *(*AnoSDKGetData2_t)(int, int);
typedef int (*AnoSDKDel_t)(void *);
typedef int (*AnoSDKIoctl_t)(int, const char *, char *, size_t);
typedef int (*AnoSDKPause_t)(void);
typedef int (*AnoSDKRecv_t)(const void *, size_t);
typedef int (*CheckSym_t)(void);

static AnoSDKInit_t         orig_AnoSDKInit;
static AnoSDKSetUserInfo_t  orig_AnoSDKSetUserInfo;
static AnoSDKGetData_t      orig_AnoSDKGetData;
static AnoSDKGetData2_t     orig_AnoSDKGetData2;
static AnoSDKDel_t          orig_AnoSDKDel;
static AnoSDKIoctl_t        orig_AnoSDKIoctl;
static AnoSDKPause_t        orig_AnoSDKPause;
static AnoSDKPause_t        orig_AnoSDKResume;
static AnoSDKRecv_t         orig_AnoSDKRecvD;
static AnoSDKRecv_t         orig_AnoSDKRecvS;
static CheckSym_t           orig_CheckSym;

static int SBXK_AnoInit(const char *p){(void)p;return 0;}
static int SBXK_AnoUser(const char *p){(void)p;return 0;}
static void *SBXK_AnoData(int a){(void)a;return NULL;}
static void *SBXK_AnoData2(int a,int b){(void)a;(void)b;return NULL;}
static int SBXK_AnoDel(void *p){(void)p;return 0;}
static int SBXK_AnoIoctl(int a,const char *i,char *o,size_t n){(void)a;(void)i;(void)o;(void)n;return 0;}
static int SBXK_AnoPause(void){return 0;}
static int SBXK_AnoRecv(const void *d,size_t n){(void)d;(void)n;return 0;}
static int SBXK_CheckSym(void){return 0;}

// --- UQM ---
typedef int (*UQMCrash_Init_t)(void*,int,int,void*);
typedef int (*UQMCrash_Str_t)(void*);
typedef int (*UQMCrash_Log_t)(int,void*,void*);
typedef int (*UQMCrash_Rpt_t)(void*,int,void*,void*,void*,void*,void*,int);
typedef int (*UQM_SetObserver_t)(void*,void*);
typedef int (*UQM_ConfigTimeout_t)(int);

static UQMCrash_Init_t      orig_UQMInit;
static UQMCrash_Str_t       orig_UQMUser;
static UQMCrash_Str_t       orig_UQMApp;
static UQMCrash_Log_t       orig_UQMLog;
static UQMCrash_Str_t       orig_UQMSetUser;
static UQMCrash_Rpt_t       orig_UQMRpt;
static UQM_SetObserver_t    orig_UQMSetCrashObs;
static UQM_SetObserver_t    orig_UQMSetLogObs;
static UQM_ConfigTimeout_t  orig_UQMConfigTimeout;

static int SBXK_UQMInit(void*a,int b,int c,void*d){(void)a;(void)b;(void)c;(void)d;return 0;}
static int SBXK_UQMUser(void*a){(void)a;return 0;}
static int SBXK_UQMApp(void*a){(void)a;return 0;}
static int SBXK_UQMLog(int a,void*b,void*c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_UQMSetUser(void*a,void*b){(void)a;(void)b;return 0;}
static int SBXK_UQMRpt(void*a,int b,void*c,void*d,void*e,void*f,void*g,int h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return 0;}
static int SBXK_UQMSetCrashObs(void*s,void*o){(void)s;(void)o;return 0;}
static int SBXK_UQMSetLogObs(void*s,void*o){(void)s;(void)o;return 0;}
static int SBXK_UQMConfigTimeout(int t){(void)t;return 0;}

// --- CrashSight ---
typedef int  (*CS_RptStuck_t)(void*,int,int,long,const char*,const char*,const char*,int,const char*);
typedef int  (*CS_RptErr_t)(void*,int,const char*,const char*,const char*,const char*,int,const char*);
typedef int  (*CS_RptLog_t)(void*,const char*,const char*);
typedef int  (*CS_LastUser_t)(void*,void*,int);
typedef void (*CS_TestOom_t)(void*);
typedef long (*CS_GetCrashTid_t)(void*);
typedef int  (*CS_IsLastCrash_t)(void*);
typedef void (*CS_SetUpload_t)(void*,int);
typedef void (*CS_ConfigRep_t)(void*,int);
typedef void (*CS_SetCatch_t)(void*,int);

static CS_RptStuck_t     orig_CSStuck;
static CS_RptErr_t       orig_CSErr;
static CS_RptLog_t       orig_CSLog;
static CS_LastUser_t     orig_CSLast;
static CS_TestOom_t      orig_CSTestOom;
static CS_GetCrashTid_t  orig_CSGetCrashTid;
static CS_IsLastCrash_t  orig_CSIsLastCrash;
static CS_SetUpload_t    orig_CSSetUpload;
static CS_ConfigRep_t    orig_CSConfigRep;
static CS_SetCatch_t     orig_CSSetCatch;

static int SBXK_CSStuck(void*a,int b,int c,long d,const char*e,const char*f,const char*g,int h,const char*i){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;(void)i;return 0;}
static int SBXK_CSErr(void*a,int b,const char*c,const char*d,const char*e,const char*f,int g,const char*h){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;(void)h;return 0;}
static int SBXK_CSLog(void*a,const char*b,const char*c){(void)a;(void)b;(void)c;return 0;}
static int SBXK_CSLast(void*a,void*b,int c){(void)a;(void)b;(void)c;return 0;}
static void SBXK_CSTestOom(void*s){(void)s;}
static long SBXK_CSGetCrashTid(void*s){(void)s;return 0;}
static int  SBXK_CSIsLastCrash(void*s){(void)s;return 0;}
static void SBXK_CSSetUpload(void*s,int n){(void)s;(void)n;}
static void SBXK_CSConfigRep(void*s,int n){(void)s;(void)n;}
static void SBXK_CSSetCatch(void*s,int b){(void)s;(void)b;}

// --- Cros/QJS ---
typedef void *(*Px_GetQJS_t)(void);
static Px_GetQJS_t orig_PxGetQJS;
static void *SBXK_PxGetQJS(void){ return NULL; }

// --- ObjC Handlers ---
#define DEF_NO(cls, name)  static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return NO; }
#define DEF_YES(cls, name) static BOOL SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return YES; }
#define DEF_V1(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1) { (void)_s;(void)_c;(void)_a1; }
#define DEF_V2(cls, name)  static void SBXK_##cls##_##name(id _s, SEL _c, id _a1, id _a2) { (void)_s;(void)_c;(void)_a1;(void)_a2; }
#define DEF_ID_P0(cls, name) static id SBXK_##cls##_##name(id _s, SEL _c) { (void)_s;(void)_c; return nil; }

DEF_NO(AntiDataProxy, checkIntegrity)
DEF_NO(AntiDataProxy, isIntegrityOK)
DEF_NO(AntiDataProxy, verifyData)
DEF_NO(AntiDataProxy, isDataValid)
DEF_NO(AntiDataProxy, isModified)
DEF_NO(AntiDataProxy, isCheat)
DEF_NO(AntiDataProxy, isSuspicious)
DEF_NO(AntiDataProxy, antiCheatCheck)
DEF_NO(AntiDataProxy, securityCheck)
DEF_NO(AntiDataProxy, hasRisk)
DEF_NO(AntiDataProxy, detectRisk)
DEF_NO(AntiDataProxy, isRiskDetected)
DEF_YES(AntiDataProxy, isValid)
DEF_YES(AntiDataProxy, isSafe)
DEF_YES(AntiDataProxy, isClean)
DEF_YES(AntiDataProxy, verifyIntegrity)
DEF_YES(AntiDataProxy, verifySignature)
DEF_YES(AntiDataProxy, shouldPass)
DEF_YES(AntiDataProxy, allowReport)
DEF_V1(AntiDataProxy, sendData)
DEF_V1(AntiDataProxy, report)
DEF_V1(AntiDataProxy, submit)
DEF_V1(AntiDataProxy, upload)
DEF_V1(AntiDataProxy, dispatch)
DEF_V1(AntiDataProxy, flush)

DEF_NO(TssInfoReceiver, isRooted)
DEF_NO(TssInfoReceiver, isRootedDevice)
DEF_NO(TssInfoReceiver, isJailbroken)
DEF_NO(TssInfoReceiver, isJailbreakDevice)
DEF_NO(TssInfoReceiver, isEmulator)
DEF_NO(TssInfoReceiver, isEmulatorDevice)
DEF_NO(TssInfoReceiver, isSimulator)
DEF_NO(TssInfoReceiver, isDebuggerAttached)
DEF_NO(TssInfoReceiver, isDebugged)
DEF_NO(TssInfoReceiver, isModified)
DEF_NO(TssInfoReceiver, isTampered)
DEF_NO(TssInfoReceiver, isInjected)
DEF_NO(TssInfoReceiver, isHooked)
DEF_NO(TssInfoReceiver, hasCheat)
DEF_NO(TssInfoReceiver, hasCheatTool)
DEF_NO(TssInfoReceiver, hasSuspiciousFiles)
DEF_NO(TssInfoReceiver, hasRisk)
DEF_NO(TssInfoReceiver, checkEnvironment)
DEF_NO(TssInfoReceiver, checkSecurity)
DEF_NO(TssInfoReceiver, checkCheat)
DEF_NO(TssInfoReceiver, detectCheat)
DEF_NO(TssInfoReceiver, detectRisk)
DEF_NO(TssInfoReceiver, detectEnvironment)
DEF_NO(TssInfoReceiver, isCheating)
DEF_NO(TssInfoReceiver, isCheatDetected)
DEF_NO(TssInfoReceiver, isSuspicious)
DEF_NO(TssInfoReceiver, antiCheatCheck)
DEF_NO(TssInfoReceiver, securityCheck)
DEF_NO(TssInfoReceiver, shouldReport)
DEF_NO(TssInfoReceiver, shouldBlock)
DEF_NO(TssInfoReceiver, needReport)
DEF_NO(TssInfoReceiver, needBlock)
DEF_NO(TssInfoReceiver, isBlocked)
DEF_NO(TssInfoReceiver, isBanned)
DEF_YES(TssInfoReceiver, isSafe)
DEF_YES(TssInfoReceiver, isClean)
DEF_YES(TssInfoReceiver, isEnvironmentClean)
DEF_YES(TssInfoReceiver, isEnvironmentSafe)
DEF_YES(TssInfoReceiver, verifyIntegrity)
DEF_YES(TssInfoReceiver, verifySignature)
DEF_YES(TssInfoReceiver, checkTokenValid)
DEF_V1(TssInfoReceiver, start)
DEF_V1(TssInfoReceiver, stop)
DEF_V1(TssInfoReceiver, run)
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

DEF_NO(CheckSymbolSource, CheckSymbol)
DEF_NO(CheckSymbolSource, checkSymbol)
DEF_NO(CheckSymbolSource, checkSymbolSource)
DEF_NO(CheckSymbolSource, isSymbolValid)
DEF_NO(CheckSymbolSource, isSymbolOK)
DEF_NO(CheckSymbolSource, verifySymbol)
DEF_NO(CheckSymbolSource, verifySymbols)
DEF_NO(CheckSymbolSource, isSourceSafe)
DEF_NO(CheckSymbolSource, checkSource)
DEF_YES(CheckSymbolSource, isSourceOK)
DEF_YES(CheckSymbolSource, sourceIsValid)

DEF_NO(CFastScanThread, isRunning)
DEF_NO(CFastScanThread, shouldScan)
DEF_NO(CFastScanThread, hasResult)
DEF_NO(CScanThread, isRunning)
DEF_NO(CScanThread, shouldScan)
DEF_NO(CScanThread, hasResult)
DEF_NO(CSendThread, isRunning)
DEF_NO(CSendThread, shouldSend)
DEF_NO(CSendThread, hasData)
DEF_NO(CMrpcsMonitor, isRunning)
DEF_NO(CMrpcsMonitor, shouldReport)
DEF_NO(CMrpcsMgrE, isReady)
DEF_NO(CMrpcsMgrE, shouldReport)
DEF_NO(CPointDataMgr, shouldReport)
DEF_NO(CPointDataMgr, hasData)
DEF_NO(CPointGlobalMgr, shouldReport)
DEF_NO(CPointGlobalMgr, hasData)
DEF_NO(CMrpcsLFUpdater, shouldUpdate)
DEF_NO(CMrpcsLFUpdater, hasUpdate)
DEF_V1(CFastScanThread, start)
DEF_V1(CFastScanThread, run)
DEF_V1(CFastScanThread, execute)
DEF_V1(CScanThread, start)
DEF_V1(CScanThread, run)
DEF_V1(CScanThread, execute)
DEF_V1(CSendThread, start)
DEF_V1(CSendThread, run)
DEF_V1(CSendThread, execute)
DEF_V1(CMrpcsMonitor, start)
DEF_V1(CMrpcsMonitor, stop)
DEF_V1(CMrpcsMonitor, run)
DEF_V1(CMrpcsMonitor, execute)
DEF_V1(CMrpcsMgrE, sendScanResult)
DEF_V1(CMrpcsMgrE, reportResult)
DEF_V1(CPointDataMgr, report)
DEF_V1(CPointDataMgr, sendData)
DEF_V1(CPointGlobalMgr, report)
DEF_V1(CPointGlobalMgr, sendReport)
DEF_V1(CMrpcsLFUpdater, update)
DEF_V1(CMrpcsLFUpdater, start)
DEF_V1(CMrpcsLFUpdater, run)

DEF_NO(IntegrityChecker, integrity_detect)
DEF_NO(IntegrityChecker, MTML_INTEGRITY_DETECT)
DEF_NO(JailbreakDetector, isJailbroken)
DEF_NO(JailbreakDetector, isJailbreak)
DEF_NO(JailbreakDetector, checkJailbreak)
DEF_NO(JailbreakDetector, jailbreakDetection)
DEF_NO(SimulatorDetector, isSimulator)
DEF_NO(SimulatorDetector, isSimulatorDevice)
DEF_NO(SimulatorDetector, checkSimulator)
DEF_NO(SecurityChecker, IsFileSystemModified)
DEF_NO(SecurityChecker, isDebuggerAttached)
DEF_NO(SecurityChecker, isDebugged)
DEF_NO(SecurityChecker, checkDebugger)
DEF_NO(SecurityChecker, amIBeingDebugged)
DEF_NO(SecurityChecker, isHooked)
DEF_NO(SecurityChecker, isHookDetected)
DEF_NO(SecurityChecker, checkHook)
DEF_NO(SecurityChecker, detectHook)
DEF_NO(SecurityChecker, antiHookCheck)
DEF_NO(SecurityChecker, isTampered)
DEF_NO(SecurityChecker, checkTamper)
DEF_NO(SecurityChecker, antiTamperCheck)
DEF_NO(SecurityChecker, isInjected)
DEF_NO(SecurityChecker, isLibraryInjected)
DEF_NO(SecurityChecker, checkInjection)
DEF_NO(SecurityChecker, antiInjectionCheck)
DEF_NO(SecurityChecker, isReversingDetected)
DEF_NO(SecurityChecker, checkReversing)
DEF_NO(SecurityChecker, antiReversingCheck)
DEF_NO(SecurityChecker, isBlocked)
DEF_NO(SecurityChecker, antiBlockingCheck)
DEF_NO(SecurityChecker, isVPNUsed)
DEF_NO(SecurityChecker, isProxyUsed)
DEF_NO(SecurityChecker, isFridaRunning)
DEF_NO(SecurityChecker, isSubstrateLoaded)
DEF_NO(SecurityChecker, isCydiaInstalled)
DEF_NO(SecurityChecker, hasSuspiciousFiles)
DEF_NO(SecurityChecker, isEnvironmentClean)
DEF_YES(SecurityChecker, verifyIntegrity)
DEF_YES(SecurityChecker, checkTokenValid)
DEF_YES(SecurityChecker, isEnvironmentSafe)
DEF_YES(SecurityChecker, verifySignature)

DEF_NO(SBXK_FridaDet, isFridaPresent)
DEF_NO(SBXK_FridaDet, isFridaRunning)
DEF_NO(SBXK_FridaDet, hasFrida)
DEF_NO(SBXK_FridaDet, checkFrida)
DEF_NO(SBXK_FridaDet, detectFrida)
DEF_NO(SBXK_SubDet, isSubstrateLoaded)
DEF_NO(SBXK_SubDet, hasSubstrate)
DEF_NO(SBXK_SubDet, checkSubstrate)
DEF_NO(SBXK_SubDet, isCydiaSubstrateLoaded)
DEF_NO(SBXK_InjectDet, isDylibInjected)
DEF_NO(SBXK_InjectDet, isImageInjected)
DEF_NO(SBXK_InjectDet, hasInjectedDylib)
DEF_NO(SBXK_InjectDet, isForeignImageLoaded)
DEF_NO(SBXK_InjectDet, hasHooked)
DEF_NO(SBXK_InjectDet, hasMSHook)
DEF_NO(SBXK_InjectDet, hasDYLD_INSERT)
DEF_NO(SBXK_InjectDet, isDYLDInjected)
DEF_NO(SBXK_InjectDet, isAttached)
DEF_NO(SBXK_InjectDet, isBeingDebugged)
DEF_NO(SBXK_InjectDet, isTraced)
DEF_YES(SBXK_InjectDet, isEnvironmentClean)
DEF_YES(SBXK_InjectDet, isEnvironmentSafe)
DEF_YES(SBXK_InjectDet, isClean)
DEF_YES(SBXK_InjectDet, isSafe)
DEF_YES(SBXK_InjectDet, verifyNoInjection)
DEF_YES(SBXK_InjectDet, verifyNoHook)

DEF_ID_P0(ScreenShot, takeScreenShot)
DEF_ID_P0(ScreenShot, screenshot)
DEF_ID_P0(ScreenShot, getAppWindowsForScreen)
DEF_ID_P0(ScreenShot, getBufFromImage)
DEF_ID_P0(Rotate, fixOrientation)
DEF_ID_P0(Rotate, flipVertical)
DEF_ID_P0(Rotate, flipHorizontal)

DEF_V2(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn)
DEF_V1(AceMsgBoxImp, dismiss)
DEF_V1(AceMsgBoxImp, show)

// ============================================================================
// §7 SBXK_Lifecycle — Event-driven cleanup
// ============================================================================

static NSArray<NSString *> *SBXK_kill_paths(void) {
    NSString *h = NSHomeDirectory();
    NSString *d = [h stringByAppendingPathComponent:@"Documents"];
    NSString *l = [h stringByAppendingPathComponent:@"Library"];
    return @[
        [d stringByAppendingPathComponent:@"atsv4.dat"],
        [d stringByAppendingPathComponent:@"attv4.dat"],
        [d stringByAppendingPathComponent:@"a64.dat"],
        [d stringByAppendingPathComponent:@"a64.sig"],
        [d stringByAppendingPathComponent:@"comm.dat"],
        [d stringByAppendingPathComponent:@"comm.zip"],
        [d stringByAppendingPathComponent:@"comm_ver.zip"],
        [d stringByAppendingPathComponent:@"comm_custom.zip"],
        [d stringByAppendingPathComponent:@"bmc.dat"],
        [d stringByAppendingPathComponent:@"mrpcs_abort.dat"],
        [d stringByAppendingPathComponent:@"p_tlc6.d"],
        [d stringByAppendingPathComponent:@"tmp.xx.dat"],
        [d stringByAppendingPathComponent:@"ano_log"],
        [d stringByAppendingPathComponent:@"hash_cache"],
        [d stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/UQMCrash"],
        [d stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/CrashSight"],
        [d stringByAppendingPathComponent:@"ShadowTrackerExtra/Saved/Logs/ano_crash.txt"],
        [l stringByAppendingPathComponent:@"Caches/com.tencent.uqm.crash"],
        [l stringByAppendingPathComponent:@"Caches/com.tencent.gcloud.crashsight"],
    ];
}

static void SBXK_cleanup_now(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSError *e = nil;
    for (NSString *p in SBXK_kill_paths()) {
        if ([fm fileExistsAtPath:p]) [fm removeItemAtPath:p error:&e];
        e = nil;
    }
}

static void SBXK_lifecycle_notif(NSNotification *n) {
    (void)n;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool { SBXK_cleanup_now(); }
    });
}

static void SBXK_lifecycle_install(void) {
    NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
    [nc addObserverForName:UIApplicationDidEnterBackgroundNotification
                    object:nil queue:nil
                usingBlock:^(NSNotification *n){ SBXK_lifecycle_notif(n); }];
    [nc addObserverForName:UIApplicationWillResignActiveNotification
                    object:nil queue:nil
                usingBlock:^(NSNotification *n){ SBXK_lifecycle_notif(n); }];
    [nc addObserverForName:UIApplicationWillTerminateNotification
                    object:nil queue:nil
                usingBlock:^(NSNotification *n){ SBXK_lifecycle_notif(n); }];
}

// ============================================================================
// §8 SBXK_Boot — Entry point
// ============================================================================

static atomic_bool g_installed = false;
static pthread_mutex_t g_install_lock = PTHREAD_MUTEX_INITIALIZER;

static void SBXK_install_fishhook(void) {
    struct sbxk_rb rb[] = {
        // AnoSDK
        { "AnoSDKInit",            (void*)SBXK_AnoInit,  (void**)&orig_AnoSDKInit },
        { "AnoSDKSetUserInfo",     (void*)SBXK_AnoUser,  (void**)&orig_AnoSDKSetUserInfo },
        { "AnoSDKGetReportData",   (void*)SBXK_AnoData,  (void**)&orig_AnoSDKGetData },
        { "AnoSDKGetReportData2",  (void*)SBXK_AnoData2, (void**)&orig_AnoSDKGetData2 },
        { "AnoSDKDelReportData",   (void*)SBXK_AnoDel,   (void**)&orig_AnoSDKDel },
        { "AnoSDKIoctl",           (void*)SBXK_AnoIoctl, (void**)&orig_AnoSDKIoctl },
        { "AnoSDKIoctlOld",        (void*)SBXK_AnoIoctl, (void**)&orig_AnoSDKIoctl },
        { "AnoSDKOnPause",         (void*)SBXK_AnoPause, (void**)&orig_AnoSDKPause },
        { "AnoSDKOnResume",        (void*)SBXK_AnoPause, (void**)&orig_AnoSDKResume },
        { "AnoSDKOnRecvData",      (void*)SBXK_AnoRecv,  (void**)&orig_AnoSDKRecvD },
        { "AnoSDKOnRecvSignature", (void*)SBXK_AnoRecv,  (void**)&orig_AnoSDKRecvS },
        { "CheckSymbolSource",     (void*)SBXK_CheckSym, (void**)&orig_CheckSym },
        // UQM
        { "__ZN3UQM8UQMCrash4InitERKNS_9UQMStringEbbS3_", (void*)SBXK_UQMInit, (void**)&orig_UQMInit },
        { "__ZN3UQM8UQMCrash9SetUserIdERKNS_9UQMStringE", (void*)SBXK_UQMUser, (void**)&orig_UQMUser },
        { "__ZN3UQM8UQMCrash8SetAppIdERKNS_9UQMStringE",  (void*)SBXK_UQMApp,  (void**)&orig_UQMApp },
        { "__ZN3UQM8UQMCrash7LogInfoEiRKNS_9UQMStringES3_", (void*)SBXK_UQMLog, (void**)&orig_UQMLog },
        { "__ZN3UQM8UQMCrash12SetUserValueERKNS_9UQMStringES3_", (void*)SBXK_UQMSetUser, (void**)&orig_UQMSetUser },
        { "__ZN3UQM8UQMCrash18ReportExceptionPRVEiRKNS_9UQMStringES3_S3_RKNS_9UQMVectorINS_9UQMKVPairELj16EEES3_bi",
          (void*)SBXK_UQMRpt, (void**)&orig_UQMRpt },
        { "__ZN3UQM8UQMCrash16SetCrashObserverEPNS_16UQMCrashObserverE", (void*)SBXK_UQMSetCrashObs, (void**)&orig_UQMSetCrashObs },
        { "__ZN3UQM8UQMCrash19SetCrashLogObserverEPNS_19UQMCrashLogObserverE", (void*)SBXK_UQMSetLogObs, (void**)&orig_UQMSetLogObs },
        { "__ZN3UQM8UQMCrash24ConfigCrashHandleTimeoutEi", (void*)SBXK_UQMConfigTimeout, (void**)&orig_UQMConfigTimeout },
        // CrashSight
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent11ReportStuckEiilPKcS3_S3_iS3_", (void*)SBXK_CSStuck, (void**)&orig_CSStuck },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19ReportExceptionJsonEiPKcS3_S3_S3_iS3_", (void*)SBXK_CSErr, (void**)&orig_CSErr },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent13ReportLogInfoEPKcS3_", (void*)SBXK_CSLog, (void**)&orig_CSLog },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent20GetLastSessionUserIdEPvi", (void*)SBXK_CSLast, (void**)&orig_CSLast },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent12TestOomCrashEv", (void*)SBXK_CSTestOom, (void**)&orig_CSTestOom },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent16GetCrashThreadIdEv", (void*)SBXK_CSGetCrashTid, (void**)&orig_CSGetCrashTid },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent18IsLastSessionCrashEv", (void*)SBXK_CSIsLastCrash, (void**)&orig_CSIsLastCrash },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent18SetUploadThreadNumEi", (void*)SBXK_CSSetUpload, (void**)&orig_CSSetUpload },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19ConfigCrashReporterEi", (void*)SBXK_CSConfigRep, (void**)&orig_CSConfigRep },
        { "__ZN6GCloud10CrashSight21CrashSightMobileAgent19SetCatchMultiSignalEb", (void*)SBXK_CSSetCatch, (void**)&orig_CSSetCatch },
        // Cros
        { "Px_GetQJSFunctionTable_V04", (void*)SBXK_PxGetQJS, (void**)&orig_PxGetQJS },
    };
    int t = SBXK_fishhook(rb, (int)(sizeof(rb)/sizeof(rb[0])));
    NSLog(@"[SBXK-v9.0] fishhook: %d / %zu", t, sizeof(rb)/sizeof(rb[0]));
}

static void SBXK_install_string_hooks(void) {
    struct sbxk_rb rb[] = {
        { "strstr",     (void*)SBXK_strstr,     (void**)&orig_strstr },
        { "strcasestr", (void*)SBXK_strcasestr, (void**)&orig_strcasestr },
        { "strcmp",     (void*)SBXK_strcmp,     (void**)&orig_strcmp },
        { "strncmp",    (void*)SBXK_strncmp,    (void**)&orig_strncmp },
        { "memmem",     (void*)SBXK_memmem,     (void**)&orig_memmem },
    };
    SBXK_fishhook(rb, (int)(sizeof(rb)/sizeof(rb[0])));

    Method containsM = class_getInstanceMethod([NSString class], @selector(containsString:));
    if (containsM) method_setImplementation(containsM, (IMP)SBXK_NSString_containsString);
}

static void SBXK_install_trampolines(void) {
    void *targets[] = {
        dlsym(RTLD_DEFAULT, "vm_read_overwrite"),
        dlsym(RTLD_DEFAULT, "task_get_exception_ports"),
        dlsym(RTLD_DEFAULT, "thread_get_exception_ports"),
    };
    void *handlers[] = {
        (void*)SBXK_vm_read_overwrite,
        (void*)SBXK_task_get_exp,
        (void*)SBXK_thread_get_exp,
    };
    for (size_t i = 0; i < sizeof(targets)/sizeof(targets[0]); i++) {
        if (targets[i] && handlers[i]) SBXK_tramp_install(targets[i], handlers[i]);
    }
    if (targets[0]) orig_vm_read_overwrite = (vm_read_overwrite_t)targets[0];
    if (targets[1]) orig_task_get_exp = (task_get_exception_ports_t)targets[1];
    if (targets[2]) orig_thread_get_exp = (thread_get_exception_ports_t)targets[2];
}

static void SBXK_install_objc(void) {
    // AntiDataProxy
    HK_B(AntiDataProxy, checkIntegrity);  HK_B(AntiDataProxy, isIntegrityOK);
    HK_B(AntiDataProxy, verifyData);      HK_B(AntiDataProxy, isDataValid);
    HK_B(AntiDataProxy, isModified);      HK_B(AntiDataProxy, isCheat);
    HK_B(AntiDataProxy, isSuspicious);    HK_B(AntiDataProxy, antiCheatCheck);
    HK_B(AntiDataProxy, securityCheck);   HK_B(AntiDataProxy, hasRisk);
    HK_B(AntiDataProxy, detectRisk);      HK_B(AntiDataProxy, isRiskDetected);
    HK_B(AntiDataProxy, isValid);         HK_B(AntiDataProxy, isSafe);
    HK_B(AntiDataProxy, isClean);         HK_B(AntiDataProxy, verifyIntegrity);
    HK_B(AntiDataProxy, verifySignature); HK_B(AntiDataProxy, shouldPass);
    HK_B(AntiDataProxy, allowReport);     HK_B(AntiDataProxy, sendData);
    HK_B(AntiDataProxy, report);          HK_B(AntiDataProxy, submit);
    HK_B(AntiDataProxy, upload);          HK_B(AntiDataProxy, dispatch);
    HK_B(AntiDataProxy, flush);

    // TssInfoReceiver
    HK_B(TssInfoReceiver, isRooted);      HK_B(TssInfoReceiver, isRootedDevice);
    HK_B(TssInfoReceiver, isJailbroken);  HK_B(TssInfoReceiver, isJailbreakDevice);
    HK_B(TssInfoReceiver, isEmulator);    HK_B(TssInfoReceiver, isEmulatorDevice);
    HK_B(TssInfoReceiver, isSimulator);   HK_B(TssInfoReceiver, isDebuggerAttached);
    HK_B(TssInfoReceiver, isDebugged);    HK_B(TssInfoReceiver, isModified);
    HK_B(TssInfoReceiver, isTampered);    HK_B(TssInfoReceiver, isInjected);
    HK_B(TssInfoReceiver, isHooked);      HK_B(TssInfoReceiver, hasCheat);
    HK_B(TssInfoReceiver, hasCheatTool);  HK_B(TssInfoReceiver, hasSuspiciousFiles);
    HK_B(TssInfoReceiver, hasRisk);       HK_B(TssInfoReceiver, checkEnvironment);
    HK_B(TssInfoReceiver, checkSecurity); HK_B(TssInfoReceiver, checkCheat);
    HK_B(TssInfoReceiver, detectCheat);   HK_B(TssInfoReceiver, detectRisk);
    HK_B(TssInfoReceiver, detectEnvironment); HK_B(TssInfoReceiver, isCheating);
    HK_B(TssInfoReceiver, isCheatDetected); HK_B(TssInfoReceiver, isSuspicious);
    HK_B(TssInfoReceiver, antiCheatCheck); HK_B(TssInfoReceiver, securityCheck);
    HK_B(TssInfoReceiver, shouldReport);  HK_B(TssInfoReceiver, shouldBlock);
    HK_B(TssInfoReceiver, needReport);    HK_B(TssInfoReceiver, needBlock);
    HK_B(TssInfoReceiver, isBlocked);     HK_B(TssInfoReceiver, isBanned);
    HK_B(TssInfoReceiver, isSafe);        HK_B(TssInfoReceiver, isClean);
    HK_B(TssInfoReceiver, isEnvironmentClean); HK_B(TssInfoReceiver, isEnvironmentSafe);
    HK_B(TssInfoReceiver, verifyIntegrity); HK_B(TssInfoReceiver, verifySignature);
    HK_B(TssInfoReceiver, checkTokenValid); HK_B(TssInfoReceiver, start);
    HK_B(TssInfoReceiver, stop);          HK_B(TssInfoReceiver, run);
    HK_B(TssInfoReceiver, report);        HK_B(TssInfoReceiver, sendReport);
    HK_B(TssInfoReceiver, uploadReport);  HK_B(TssInfoReceiver, submitReport);
    HK_B(TssInfoReceiver, reportRoot);    HK_B(TssInfoReceiver, reportEmu);
    HK_B(TssInfoReceiver, reportDebugger); HK_B(TssInfoReceiver, reportCheat);
    HK_B(TssInfoReceiver, reportAlert);   HK_B(TssInfoReceiver, sendAlert);
    HK_B(TssInfoReceiver, blockGame);     HK_B(TssInfoReceiver, blockPlayer);
    HK_B(TssInfoReceiver, kickPlayer);

    // CheckSymbolSource
    HK_B(CheckSymbolSource, CheckSymbol); HK_B(CheckSymbolSource, checkSymbol);
    HK_B(CheckSymbolSource, checkSymbolSource); HK_B(CheckSymbolSource, isSymbolValid);
    HK_B(CheckSymbolSource, isSymbolOK);  HK_B(CheckSymbolSource, verifySymbol);
    HK_B(CheckSymbolSource, verifySymbols); HK_B(CheckSymbolSource, isSourceSafe);
    HK_B(CheckSymbolSource, checkSource); HK_B(CheckSymbolSource, isSourceOK);
    HK_B(CheckSymbolSource, sourceIsValid);

    // Scan threads
    HK_B(CFastScanThread, isRunning); HK_B(CFastScanThread, shouldScan);
    HK_B(CFastScanThread, hasResult); HK_B(CScanThread, isRunning);
    HK_B(CScanThread, shouldScan);    HK_B(CScanThread, hasResult);
    HK_B(CSendThread, isRunning);     HK_B(CSendThread, shouldSend);
    HK_B(CSendThread, hasData);       HK_B(CMrpcsMonitor, isRunning);
    HK_B(CMrpcsMonitor, shouldReport); HK_B(CMrpcsMgrE, isReady);
    HK_B(CMrpcsMgrE, shouldReport);   HK_B(CPointDataMgr, shouldReport);
    HK_B(CPointDataMgr, hasData);     HK_B(CPointGlobalMgr, shouldReport);
    HK_B(CPointGlobalMgr, hasData);   HK_B(CMrpcsLFUpdater, shouldUpdate);
    HK_B(CMrpcsLFUpdater, hasUpdate);
    HK_B(CFastScanThread, start);     HK_B(CFastScanThread, run);
    HK_B(CFastScanThread, execute);   HK_B(CScanThread, start);
    HK_B(CScanThread, run);           HK_B(CScanThread, execute);
    HK_B(CSendThread, start);         HK_B(CSendThread, run);
    HK_B(CSendThread, execute);       HK_B(CMrpcsMonitor, start);
    HK_B(CMrpcsMonitor, stop);        HK_B(CMrpcsMonitor, run);
    HK_B(CMrpcsMonitor, execute);     HK_B(CMrpcsMgrE, sendScanResult);
    HK_B(CMrpcsMgrE, reportResult);   HK_B(CPointDataMgr, report);
    HK_B(CPointDataMgr, sendData);    HK_B(CPointGlobalMgr, report);
    HK_B(CPointGlobalMgr, sendReport); HK_B(CMrpcsLFUpdater, update);
    HK_B(CMrpcsLFUpdater, start);     HK_B(CMrpcsLFUpdater, run);

    // Integrity
    HK_B(IntegrityChecker, integrity_detect);
    HK_B(IntegrityChecker, MTML_INTEGRITY_DETECT);
    HK_B(JailbreakDetector, isJailbroken);
    HK_B(JailbreakDetector, isJailbreak);
    HK_B(JailbreakDetector, checkJailbreak);
    HK_B(JailbreakDetector, jailbreakDetection);
    HK_B(SimulatorDetector, isSimulator);
    HK_B(SimulatorDetector, isSimulatorDevice);
    HK_B(SimulatorDetector, checkSimulator);
    HK_B(SecurityChecker, IsFileSystemModified);
    HK_B(SecurityChecker, isDebuggerAttached);
    HK_B(SecurityChecker, isDebugged);
    HK_B(SecurityChecker, checkDebugger);
    HK_B(SecurityChecker, amIBeingDebugged);
    HK_B(SecurityChecker, isHooked);
    HK_B(SecurityChecker, isHookDetected);
    HK_B(SecurityChecker, checkHook);
    HK_B(SecurityChecker, detectHook);
    HK_B(SecurityChecker, antiHookCheck);
    HK_B(SecurityChecker, isTampered);
    HK_B(SecurityChecker, checkTamper);
    HK_B(SecurityChecker, antiTamperCheck);
    HK_B(SecurityChecker, isInjected);
    HK_B(SecurityChecker, isLibraryInjected);
    HK_B(SecurityChecker, checkInjection);
    HK_B(SecurityChecker, antiInjectionCheck);
    HK_B(SecurityChecker, isReversingDetected);
    HK_B(SecurityChecker, checkReversing);
    HK_B(SecurityChecker, antiReversingCheck);
    HK_B(SecurityChecker, isBlocked);
    HK_B(SecurityChecker, antiBlockingCheck);
    HK_B(SecurityChecker, isVPNUsed);
    HK_B(SecurityChecker, isProxyUsed);
    HK_B(SecurityChecker, isFridaRunning);
    HK_B(SecurityChecker, isSubstrateLoaded);
    HK_B(SecurityChecker, isCydiaInstalled);
    HK_B(SecurityChecker, hasSuspiciousFiles);
    HK_B(SecurityChecker, isEnvironmentClean);
    HK_B(SecurityChecker, verifyIntegrity);
    HK_B(SecurityChecker, checkTokenValid);
    HK_B(SecurityChecker, isEnvironmentSafe);
    HK_B(SecurityChecker, verifySignature);

    // Frida
    HK_B(SBXK_FridaDet, isFridaPresent);
    HK_B(SBXK_FridaDet, isFridaRunning);
    HK_B(SBXK_FridaDet, hasFrida);
    HK_B(SBXK_FridaDet, checkFrida);
    HK_B(SBXK_FridaDet, detectFrida);
    HK_B(SBXK_SubDet, isSubstrateLoaded);
    HK_B(SBXK_SubDet, hasSubstrate);
    HK_B(SBXK_SubDet, checkSubstrate);
    HK_B(SBXK_SubDet, isCydiaSubstrateLoaded);
    HK_B(SBXK_InjectDet, isDylibInjected);
    HK_B(SBXK_InjectDet, isImageInjected);
    HK_B(SBXK_InjectDet, hasInjectedDylib);
    HK_B(SBXK_InjectDet, isForeignImageLoaded);
    HK_B(SBXK_InjectDet, hasHooked);
    HK_B(SBXK_InjectDet, hasMSHook);
    HK_B(SBXK_InjectDet, hasDYLD_INSERT);
    HK_B(SBXK_InjectDet, isDYLDInjected);
    HK_B(SBXK_InjectDet, isAttached);
    HK_B(SBXK_InjectDet, isBeingDebugged);
    HK_B(SBXK_InjectDet, isTraced);
    HK_B(SBXK_InjectDet, isEnvironmentClean);
    HK_B(SBXK_InjectDet, isEnvironmentSafe);
    HK_B(SBXK_InjectDet, isClean);
    HK_B(SBXK_InjectDet, isSafe);
    HK_B(SBXK_InjectDet, verifyNoInjection);
    HK_B(SBXK_InjectDet, verifyNoHook);

    // Screenshot
    HK_B(ScreenShot, takeScreenShot);
    HK_B(ScreenShot, screenshot);
    HK_B(ScreenShot, getAppWindowsForScreen);
    HK_B(ScreenShot, getBufFromImage);
    HK_B(Rotate, fixOrientation);
    HK_B(Rotate, flipVertical);
    HK_B(Rotate, flipHorizontal);

    // Message box
    HK_B(AceMsgBoxImp, ShowMessageBoxWithTitle_Message_LeftBtn_RightBtn);
    HK_B(AceMsgBoxImp, dismiss);
    HK_B(AceMsgBoxImp, show);
}

static void SBXK_install_all(void) {
    pthread_mutex_lock(&g_install_lock);
    if (atomic_load(&g_installed)) {
        pthread_mutex_unlock(&g_install_lock);
        return;
    }

    SBXK_install_objc();
    SBXK_install_fishhook();
    SBXK_install_string_hooks();
    SBXK_install_trampolines();

    atomic_store(&g_installed, true);
    pthread_mutex_unlock(&g_install_lock);
}

static void SBXK_on_dyld_image(const struct mach_header *mh, intptr_t slide) {
    (void)mh; (void)slide;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        @autoreleasepool { SBXK_install_fishhook(); }
    });
}

__attribute__((constructor))
static void SBXK_boot(void) {
    @autoreleasepool {
        SBXK_derive_key();
        SBXK_detect_jit();
        _dyld_register_func_for_add_image(SBXK_on_dyld_image);
        SBXK_lifecycle_install();

        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(4 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            @autoreleasepool {
                SBXK_install_all();
                SBXK_cleanup_now();
                NSLog(@"[SBXK-v9.0] installed. hooks=%zu tramps=%zu jit=%d",
                      g_hooks_len, g_tramps_len, (int)g_jit_supported);
            }
        });
    }
}
