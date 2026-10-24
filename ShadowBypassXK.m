// language: Objective-C++, file: ShadowBypassXK.mm, target: iOS arm64/arm64e jailed
// Build: xcrun -sdk iphoneos clang++ -std=gnu++17 -arch arm64e -arch arm64 \
//        -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
//        -miphoneos-version-min=13.0 -fobjc-arc -O2 -dynamiclib \
//        -Wl,-undefined,dynamic_lookup -Wl,-install_name,@rpath/ShadowBypassXK.dylib \
//        -I deps ShadowBypassXK.mm deps/fishhook/fishhook.c \
//        -framework Foundation -framework UIKit -framework Security \
//        -framework AdSupport -framework AppTrackingTransparency \
//        -o ShadowBypassXK.dylib
//
// v8 fixes vs v7:
//   * resign_got: switch on ptrauth_key (builtin needs compile-time constant)
//   * ts_pc_load / ts_pc_store: __pc field renamed to pc on newer SDKs
//   * = {} instead of {} everywhere (C++98-compatible, works in all modes)
//   * <sys/ptrace.h> included for PT_DENY_ATTACH
//   * sign_fp helper for hardware-breakpoint PC redirect on arm64e

#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <mach/exception_types.h>
#include <mach/thread_act.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <mach/arm/thread_status.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/fixup-chains.h>
#include <ptrauth.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <cstring>
#include <cstdint>

__attribute__((weak)) extern "C" int DobbyHook(void*, void*, void**);

#ifndef ARM_DEBUG_STATE64
#define ARM_DEBUG_STATE64 15
#endif
#ifndef ARM_DEBUG_STATE64_COUNT
typedef struct { uint64_t __bvr[16],__bcr[16],__wvr[16],__wcr[16],__mdscr_el1; } arm_debug_state64_t;
#define ARM_DEBUG_STATE64_COUNT (sizeof(arm_debug_state64_t)/sizeof(uint32_t))
#endif
#ifndef THREAD_CONVERT_THREAD_STATE_TO_SELF
#define THREAD_CONVERT_THREAD_STATE_TO_SELF   1
#define THREAD_CONVERT_THREAD_STATE_FROM_SELF 2
#endif

struct exc_msg_t {
    mach_msg_header_t Head; mach_msg_body_t msgh_body;
    mach_msg_port_descriptor_t thread, task; NDR_record_t NDR;
    exception_type_t exception; mach_msg_type_number_t codeCnt; int64_t code[2];
};
struct exc_reply_t { mach_msg_header_t Head; NDR_record_t NDR; kern_return_t RetCode; };

// =================== replacement function forwards ===================
static void repl_inline_detect();
static void repl_black_module();
static void repl_tcj_protect();
static void repl_sc_protect();

// =========================== thread-state PC access ===========================
// __pc became `pc` on newer SDKs. Access by fixed offset:
//   __x[29] (232) + __fp (8) + __lr (8) + __sp (8) = 256 → __pc
static inline uint64_t ts_pc_load(const arm_thread_state64_t *s) {
    uint64_t v; memcpy(&v, (const uint8_t*)s + 256, sizeof(v)); return v;
}
static inline void ts_pc_store(arm_thread_state64_t *s, uint64_t v) {
    memcpy((uint8_t*)s + 256, &v, sizeof(v));
}

// Sign a function pointer with the canonical key used for BLR/BLRAA.
static inline void *sign_fp(void *p) {
#if __arm64e__
    return ptrauth_sign_unauthenticated(p, ptrauth_key_function_pointer, 0);
#else
    return p;
#endif
}

// ================================ PAC GOT ================================
static inline uintptr_t pac_blend(uintptr_t slot, uint16_t d) { return slot ^ d; }

static inline void *resign_got(void *raw, void *slot, uint8_t key, uint8_t ad, uint16_t d) {
#if __arm64e__
    uintptr_t disc = ad ? pac_blend((uintptr_t)slot, d) : (uintptr_t)d;
    switch (key) {
        case 0:  return ptrauth_sign_unauthenticated(raw, ptrauth_key_asia, disc);
        case 1:  return ptrauth_sign_unauthenticated(raw, ptrauth_key_asib, disc);
        case 2:  return ptrauth_sign_unauthenticated(raw, ptrauth_key_asda, disc);
        case 3:  return ptrauth_sign_unauthenticated(raw, ptrauth_key_asdb, disc);
        default: return raw;
    }
#else
    (void)raw;(void)slot;(void)key;(void)ad;(void)d; return raw;
#endif
}

// ==================== chained-fixup metadata =========================
struct auth_meta { uint8_t key, addrDiv; uint16_t diversity; bool ok; };

static auth_meta find_auth_meta(const struct mach_header_64 *mh, const void *slot) {
    auth_meta o = {0,0,0,false};
    const struct linkedit_data_command *cf = nullptr;
    const struct segment_command_64 *le = nullptr;
    const struct load_command *lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) cf = (const struct linkedit_data_command*)lc;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64*)lc;
            if (!strcmp(sg->segname, "__LINKEDIT")) le = sg;
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    if (!cf || !le || cf->dataoff < le->fileoff) return o;
    const uint8_t *data = (const uint8_t*)mh + le->vmaddr + (cf->dataoff - le->fileoff);
    const dyld_chained_fixups_header *hdr = (const dyld_chained_fixups_header*)data;
    if (hdr->fixups_version || !hdr->starts_offset) return o;
    const dyld_chained_starts_in_image *starts =
        (const dyld_chained_starts_in_image*)(data + hdr->starts_offset);
    for (uint32_t si = 0; si < starts->seg_count; ++si) {
        if (!starts->seg_info_offset[si]) continue;
        const dyld_chained_starts_in_segment *seg =
            (const dyld_chained_starts_in_segment*)((const uint8_t*)starts + starts->seg_info_offset[si]);
        if (seg->pointer_format != 1 && seg->pointer_format != 9 &&
            seg->pointer_format != 10 && seg->pointer_format != 12) continue;
        for (uint16_t pi = 0; pi < seg->page_count; ++pi) {
            if (seg->page_start[pi] == 0xFFFF) continue;
            uint8_t *cur = (uint8_t*)mh + seg->segment_offset
                         + (uint64_t)pi * seg->page_size + seg->page_start[pi];
            uint8_t *lim = (uint8_t*)mh + seg->segment_offset
                         + (uint64_t)(pi + 1) * seg->page_size;
            for (int g = 0; g < 200000; ++g) {
                if (cur < (uint8_t*)mh || cur >= lim) break;
                if ((const void*)cur == slot) {
                    const dyld_chained_ptr_arm64e_auth_bind *b =
                        (const dyld_chained_ptr_arm64e_auth_bind*)cur;
                    if (b->auth) {
                        o.key = b->key; o.addrDiv = b->addrDiv;
                        o.diversity = b->diversity; o.ok = true;
                    }
                    return o;
                }
                const dyld_chained_ptr_arm64e_auth_bind *bb =
                    (const dyld_chained_ptr_arm64e_auth_bind*)cur;
                uint32_t st = bb->auth ? ((const dyld_chained_ptr_arm64e_auth_bind*)cur)->next
                             : bb->bind ? ((const dyld_chained_ptr_arm64e_bind*)cur)->next
                                        : ((const dyld_chained_ptr_arm64e_rebase*)cur)->next;
                if (!st) break;
                cur += (size_t)st * 4;
            }
        }
    }
    return o;
}

// ========================= Mach-O parsers =========================
struct symtab_info { const struct nlist_64 *nl; const char *str; uint32_t n; };

static bool get_symtab(const struct mach_header_64 *mh, symtab_info *o) {
    const struct load_command *lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    const struct symtab_command *sc = nullptr;
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_SYMTAB) { sc = (const struct symtab_command*)lc; break; }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    if (!sc) return false;
    o->nl = (const struct nlist_64*)((const uint8_t*)mh + sc->symoff);
    o->str = (const char*)((const uint8_t*)mh + sc->stroff);
    o->n = sc->nsyms;
    return true;
}

static bool page_prot(vm_address_t a, vm_prot_t *out) {
    vm_address_t r = a; vm_size_t sz = 0;
    vm_region_submap_info_data_64_t info = {};
    mach_msg_type_number_t c = VM_REGION_SUBMAP_INFO_COUNT_64; natural_t d = 0;
    if (vm_region_recurse_64(mach_task_self(), &r, &sz, &d,
            (vm_region_recurse_info_t)&info, &c) != KERN_SUCCESS) return false;
    if (a < r || a >= r + sz) return false;
    *out = info.protection; return true;
}

// ================ string-in-image + xref resolver ================
static uintptr_t find_cstring(const struct mach_header_64 *mh, const char *needle) {
    const size_t nlen = strlen(needle);
    const struct load_command *lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64*)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) {
                const struct section_64 *s = (const struct section_64*)((const uint8_t*)lc + sizeof(*sg));
                for (uint32_t j = 0; j < sg->nsects; ++j, ++s) {
                    if (strcmp(s->sectname, "__cstring") != 0) continue;
                    const char *base = (const char*)((const uint8_t*)mh + s->offset);
                    for (size_t k = 0; k + nlen < s->size; ++k) {
                        if (memcmp(base + k, needle, nlen) == 0 && base[k + nlen] == '\0') {
                            return (uintptr_t)((const uint8_t*)mh + s->addr + k);
                        }
                    }
                }
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    return 0;
}

static uintptr_t adrp_page(uint32_t inst, uintptr_t pc) {
    if ((inst & 0x9F000000u) != 0x90000000u) return 0;
    uint32_t immlo = (inst >> 29) & 0x3;
    uint32_t immhi = (inst >> 5) & 0x7FFFF;
    int64_t imm = ((int64_t)(((uint64_t)immhi << 2) | immlo) << 43) >> 43;
    return (pc & ~0xFFFULL) + (uintptr_t)(imm << 12);
}
static bool add_low12(uint32_t inst, uintptr_t page, uintptr_t *out, uint32_t *rd) {
    if ((inst & 0xFF800000u) != 0x91000000u) return false;
    if (((inst >> 22) & 0x3) != 0) return false;
    uint32_t imm12 = (inst >> 10) & 0xFFF;
    *rd = inst & 0x1F;
    *out = page + imm12;
    return true;
}

static uintptr_t find_ref_to_addr(const struct mach_header_64 *mh, uintptr_t target) {
    const struct load_command *lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64*)lc;
            if (strcmp(sg->segname, "__TEXT") == 0) {
                const struct section_64 *s = (const struct section_64*)((const uint8_t*)lc + sizeof(*sg));
                for (uint32_t j = 0; j < sg->nsects; ++j, ++s) {
                    if (strcmp(s->sectname, "__text") != 0) continue;
                    const uint8_t *base = (const uint8_t*)mh + s->offset;
                    const size_t bytes = s->size;
                    for (size_t k = 0; k + 8 <= bytes; k += 4) {
                        uint32_t i0 = *(const uint32_t*)(base + k);
                        uintptr_t pg = adrp_page(i0, (uintptr_t)(base + k));
                        if (!pg) continue;
                        uint32_t rd0 = i0 & 0x1F;
                        for (size_t m = 4; m <= 12 && k + m + 4 <= bytes; m += 4) {
                            uint32_t iN = *(const uint32_t*)(base + k + m);
                            uintptr_t final_addr; uint32_t rdN;
                            if (add_low12(iN, pg, &final_addr, &rdN) && rdN == rd0) {
                                if (final_addr == target) return (uintptr_t)(base + k);
                                break;
                            }
                            if ((iN & 0x1F) == rd0 && (iN & 0xFF800000u) != 0x91000000u) break;
                        }
                    }
                }
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    return 0;
}

static uintptr_t find_func_start(uintptr_t code_ref, size_t max_back) {
    for (size_t off = 0; off <= max_back; off += 4) {
        if (code_ref < off + 4) break;
        uintptr_t cand = code_ref - off;
        uint32_t inst = *(const uint32_t*)cand;
        if ((inst & 0xFFC07FFFu) == 0xA9807BFDu) return cand; // STP x29,x30,[sp,#-N]!
        if (inst == 0xD503233Fu) return cand;                  // PACIASP
    }
    return 0;
}

// ========================= GOT rebind =========================
static bool rebind_image(const struct mach_header_64 *mh, const char *name,
                         void *repl_raw, void **orig_out) {
    symtab_info st = {};
    if (!get_symtab(mh, &st)) return false;
    const struct dysymtab_command *dys = nullptr;
    const struct load_command *lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_DYSYMTAB) { dys = (const struct dysymtab_command*)lc; break; }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    if (!dys) return false;
    const uint32_t *ind = (const uint32_t*)((const uint8_t*)mh + dys->indirectsymoff);
    lc = (const struct load_command*)((const uint8_t*)mh + sizeof(*mh));
    for (uint32_t i = 0; i < mh->ncmds; ++i) {
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *sg = (const struct segment_command_64*)lc;
            const bool isData = !strcmp(sg->segname, "__DATA") ||
                                !strcmp(sg->segname, "__DATA_CONST") ||
                                !strcmp(sg->segname, "__AUTH_CONST");
            if (isData) {
                const struct section_64 *s = (const struct section_64*)((const uint8_t*)lc + sizeof(*sg));
                for (uint32_t j = 0; j < sg->nsects; ++j, ++s) {
                    const bool isA = !strcmp(s->sectname, "__auth_got") ||
                                     !strcmp(s->sectname, "__auth_ptr");
                    const bool isP = !strcmp(s->sectname, "__got") ||
                                     !strcmp(s->sectname, "__la_symbol_ptr");
                    if (!isA && !isP) continue;
                    void **slots = (void**)((uint8_t*)mh + s->offset);
                    const uint32_t ns = s->size / sizeof(void*);
                    for (uint32_t k = 0; k < ns; ++k) {
                        uint32_t idx = ind[s->reserved1 + k];
                        if (idx == INDIRECT_SYMBOL_LOCAL || idx == INDIRECT_SYMBOL_ABS || idx >= st.n) continue;
                        const char *sym = st.str + st.nl[idx].n_un.n_strx;
                        if (*sym == '_') ++sym;
                        if (strcmp(sym, name) != 0) continue;
                        vm_address_t pg = (vm_address_t)&slots[k] & ~(vm_page_size - 1);
                        vm_prot_t op = VM_PROT_READ; const bool have = page_prot(pg, &op);
                        if (vm_protect(mach_task_self(), pg, vm_page_size, false,
                                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) != KERN_SUCCESS) return false;
                        if (orig_out && !*orig_out)
                            *orig_out = (void*)ptrauth_strip(slots[k], ptrauth_key_asia);
                        void *ns_v;
                        if (isA) {
                            auth_meta m = find_auth_meta(mh, &slots[k]);
                            if (!m.ok) { m.key = 0; m.addrDiv = 1; m.diversity = 0; }
                            ns_v = resign_got(repl_raw, &slots[k], m.key, m.addrDiv, m.diversity);
                        } else ns_v = repl_raw;
                        slots[k] = ns_v;
                        __builtin___clear_cache((char*)&slots[k], (char*)&slots[k] + sizeof(void*));
                        vm_prot_t rp = have ? op : VM_PROT_READ;
                        if (vm_protect(mach_task_self(), pg, vm_page_size, false, rp) != KERN_SUCCESS)
                            (void)vm_protect(mach_task_self(), pg, vm_page_size, false, VM_PROT_READ);
                        return true;
                    }
                }
            }
        }
        lc = (const struct load_command*)((const uint8_t*)lc + lc->cmdsize);
    }
    return false;
}

static bool rebind_all(const char *name, void *repl, void **orig) {
    bool any = false;
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const struct mach_header_64 *mh = (const struct mach_header_64*)_dyld_get_image_header(i);
        if (mh && mh->magic == MH_MAGIC_64 && rebind_image(mh, name, repl, orig)) any = true;
    }
    return any;
}

// =========================== anogs ===========================
static const struct mach_header_64 *find_image(const char *n) {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, n)) return (const struct mach_header_64*)_dyld_get_image_header(i);
    }
    return nullptr;
}
static intptr_t anogs_slide() {
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && strstr(nm, "anogs")) return _dyld_get_image_vmaddr_slide(i);
    }
    return 0;
}

// ===================== Mach exception handler =====================
static mach_port_t g_exc_port = MACH_PORT_NULL;
static const int kMaxHWBP = 6;
static uintptr_t g_hwb_addr[kMaxHWBP] = {};
static void    *g_hwb_repl[kMaxHWBP] = {};
static volatile int g_hwb_n = 0;
static pthread_mutex_t g_hwb_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_threads_mu = PTHREAD_MUTEX_INITIALIZER;

static int hwb_slot_for(uintptr_t a) {
    for (int i = 0; i < kMaxHWBP; ++i) if (g_hwb_addr[i] == a && a) return i;
    return -1;
}
static bool hwb_arm_on_thread(thread_t th, int slot, uintptr_t addr) {
    arm_debug_state64_t dbg = {};
    mach_msg_type_number_t c = ARM_DEBUG_STATE64_COUNT;
    if (thread_get_state(th, ARM_DEBUG_STATE64, (thread_state_t)&dbg, &c) != KERN_SUCCESS) return false;
    if (c != ARM_DEBUG_STATE64_COUNT) return false;
    dbg.__bvr[slot] = addr;
    dbg.__bcr[slot] = 0x1E5ULL;
    return thread_set_state(th, ARM_DEBUG_STATE64, (thread_state_t)&dbg, c) == KERN_SUCCESS;
}
static void hwb_arm_all_threads() {
    int n; pthread_mutex_lock(&g_hwb_mu); n = g_hwb_n; pthread_mutex_unlock(&g_hwb_mu);
    if (!n) return;
    pthread_mutex_lock(&g_threads_mu);
    thread_act_array_t ts = nullptr; mach_msg_type_number_t c = 0;
    if (task_threads(mach_task_self(), &ts, &c) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < c; ++i) {
            (void)thread_suspend(ts[i]);
            for (int s = 0; s < n; ++s) (void)hwb_arm_on_thread(ts[i], s, g_hwb_addr[s]);
            (void)thread_resume(ts[i]);
            mach_port_deallocate(mach_task_self(), ts[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)ts, c * sizeof(thread_t));
    }
    pthread_mutex_unlock(&g_threads_mu);
}

static bool handle_breakpoint(thread_t th) {
    arm_thread_state64_t raw = {};
    mach_msg_type_number_t c = ARM_THREAD_STATE64_COUNT;
    if (thread_get_state(th, ARM_THREAD_STATE64, (thread_state_t)&raw, &c) != KERN_SUCCESS) return false;
    if (c != ARM_THREAD_STATE64_COUNT) return false;

    uintptr_t pc = (uintptr_t)ptrauth_strip((void*)ts_pc_load(&raw), ptrauth_key_function_pointer);
    int slot = hwb_slot_for(pc);
    if (slot < 0) return false;

#if __arm64e__
    arm_thread_state64_t self = {};
    mach_msg_type_number_t sc = ARM_THREAD_STATE64_COUNT;
    if (thread_convert_thread_state(th, THREAD_CONVERT_THREAD_STATE_TO_SELF, ARM_THREAD_STATE64,
            (thread_state_t)&raw, c, (thread_state_t)&self, &sc) != KERN_SUCCESS ||
        sc != ARM_THREAD_STATE64_COUNT) return false;

    ts_pc_store(&self, (uint64_t)sign_fp(g_hwb_repl[slot]));

    arm_thread_state64_t fin = {};
    mach_msg_type_number_t fc = ARM_THREAD_STATE64_COUNT;
    if (thread_convert_thread_state(th, THREAD_CONVERT_THREAD_STATE_FROM_SELF, ARM_THREAD_STATE64,
            (thread_state_t)&self, sc, (thread_state_t)&fin, &fc) != KERN_SUCCESS ||
        fc != ARM_THREAD_STATE64_COUNT) return false;
    return thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&fin, fc) == KERN_SUCCESS;
#else
    ts_pc_store(&raw, (uint64_t)g_hwb_repl[slot]);
    return thread_set_state(th, ARM_THREAD_STATE64, (thread_state_t)&raw, c) == KERN_SUCCESS;
#endif
}

static void free_ports(exc_msg_t *m) {
    if (!(m->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX)) return;
    if (m->msgh_body.msgh_descriptor_count >= 1 && m->thread.name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), m->thread.name);
        m->thread.name = MACH_PORT_NULL;
    }
    if (m->msgh_body.msgh_descriptor_count >= 2 && m->task.name != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), m->task.name);
        m->task.name = MACH_PORT_NULL;
    }
}
static void send_reply(exc_msg_t *r, kern_return_t ret) {
    exc_reply_t p = {};
    p.Head.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    p.Head.msgh_size = sizeof(p);
    p.Head.msgh_remote_port = r->Head.msgh_remote_port;
    p.Head.msgh_local_port  = MACH_PORT_NULL;
    p.Head.msgh_id = r->Head.msgh_id + 100;
    p.NDR = r->NDR; p.RetCode = ret;
    (void)mach_msg(&p.Head, MACH_SEND_MSG, sizeof(p), 0, MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}
static void *exc_loop(void *) {
    uint8_t buf[2048] __attribute__((aligned(8)));
    for (;;) {
        memset(buf, 0, sizeof(buf));
        exc_msg_t *r = (exc_msg_t*)buf;
        mach_msg_return_t mr = mach_msg(&r->Head, MACH_RCV_MSG, 0, sizeof(buf),
                                        g_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
        if (mr == MACH_RCV_TOO_LARGE) {
            uint8_t t[64] __attribute__((aligned(8)));
            (void)mach_msg((mach_msg_header_t*)t, MACH_RCV_MSG, 0, sizeof(t),
                           g_exc_port, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            continue;
        }
        if (mr != MACH_MSG_SUCCESS) continue;
        if (r->Head.msgh_id != 2405 && r->Head.msgh_id != 2406 && r->Head.msgh_id != 2407) {
            free_ports(r); continue;
        }
        kern_return_t ret = KERN_FAILURE;
        const bool cx = (r->Head.msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0;
        const bool ht = cx && r->msgh_body.msgh_descriptor_count >= 1 &&
                        r->thread.name != MACH_PORT_NULL;
        if (r->exception == EXC_BREAKPOINT && ht && handle_breakpoint(r->thread.name))
            ret = KERN_SUCCESS;
        send_reply(r, ret);
        free_ports(r);
    }
    return nullptr;
}
static bool exc_setup() {
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port) != KERN_SUCCESS) return false;
    if (mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port,
            MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return false;
    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_exc_port,
            EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, ARM_THREAD_STATE64) != KERN_SUCCESS) return false;
    pthread_t t; pthread_attr_t a; pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&t, &a, exc_loop, nullptr);
    pthread_attr_destroy(&a);
    return rc == 0;
}

// ========================= GOT hooks =========================
static int (*g_orig_kill)(pid_t,int) = nullptr;
static int (*g_orig_sysctl)(int*,u_int,void*,size_t*,void*,size_t) = nullptr;
static int (*g_orig_ptrace)(int,pid_t,caddr_t,int) = nullptr;
static int (*g_orig_pthread_create)(pthread_t*,const pthread_attr_t*,void*(*)(void*),void*) = nullptr;
static kern_return_t (*g_orig_task_set_exc)(task_t,exception_mask_t,mach_port_t,
                                            exception_behavior_t,thread_state_flavor_t) = nullptr;

static int hk_kill(pid_t p, int s) {
    if (p == getpid() && (s == SIGKILL || s == SIGSTOP || s == SIGABRT)) return 0;
    return g_orig_kill ? g_orig_kill(p,s) : -1;
}
static int hk_sysctl(int *n, u_int nl, void *o, size_t *ol, void *nw, size_t nw2) {
    int rc = g_orig_sysctl ? g_orig_sysctl(n,nl,o,ol,nw,nw2) : -1;
    if (!rc && n && nl >= 4 && o && n[0]==CTL_KERN && n[1]==KERN_PROC &&
        n[2]==KERN_PROC_PID && n[3]==getpid()) {
        struct kinfo_proc *kp = (struct kinfo_proc*)o;
        if (kp) kp->kp_proc.p_flag &= ~P_TRACED;
    }
    return rc;
}
static int hk_ptrace(int r, pid_t p, caddr_t a, int d) {
    if (r == PT_DENY_ATTACH) return 0;
    return g_orig_ptrace ? g_orig_ptrace(r,p,a,d) : -1;
}
static int hk_pthread_create(pthread_t *t, const pthread_attr_t *a,
                             void *(*fn)(void*), void *arg) {
    int rc = g_orig_pthread_create ? g_orig_pthread_create(t,a,fn,arg) : -1;
    if (!rc && t) {
        int n; pthread_mutex_lock(&g_hwb_mu); n = g_hwb_n; pthread_mutex_unlock(&g_hwb_mu);
        if (n) {
            thread_t m = pthread_mach_thread_np(*t);
            for (int s = 0; s < n; ++s) (void)hwb_arm_on_thread(m, s, g_hwb_addr[s]);
        }
    }
    return rc;
}
static kern_return_t hk_task_set_exc(task_t t, exception_mask_t m, mach_port_t p,
                                     exception_behavior_t b, thread_state_flavor_t f) {
    kern_return_t rc = g_orig_task_set_exc ? g_orig_task_set_exc(t,m,p,b,f) : KERN_FAILURE;
    if (t == mach_task_self() && (m & EXC_MASK_BREAKPOINT) &&
        g_exc_port && p != g_exc_port) {
        (void)task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_exc_port,
                                        EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                        ARM_THREAD_STATE64);
    }
    return rc;
}

// ============== EXPORTED AnoSDK* HOOKS (via GOT) ==============
static int (*g_orig_GetReportData)(void*, unsigned int*) = nullptr;
static int hk_GetReportData(void *out, unsigned int *outLen) {
    if (out) memset(out, 0, outLen ? *outLen : 0);
    if (outLen) *outLen = 0;
    return 0;
}
static int (*g_orig_GetReportData2)(void*, unsigned int*) = nullptr;
static int hk_GetReportData2(void *out, unsigned int *outLen) {
    if (out) memset(out, 0, outLen ? *outLen : 0);
    if (outLen) *outLen = 0;
    return 0;
}
static int (*g_orig_OnRecvSignature)(const char*, unsigned int) = nullptr;
static int hk_OnRecvSignature(const char *s, unsigned int l) { (void)s; (void)l; return 0; }
static int (*g_orig_OnRecvData)(const char*, unsigned int) = nullptr;
static int hk_OnRecvData(const char *d, unsigned int l) { (void)d; (void)l; return 0; }
static int (*g_orig_DelReportData)(void) = nullptr;
static int hk_DelReportData(void) { return 0; }

static void install_exported_hooks() {
    rebind_all("AnoSDKGetReportData",   (void*)&hk_GetReportData,   (void**)&g_orig_GetReportData);
    rebind_all("AnoSDKGetReportData2",  (void*)&hk_GetReportData2,  (void**)&g_orig_GetReportData2);
    rebind_all("AnoSDKOnRecvSignature", (void*)&hk_OnRecvSignature, (void**)&g_orig_OnRecvSignature);
    rebind_all("AnoSDKOnRecvData",      (void*)&hk_OnRecvData,      (void**)&g_orig_OnRecvData);
    rebind_all("AnoSDKDelReportData",   (void*)&hk_DelReportData,   (void**)&g_orig_DelReportData);
}

// ================= hook installers =================
static bool hw_hook_addr(uintptr_t a, void *repl) {
    pthread_mutex_lock(&g_hwb_mu);
    if (g_hwb_n >= kMaxHWBP) { pthread_mutex_unlock(&g_hwb_mu); return false; }
    int slot = g_hwb_n++;
    g_hwb_addr[slot] = a; g_hwb_repl[slot] = repl;
    pthread_mutex_unlock(&g_hwb_mu);
    hwb_arm_all_threads();
    return true;
}
static bool hw_hook(uintptr_t vaddr, void *repl) {
    intptr_t s = anogs_slide(); if (!s) return false;
    return hw_hook_addr((uintptr_t)s + vaddr, repl);
}
static bool inline_hook_addr(void *target, void *repl, void **orig_out) {
    if (!DobbyHook) return false;
    void *orig = nullptr;
    if (DobbyHook(ptrauth_strip(target, ptrauth_key_asia),
                  ptrauth_strip(repl, ptrauth_key_function_pointer), &orig) != 0) return false;
    if (orig_out) {
#if __arm64e__
        *orig_out = ptrauth_sign_unauthenticated(orig, ptrauth_key_asia, (uintptr_t)target);
#else
        *orig_out = orig;
#endif
    }
    return true;
}

// ============ INTERNAL PROTECTION HOOKS (string xref) ============
struct str_target { const char *needle; void *repl; const char *name; };
static str_target kStrTargets[] = {
    { "ms_set_inlie_hook",           (void*)&repl_inline_detect, "set_inline_hook_error" },
    { "inline_hook_opcode_dismatch", (void*)&repl_inline_detect, "inline_hook_opcode_dismatch" },
    { "black_module_macho",          (void*)&repl_black_module,  "black_module_macho" },
    // { "tcj_protect",              (void*)&repl_tcj_protect,   "tcj_protect" },
    // { "sc_protect",               (void*)&repl_sc_protect,    "sc_protect" },
};

static void install_string_hooks() {
    const struct mach_header_64 *mh = find_image("anogs"); if (!mh) return;
    for (size_t i = 0; i < sizeof(kStrTargets)/sizeof(kStrTargets[0]); ++i) {
        uintptr_t str_addr = find_cstring(mh, kStrTargets[i].needle);
        if (!str_addr) continue;
        uintptr_t cref = find_ref_to_addr(mh, str_addr);
        if (!cref) continue;
        uintptr_t fstart = find_func_start(cref, 0x1000);
        if (!fstart) fstart = cref;
        if (!inline_hook_addr((void*)fstart, kStrTargets[i].repl, nullptr)) {
            (void)hw_hook_addr(fstart, kStrTargets[i].repl);
        }
    }
}

// ========================= constructor =========================
__attribute__((constructor))
static void hookkit_entry(void) {
    @autoreleasepool {
        if (!find_image("anogs")) return;
        if (!exc_setup()) return;

        rebind_all("kill",                    (void*)&hk_kill,          (void**)&g_orig_kill);
        rebind_all("sysctl",                  (void*)&hk_sysctl,        (void**)&g_orig_sysctl);
        rebind_all("ptrace",                  (void*)&hk_ptrace,        (void**)&g_orig_ptrace);
        rebind_all("pthread_create",          (void*)&hk_pthread_create,(void**)&g_orig_pthread_create);
        rebind_all("task_set_exception_ports",(void*)&hk_task_set_exc,  (void**)&g_orig_task_set_exc);

        install_exported_hooks();
        install_string_hooks();
    }
}

// =================== replacement bodies ===================
static void repl_inline_detect() {}
static void repl_black_module()  {}
static void repl_tcj_protect()   {}
static void repl_sc_protect()    {}
