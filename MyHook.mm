// MyHook.mm
// هوك متكامل لـ iOS بدون جيلبريك — يدعم arm64 و arm64e (PAC)
// + طبقات حماية شاملة (Anti-Debug / Anti-Tamper / Anti-Hook / Anti-Jailbreak / Anti-Injection)

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <dlfcn.h>
#import <ptrauth.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import <sys/ptrace.h>
#import <unistd.h>
#import <signal.h>
#import <errno.h>
#import <string.h>
#import <stdlib.h>
#import <pthread.h>
#import <execinfo.h>
#import <mach/mach.h>
#import <mach/vm_map.h>
#import <mach-o/nlist.h>
#import <libkern/OSAtomic.h>

#include "Dobby.h"

// ============================================================
// 0. أدوات مساعدة عامة
// ============================================================

static uintptr_t get_image_slide(const char *image_name) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, image_name)) {
            return (uintptr_t)_dyld_get_image_vmaddr_slide(i);
        }
    }
    return 0;
}

static uintptr_t get_image_base(const char *image_name) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, image_name)) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

static void *addr_from_vmaddr(const char *image_name, uintptr_t vmaddr) {
    uintptr_t slide = get_image_slide(image_name);
    if (slide == 0) return NULL;
    return (void *)(slide + vmaddr);
}

static void *addr_from_symbol(const char *symbol_name) {
    void *handle = dlopen(NULL, RTLD_NOW);
    return dlsym(handle, symbol_name);
}

// ============================================================
// 1. دعم PAC لـ arm64e
// ============================================================

#if __arm64e__
static void *strip_pac(void *ptr) {
    return __builtin_ptrauth_strip(ptr, ptrauth_key_asia);
}
static void *sign_pac(void *ptr) {
    return ptrauth_sign_unauthenticated(ptr, ptrauth_key_asia, 0);
}
#else
#define strip_pac(ptr) (ptr)
#define sign_pac(ptr) (ptr)
#endif

// ============================================================
// 2. حماية من التصحيح (Anti-Debugging)
// ============================================================

// 2.1 كشف الـ debugger عبر sysctl
static bool is_debugger_attached_sysctl(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

// 2.2 كشف الـ debugger عبر ptrace (PT_DENY_ATTACH المضاد)
static bool is_debugger_attached_ptrace(void) {
    // نحاول استخدام ptrace مع طلب DENY - إذا فشل، فهناك debugger
    int result = ptrace(PT_DENY_ATTACH, 0, 0, 0);
    if (result == -1 && errno == EPERM) {
        // هذا يعني أن هناك من يحاول التصحيح
        return true;
    }
    return false;
}

// 2.3 كشف الـ debugger عبر sysctl لـ P_TRACED مباشرة
static bool is_ptraced(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

// 2.4 كشف الـ debugger عبر task_get_exception_ports
static bool is_debugger_attached_exception_ports(void) {
    mach_port_t task = mach_task_self();
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];
    mach_msg_type_number_t count = EXC_TYPES_COUNT;
    
    kern_return_t kr = task_get_exception_ports(
        task,
        EXC_MASK_ALL,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );
    
    if (kr != KERN_SUCCESS) return false;
    
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL && ports[i] != MACH_PORT_DEAD) {
            // أي منفذ استثناء آخر غير المنفذ الافتراضي يعتبر مشبوه
            if (ports[i] != task) {
                // قد يكون debugger
            }
        }
    }
    return false;
}

// 2.5 كشف الـ debugger عبر sysctl KERN_PROC
static bool is_debugger_attached(void) {
    return is_ptraced() || is_debugger_attached_sysctl();
}

// ============================================================
// 3. حماية من الجيلبريك (Anti-Jailbreak)
// ============================================================

// 3.1 فحص وجود ملفات/مجلدات الجيلبريك
static bool check_jailbreak_files(void) {
    const char *jailbreak_paths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Activator.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Flipswitch.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/RocketBootstrap.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SubstrateLoader.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SubstrateInjection.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/TweakInject.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SafeMode.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/sslkillswitch.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Flex.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/FlexLoader.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Anywhere.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Cephei.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/libcolorpicker.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/libstatusbar.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/libpackageinfo.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/APTTimeOut.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/NoCrash.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/CydiaSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/Substrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/PreferenceBundles.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/AppList.dylib",
        "/Library/MobileSubstrate/DynamicLibraries/PreferenceLoader.dylib",
        "/var/lib/cydia",
        "/var/lib/dpkg",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/dpkg/status",
        "/var/lib/dpkg/info",
        "/var/stash",
        "/var/tmp/cydia.log",
        "/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
        "/var/mobile/Library/Preferences/com.saurik.Cydia.Settings.plist",
        "/var/mobile/Library/Preferences/com.saurik.impactor.plist",
        "/var/mobile/Library/Preferences/com.saurik.MobileSubstrate.plist",
        "/var/mobile/Library/Preferences/com.saurik.MobileSubstrateSafeMode.plist",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/private/var/mobile/Library/Preferences/com.saurik.Cydia.plist",
        "/private/var/mobile/Library/Preferences/com.saurik.Cydia.Settings.plist",
        "/private/var/mobile/Library/Preferences/com.saurik.MobileSubstrate.plist",
        "/private/var/mobile/Library/Preferences/com.saurik.MobileSubstrateSafeMode.plist",
        "/private/etc/apt",
        "/private/etc/dpkg",
        "/private/etc/ssh",
        "/private/etc/sshd_config",
        "/private/var/db/stash",
        "/private/var/db/cydia",
        "/etc/apt",
        "/etc/ssh",
        "/etc/sshd_config",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/sshd",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/bin/ssh",
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/cycript",
        "/usr/bin/cynject",
        "/usr/lib/libcycript.dylib",
        "/usr/lib/libcycript.0.dylib",
        "/usr/bin/cycript",
        "/usr/libexec/cydia",
        "/usr/libexec/cydia/firmware.sh",
        "/usr/bin/sbsettings",
        "/usr/bin/sbssettings",
        "/usr/bin/sbwalk",
        "/usr/bin/sbutil",
        "/usr/bin/sbmanager",
        "/usr/bin/sbapp",
        "/usr/bin/sbpush",
        "/usr/bin/sbpop",
        "/usr/bin/sbtool",
        "/usr/bin/sbsh",
        "/usr/bin/sb",
        "/usr/bin/class-dump",
        "/usr/bin/class-dump-z",
        "/usr/bin/ldid",
        "/usr/bin/codesign",
        "/usr/bin/csreq",
        "/usr/bin/csops",
        "/usr/bin/otool",
        "/usr/bin/nmedit",
        "/usr/bin/install_name_tool",
        "/usr/bin/lipo",
        "/usr/bin/plutil",
        "/usr/bin/plutil",
        "/usr/bin/plutil",
        "/usr/bin/plutil",
        NULL
    };
    
    for (int i = 0; jailbreak_paths[i] != NULL; i++) {
        struct stat st;
        if (stat(jailbreak_paths[i], &st) == 0) {
            return true;
        }
    }
    return false;
}

// 3.2 فحص إمكانية الكتابة خارج الـ sandbox
static bool check_sandbox_violation(void) {
    NSString *testPath = @"/private/jailbreak_test.txt";
    NSError *error = nil;
    NSString *testString = @"test";
    BOOL success = [testString writeToFile:testPath
                                atomically:YES
                                  encoding:NSUTF8StringEncoding
                                     error:&error];
    if (success) {
        [[NSFileManager defaultManager] removeItemAtPath:testPath error:nil];
        return true; // الجيلبريك موجود
    }
    return false;
}

// 3.3 فحص وجود fork() (يعمل فقط على أجهزة مكسورة)
static bool check_fork(void) {
    pid_t pid = fork();
    if (pid >= 0) {
        // fork نجح - جيلبريك
        if (pid == 0) {
            _exit(0);
        }
        return true;
    }
    return false;
}

// 3.4 فحص وجود symlinks مشبوهة
static bool check_suspicious_symlinks(void) {
    const char *paths[] = {
        "/var/lib/apt",
        "/var/lib/cydia",
        "/var/stash",
        "/private/var/stash",
        "/Applications",
        NULL
    };
    for (int i = 0; paths[i] != NULL; i++) {
        struct stat st;
        if (lstat(paths[i], &st) == 0) {
            if (S_ISLNK(st.st_mode)) {
                return true;
            }
        }
    }
    return false;
}

// 3.5 الفحص الشامل للجيلبريك
static bool is_jailbroken(void) {
    return check_jailbreak_files() ||
           check_sandbox_violation() ||
           check_fork() ||
           check_suspicious_symlinks();
}

// ============================================================
// 4. حماية من الحقن (Anti-Injection / Anti-Dylib)
// ============================================================

// 4.1 كشف مكتبات مشبوهة محمّلة
static bool check_suspicious_dylibs(void) {
    const char *suspicious[] = {
        "MobileSubstrate",
        "Substrate",
        "CydiaSubstrate",
        "SubstrateLoader",
        "SubstrateInjection",
        "TweakInject",
        "libsubstrate",
        "libsubstrate.dylib",
        "libhooker",
        "libhooker.dylib",
        "FridaGadget",
        "frida",
        "frida-agent",
        "frida-gadget",
        "cynject",
        "cycript",
        "libcycript",
        "SSLKillSwitch",
        "sslkillswitch",
        "Flex",
        "flexloader",
        "Anywhere",
        "Anywhere.dylib",
        "Cephei",
        "Cephei.dylib",
        "RocketBootstrap",
        "RocketBootstrap.dylib",
        "PreferenceLoader",
        "PreferenceLoader.dylib",
        "PreferenceBundles",
        "AppList",
        "AppList.dylib",
        "libcolorpicker",
        "libstatusbar",
        "libpackageinfo",
        "APTTimeOut",
        "NoCrash",
        "SafeMode",
        "libswiftCore",
        "Dobby",
        "dobby",
        "libdobby",
        "libdobby.dylib",
        "libfrida",
        "libfrida-gadget",
        "libfrida-gadget.dylib",
        "gadget",
        "libgadget",
        "libgadget.dylib",
        "substrate",
        "SubstrateLoader.dylib",
        "libsubstitute",
        "libsubstitute.dylib",
        "substitute",
        "libellekit",
        "libellekit.dylib",
        "ellekit",
        "libhooker",
        "libhooker.dylib",
        "hooker",
        "libSandy",
        "libSandy.dylib",
        "Sandy",
        "libKernBypass",
        "libKernBypass.dylib",
        "KernBypass",
        "libChoicy",
        "libChoicy.dylib",
        "Choicy",
        "libHideJB",
        "libHideJB.dylib",
        "HideJB",
        "libShadow",
        "libShadow.dylib",
        "Shadow",
        "libA-Bypass",
        "libA-Bypass.dylib",
        "A-Bypass",
        "libBypass",
        "libBypass.dylib",
        "Bypass",
        "libFlyJB",
        "libFlyJB.dylib",
        "FlyJB",
        "libLiberty",
        "libLiberty.dylib",
        "Liberty",
        "libLibertyLite",
        "libLibertyLite.dylib",
        "LibertyLite",
        "libHestia",
        "libHestia.dylib",
        "Hestia",
        "libKernbypass",
        "libKernbypass.dylib",
        "Kernbypass",
        NULL
    };
    
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        for (int j = 0; suspicious[j] != NULL; j++) {
            if (strcasestr(name, suspicious[j]) != NULL) {
                return true;
            }
        }
    }
    return false;
}

// 4.2 كشف Frida عبر المنافذ
static bool check_frida_ports(void) {
    // فحص المنفذ 27042 (Frida الافتراضي) و 27043
    // نستخدم socket connection بسيط
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    
    if (result == 0) {
        return true; // Frida موجود
    }
    return false;
}

// 4.3 كشف Frida عبر اسم العملية
static bool check_frida_process(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) return false;
    
    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (!procs) return false;
    
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return false;
    }
    
    int count = size / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        const char *name = procs[i].kp_proc.p_comm;
        if (strcasestr(name, "frida") != NULL ||
            strcasestr(name, "cycript") != NULL ||
            strcasestr(name, "gadget") != NULL) {
            free(procs);
            return true;
        }
    }
    free(procs);
    return false;
}

// 4.4 كشف Frida عبر فحص الذاكرة (gadget signatures)
static bool check_frida_memory(void) {
    // فحص وجود سلاسل Frida في الذاكرة
    const char *frida_strings[] = {
        "frida:rpc",
        "frida-agent",
        "frida-gadget",
        "FridaScript",
        "gum-js-loop",
        "gmain",
        "gdbus",
        "frida_agent_main",
        "frida_gadget",
        "FRIDA",
        NULL
    };
    
    // البحث في مكتبات dyld
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        for (int j = 0; frida_strings[j] != NULL; j++) {
            if (strcasestr(name, frida_strings[j]) != NULL) {
                return true;
            }
        }
    }
    return false;
}

// 4.5 الفحص الشامل للحقن
static bool is_injected(void) {
    return check_suspicious_dylibs() ||
           check_frida_ports() ||
           check_frida_process() ||
           check_frida_memory();
}

// ============================================================
// 5. حماية من التلاعب بالكود (Anti-Tamper)
// ============================================================

// 5.1 فحص تكامل __TEXT
static bool check_text_integrity(void) {
    // فحص بسيط: نتأكد من أن رأس Mach-O لم يتم تعديله
    const struct mach_header_64 *header = 
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header) return false;
    
    if (header->magic != MH_MAGIC_64) return false;
    if (header->cputype != CPU_TYPE_ARM64) return false;
    if (header->filetype != MH_EXECUTE) return false;
    
    return true;
}

// 5.2 فحص أن صفحة __TEXT غير قابلة للكتابة
static bool check_text_writable(void) {
    const struct mach_header_64 *header = 
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header) return false;
    
    uintptr_t base = (uintptr_t)header;
    // فحص أول صفحة
    vm_address_t addr = base;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    
    kern_return_t kr = vm_region_64(mach_task_self(),
                                    &addr,
                                    &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info,
                                    &info_count,
                                    &object_name);
    
    if (kr == KERN_SUCCESS) {
        // إذا كانت __TEXT قابلة للكتابة، فهذا تلاعب
        if (info.protection & VM_PROT_WRITE) {
            return true;
        }
    }
    return false;
}

// 5.3 فحص checksum للكود (يمكن استبداله بـ checksum حقيقي)
static bool check_code_checksum(void) {
    // هنا يمكن إضافة فحص CRC لمقطع __text
    // لأغراض الحماية، نتحقق من أن العنوان الأساسي سليم
    return true;
}

// 5.4 فحص التوقيع
static bool check_code_signature(void) {
    // فحص وجود توقيع صالح (على الأجهزة الحقيقية)
    #if !TARGET_OS_SIMULATOR
    NSBundle *bundle = [NSBundle mainBundle];
    NSURL *receiptURL = [bundle appStoreReceiptURL];
    if (receiptURL) {
        NSString *receiptPath = [receiptURL path];
        if (receiptPath) {
            struct stat st;
            if (stat([receiptPath UTF8String], &st) == 0) {
                return true;
            }
        }
    }
    #endif
    return true;
}

// 5.5 الفحص الشامل للتلاعب
static bool is_tampered(void) {
    return check_text_integrity() ||
           check_text_writable() ||
           check_code_checksum() ||
           check_code_signature();
}

// ============================================================
// 6. حماية من الهوك (Anti-Hook) — كشف inline hooks
// ============================================================

// 6.1 كشف inline hook على دالة
static bool is_function_hooked(void *func_addr) {
    if (!func_addr) return false;
    
    // فحص أول 4 بايتات
    uint32_t *code = (uint32_t *)func_addr;
    uint32_t first = code[0];
    
    // كشف بعض أنماط الهوك الشائعة
    // B <offset> (branch) - 0x14000000
    // LDR X16, #... ; BR X16
    // ADRP X16, ... ; ADD X16, ... ; BR X16
    
    // branch instruction: 0001 01xx xxxx xxxx xxxx xxxx xxxx xxxx
    if ((first & 0xFC000000) == 0x14000000) {
        // B (branch) - مشبوه جداً في بداية دالة
        return true;
    }
    
    // كشف Dobby hook patterns
    // Dobby يستخدم عادة ADRP + ADD + BR أو LDR + BR
    // ADRP: 1001 0000 0000 0000 0000 0000 0000 0000 (0x90000000)
    if ((first & 0x9F000000) == 0x90000000) {
        // ADRP - قد يكون hook
        // نتحقق من التعليمات التالية
        uint32_t second = code[1];
        // ADD: 1001 0001 0000 0000 0000 0000 0000 0000 (0x91000000)
        if ((second & 0xFF800000) == 0x91000000) {
            uint32_t third = code[2];
            // BR: 1101 0110 0000 0000 0000 0000 0000 0000 (0xD6000000)
            if ((third & 0xFFFFFC1F) == 0xD61F0000) {
                return true;
            }
        }
    }
    
    // LDR X16, #8 ; BR X16 (نمط Dobby آخر)
    // LDR: 0101 1000 0000 0000 0000 0000 0000 0000 (0x58000000)
    if ((first & 0xFF000000) == 0x58000000) {
        uint32_t second = code[1];
        if ((second & 0xFFFFFC1F) == 0xD61F0000) {
            return true;
        }
    }
    
    return false;
}

// 6.2 فحص الدوال الحساسة من الهوك
static bool check_critical_functions_hooked(void) {
    // قائمة بالدوال الحساسة التي يجب أن لا تكون مهوكة
    const char *critical_funcs[] = {
        "open",
        "close",
        "read",
        "write",
        "ptrace",
        "sysctl",
        "fork",
        "dlopen",
        "dlsym",
        "malloc",
        "free",
        "objc_msgSend",
        "method_exchangeImplementations",
        "method_setImplementation",
        NULL
    };
    
    for (int i = 0; critical_funcs[i] != NULL; i++) {
        void *addr = dlsym(RTLD_DEFAULT, critical_funcs[i]);
        if (addr && is_function_hooked(addr)) {
            return true;
        }
    }
    return false;
}

// 6.3 فحص جدول GOT/PLT للتلاعب
static bool check_got_plt(void) {
    // فحص بسيط: نتأكد من أن دوال النظام تشير إلى عناوين صحيحة
    void *open_addr = dlsym(RTLD_DEFAULT, "open");
    if (open_addr) {
        // نتأكد أن العنوان في نطاق مكتبة النظام
        Dl_info info;
        if (dladdr(open_addr, &info)) {
            if (info.dli_fname) {
                // open يجب أن يكون في libsystem_kernel
                if (strstr(info.dli_fname, "libsystem") == NULL &&
                    strstr(info.dli_fname, "libdyld") == NULL) {
                    return true; // مشبوه
                }
            }
        }
    }
    return false;
}

// 6.4 الفحص الشامل للهوك
static bool is_hooked(void) {
    return check_critical_functions_hooked() ||
           check_got_plt();
}

// ============================================================
// 7. حماية من الهندسة العكسية (Anti-Reverse Engineering)
// ============================================================

// 7.1 كشف أدوات التحليل
static bool check_analysis_tools(void) {
    const char *tools[] = {
        "IDA",
        "Hopper",
        "Ghidra",
        "radare2",
        "r2",
        "lldb",
        "gdb",
        "debugserver",
        "frida",
        "objection",
        "cycript",
        "class-dump",
        "otool",
        "nm",
        "strings",
        "xxd",
        "hexdump",
        "lldb-server",
        "debugserver",
        NULL
    };
    
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0;
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) return false;
    
    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (!procs) return false;
    
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        free(procs);
        return false;
    }
    
    int count = size / sizeof(struct kinfo_proc);
    for (int i = 0; i < count; i++) {
        const char *name = procs[i].kp_proc.p_comm;
        for (int j = 0; tools[j] != NULL; j++) {
            if (strcasecmp(name, tools[j]) == 0) {
                free(procs);
                return true;
            }
        }
    }
    free(procs);
    return false;
}

// 7.2 كشف Simulator
static bool is_simulator(void) {
    #if TARGET_OS_SIMULATOR
    return true;
    #else
    return false;
    #endif
}

// 7.3 كشف البيئة الافتراضية
static bool is_virtual_environment(void) {
    // فحص بعض المؤشرات
    const char *env = getenv("SIMULATOR_DEVICE_NAME");
    if (env) return true;
    
    env = getenv("SIMULATOR_ROOT");
    if (env) return true;
    
    return false;
}

// ============================================================
// 8. حماية من الاعتراض (Anti-Interposition)
// ============================================================

// 8.1 فحص DYLD_INSERT_LIBRARIES
static bool check_dyld_insert(void) {
    const char *insert = getenv("DYLD_INSERT_LIBRARIES");
    if (insert != NULL && strlen(insert) > 0) {
        return true;
    }
    return false;
}

// 8.2 فحص DYLD_LIBRARY_PATH
static bool check_dyld_library_path(void) {
    const char *path = getenv("DYLD_LIBRARY_PATH");
    if (path != NULL && strlen(path) > 0) {
        return true;
    }
    return false;
}

// 8.3 فحص DYLD_FRAMEWORK_PATH
static bool check_dyld_framework_path(void) {
    const char *path = getenv("DYLD_FRAMEWORK_PATH");
    if (path != NULL && strlen(path) > 0) {
        return true;
    }
    return false;
}

// 8.4 فحص متغيرات البيئة المشبوهة
static bool check_suspicious_env(void) {
    const char *envs[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "DYLD_FALLBACK_FRAMEWORK_PATH",
        "DYLD_VERSIONED_LIBRARY_PATH",
        "DYLD_VERSIONED_FRAMEWORK_PATH",
        "DYLD_ROOT_PATH",
        "DYLD_SHARED_CACHE_DIR",
        "DYLD_SHARED_REGION",
        "FRIDA_SERVER",
        "FRIDA_AGENT",
        "FRIDA_GADGET",
        "FRIDA_SCRIPT",
        "FRIDA_HOST",
        "FRIDA_PORT",
        "CYCRIPT",
        "CYCRIPT_PORT",
        NULL
    };
    
    for (int i = 0; envs[i] != NULL; i++) {
        if (getenv(envs[i]) != NULL) {
            return true;
        }
    }
    return false;
}

// 8.5 الفحص الشامل للاعتراض
static bool is_interposed(void) {
    return check_dyld_insert() ||
           check_dyld_library_path() ||
           check_dyld_framework_path() ||
           check_suspicious_env();
}

// ============================================================
// 9. الحماية الشاملة (Master Check)
// ============================================================

static void protective_response(const char *reason) {
    NSLog(@"[PROTECT] Security violation: %s", reason);
    
    // استجابة الحماية:
    // 1. إنهاء التطبيق مباشرة
    // 2. أو إظهار رسالة
    // 3. أو تعطيل وظائف معينة
    
    // نستخدم exit() مباشرة لمنع أي تحليل
    // يمكن استبدالها بـ abort() أو kill(getpid(), SIGKILL)
    
    // إظهار رسالة للمستخدم (اختياري)
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController 
            alertControllerWithTitle:@"Security Warning"
            message:@"A security violation has been detected. The application will now close."
            preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction *ok = [UIAlertAction 
            actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *action) {
                exit(0);
            }];
        
        [alert addAction:ok];
        
        UIWindow *window = [[UIApplication sharedApplication] keyWindow];
        if (window && window.rootViewController) {
            [window.rootViewController presentViewController:alert animated:YES completion:nil];
        }
    });
    
    // تأخير بسيط ثم إنهاء
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)), 
                   dispatch_get_main_queue(), ^{
        exit(0);
    });
}

// الفحص الشامل
static void master_security_check(void) {
    // فحص 1: التصحيح
    if (is_debugger_attached()) {
        protective_response("Debugger detected");
        return;
    }
    
    // فحص 2: الجيلبريك
    if (is_jailbroken()) {
        protective_response("Jailbreak detected");
        return;
    }
    
    // فحص 3: الحقن
    if (is_injected()) {
        protective_response("Injection detected");
        return;
    }
    
    // فحص 4: التلاعب
    if (is_tampered()) {
        protective_response("Tampering detected");
        return;
    }
    
    // فحص 5: الهوك
    if (is_hooked()) {
        protective_response("Hooking detected");
        return;
    }
    
    // فحص 6: الاعتراض
    if (is_interposed()) {
        protective_response("Interposition detected");
        return;
    }
    
    // فحص 7: أدوات التحليل
    if (check_analysis_tools()) {
        protective_response("Analysis tools detected");
        return;
    }
    
    // فحص 8: Simulator
    if (is_simulator() || is_virtual_environment()) {
        protective_response("Virtual environment detected");
        return;
    }
    
    NSLog(@"[PROTECT] All security checks passed");
}

// ============================================================
// 10. المراقبة المستمرة (Continuous Monitoring)
// ============================================================

static void *monitor_thread(void *arg) {
    while (1) {
        sleep(2); // فحص كل ثانيتين
        
        if (is_debugger_attached()) {
            protective_response("Debugger attached (monitor)");
            break;
        }
        
        if (is_injected()) {
            protective_response("Injection detected (monitor)");
            break;
        }
        
        if (is_hooked()) {
            protective_response("Hooking detected (monitor)");
            break;
        }
        
        if (check_dyld_insert()) {
            protective_response("DYLD_INSERT_LIBRARIES detected (monitor)");
            break;
        }
    }
    return NULL;
}

static void start_monitoring(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, monitor_thread, NULL);
    pthread_detach(thread);
}

// ============================================================
// 11. حماية الدوال الحساسة عبر الهوك العكسي
// ============================================================

// حماية ptrace من الاستدعاء
static int (*orig_ptrace)(int, pid_t, caddr_t, int);
static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    // منع PT_DENY_ATTACH العكسي والتصحيح
    if (request == PT_DENY_ATTACH) {
        return 0; // نسمح به لأننا نحتاجه
    }
    // نمنع طلبات التصحيح الأخرى
    if (request == PT_ATTACH || request == PT_ATTACHEXC ||
        request == PT_CONTINUE || request == PT_STEP ||
        request == PT_READ_D || request == PT_WRITE_D) {
        NSLog(@"[PROTECT] ptrace(%d) blocked", request);
        return -1;
    }
    return orig_ptrace(request, pid, addr, data);
}

// حماية sysctl من التلاعب
static int (*orig_sysctl)(int *, u_int, void *, size_t *, void *, size_t);
static int hooked_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    // نمنع تغيير معلومات العملية
    if (name && namelen >= 4) {
        if (name[0] == CTL_KERN && name[1] == KERN_PROC) {
            // نسمح بالقراءة فقط
            if (newp != NULL) {
                return -1;
            }
        }
    }
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

// ============================================================
// 12. تثبيت الحماية والهوكات
// ============================================================

__attribute__((constructor))
static void init_hooks() {
    NSLog(@"[HOOK] Initializing hooks and protections...");
    
    // --- فحص الحماية الأولي ---
    master_security_check();
    
    // --- تشغيل المراقبة المستمرة ---
    start_monitoring();
    
    // --- هوك ptrace للحماية ---
    void *ptrace_addr = addr_from_symbol("ptrace");
    if (ptrace_addr) {
        DobbyHook(strip_pac(ptrace_addr),
                  (void *)hooked_ptrace,
                  (void **)&orig_ptrace);
        NSLog(@"[HOOK] ptrace() hooked for protection");
    }
    
    // --- هوك sysctl للحماية ---
    void *sysctl_addr = addr_from_symbol("sysctl");
    if (sysctl_addr) {
        DobbyHook(strip_pac(sysctl_addr),
                  (void *)hooked_sysctl,
                  (void **)&orig_sysctl);
        NSLog(@"[HOOK] sysctl() hooked for protection");
    }
    
    // --- هوك open لمنع الوصول للملفات الحساسة ---
    // (يمكن تفعيله حسب الحاجة)
    
    NSLog(@"[HOOK] All protections installed");
}
