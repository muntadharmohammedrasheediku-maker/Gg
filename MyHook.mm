// ============================================================
// MyHook.mm — iOS Hook + Full Protections
// Target: iOS 14.0+ | Arch: arm64 + arm64e
// Fixed: ptrace manual declaration (sys/ptrace.h not on iOS)
// ============================================================

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <mach-o/getsect.h>
#import <mach-o/nlist.h>
#import <dlfcn.h>
#import <ptrauth.h>
#import <sys/sysctl.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/mman.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <unistd.h>
#import <signal.h>
#import <errno.h>
#import <string.h>
#import <stdlib.h>
#import <pthread.h>
#import <execinfo.h>
#import <mach/mach.h>
#import <mach/vm_map.h>

// ⚠️ sys/ptrace.h غير موجود في iOS SDK — نُعرّفه يدوياً
// ============================================================
// ptrace manual definitions (from sys/ptrace.h)
// ============================================================
#define PT_TRACE_ME     0
#define PT_READ_I       1
#define PT_READ_D       2
#define PT_READ_U       3
#define PT_WRITE_I      4
#define PT_WRITE_D      5
#define PT_WRITE_U      6
#define PT_CONTINUE     7
#define PT_KILL         8
#define PT_STEP         9
#define PT_ATTACH       10
#define PT_DETACH       11
#define PT_SIGEXC       12
#define PT_THUPDATE     13
#define PT_ATTACHEXC    14
#define PT_FORCEQUOTA   30
#define PT_DENY_ATTACH  31
#define PT_FREEZE       32
#define PT_THAW         33

extern int ptrace(int _request, pid_t _pid, caddr_t _addr, int _data);

// ============================================================
// Dobby — لاحظ: dobby.h (حروف صغيرة)
// ============================================================
#include "dobby.h"

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

static bool is_ptraced(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));
    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

static bool is_debugger_attached_sysctl(void) {
    return is_ptraced();
}

static bool is_debugger_attached(void) {
    return is_ptraced() || is_debugger_attached_sysctl();
}

// ============================================================
// 3. حماية من الجيلبريك (Anti-Jailbreak)
// ============================================================

static bool check_jailbreak_files(void) {
    const char *jailbreak_paths[] = {
        "/Applications/Cydia.app",
        "/Applications/Sileo.app",
        "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/Library/MobileSubstrate/DynamicLibraries",
        "/var/lib/cydia",
        "/var/lib/dpkg",
        "/var/cache/apt",
        "/var/lib/apt",
        "/var/lib/dpkg/status",
        "/var/lib/dpkg/info",
        "/var/stash",
        "/var/tmp/cydia.log",
        "/private/var/lib/apt",
        "/private/var/lib/cydia",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
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
        "/usr/libexec/cydia",
        "/usr/libexec/cydia/firmware.sh",
        "/usr/bin/class-dump",
        "/usr/bin/class-dump-z",
        "/usr/bin/ldid",
        "/usr/bin/codesign",
        "/usr/bin/otool",
        "/usr/bin/lipo",
        "/var/jb",
        "/var/jb/usr/bin/ssh",
        "/var/jb/Library/MobileSubstrate",
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
        return true;
    }
    return false;
}

static bool check_fork(void) {
    pid_t pid = fork();
    if (pid >= 0) {
        if (pid == 0) _exit(0);
        return true;
    }
    return false;
}

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
            if (S_ISLNK(st.st_mode)) return true;
        }
    }
    return false;
}

static bool is_jailbroken(void) {
    return check_jailbreak_files() ||
           check_sandbox_violation() ||
           check_fork() ||
           check_suspicious_symlinks();
}

// ============================================================
// 4. حماية من الحقن (Anti-Injection)
// ============================================================

static bool check_suspicious_dylibs(void) {
    const char *suspicious[] = {
        "MobileSubstrate", "Substrate", "CydiaSubstrate",
        "SubstrateLoader", "SubstrateInjection", "TweakInject",
        "libsubstrate", "libhooker", "FridaGadget", "frida",
        "frida-agent", "frida-gadget", "cynject", "cycript",
        "libcycript", "SSLKillSwitch", "sslkillswitch",
        "Flex", "flexloader", "Anywhere", "Cephei",
        "RocketBootstrap", "PreferenceLoader", "PreferenceBundles",
        "AppList", "libcolorpicker", "libstatusbar",
        "libpackageinfo", "APTTimeOut", "NoCrash", "SafeMode",
        "Dobby", "dobby", "libdobby",
        "libfrida", "libfrida-gadget", "gadget", "libgadget",
        "substitute", "libsubstitute", "libellekit", "ellekit",
        "libSandy", "Sandy", "libKernBypass", "KernBypass",
        "libChoicy", "Choicy", "libHideJB", "HideJB",
        "libShadow", "Shadow", "libA-Bypass", "A-Bypass",
        "libBypass", "Bypass", "libFlyJB", "FlyJB",
        "libLiberty", "Liberty", "libLibertyLite", "LibertyLite",
        "libHestia", "Hestia", "libKernbypass", "Kernbypass",
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

static bool check_frida_ports(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(27042);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    close(sock);
    return (result == 0);
}

static bool is_injected(void) {
    return check_suspicious_dylibs() || check_frida_ports();
}

// ============================================================
// 5. حماية من التلاعب بالكود (Anti-Tamper)
// ============================================================

static bool check_text_integrity(void) {
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header) return false;
    if (header->magic != MH_MAGIC_64) return false;
    if (header->cputype != CPU_TYPE_ARM64) return false;
    if (header->filetype != MH_EXECUTE) return false;
    return false; // طبيعي
}

static bool check_text_writable(void) {
    const struct mach_header_64 *header =
        (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (!header) return false;
    
    vm_address_t addr = (vm_address_t)header;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t object_name;
    
    kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info,
                                    &info_count, &object_name);
    if (kr == KERN_SUCCESS) {
        if (info.protection & VM_PROT_WRITE) return true;
    }
    return false;
}

static bool is_tampered(void) {
    return check_text_writable();
}

// ============================================================
// 6. حماية من الهوك (Anti-Hook)
// ============================================================

static bool is_function_hooked(void *func_addr) {
    if (!func_addr) return false;
    uint32_t *code = (uint32_t *)func_addr;
    uint32_t first = code[0];
    
    if ((first & 0xFC000000) == 0x14000000) return true;
    
    if ((first & 0x9F000000) == 0x90000000) {
        uint32_t second = code[1];
        if ((second & 0xFF800000) == 0x91000000) {
            uint32_t third = code[2];
            if ((third & 0xFFFFFC1F) == 0xD61F0000) return true;
        }
    }
    
    if ((first & 0xFF000000) == 0x58000000) {
        uint32_t second = code[1];
        if ((second & 0xFFFFFC1F) == 0xD61F0000) return true;
    }
    
    return false;
}

static bool check_critical_functions_hooked(void) {
    const char *critical_funcs[] = {
        "open", "close", "read", "write", "ptrace",
        "sysctl", "fork", "dlopen", "dlsym",
        "malloc", "free", "objc_msgSend",
        "method_exchangeImplementations",
        "method_setImplementation",
        NULL
    };
    for (int i = 0; critical_funcs[i] != NULL; i++) {
        void *addr = dlsym(RTLD_DEFAULT, critical_funcs[i]);
        if (addr && is_function_hooked(addr)) return true;
    }
    return false;
}

static bool check_got_plt(void) {
    void *open_addr = dlsym(RTLD_DEFAULT, "open");
    if (open_addr) {
        Dl_info info;
        if (dladdr(open_addr, &info) && info.dli_fname) {
            if (strstr(info.dli_fname, "libsystem") == NULL &&
                strstr(info.dli_fname, "libdyld") == NULL) {
                return true;
            }
        }
    }
    return false;
}

static bool is_hooked(void) {
    return check_critical_functions_hooked() || check_got_plt();
}

// ============================================================
// 7. حماية من الهندسة العكسية
// ============================================================

static bool is_simulator(void) {
    #if TARGET_OS_SIMULATOR
    return true;
    #else
    return false;
    #endif
}

static bool is_virtual_environment(void) {
    if (getenv("SIMULATOR_DEVICE_NAME")) return true;
    if (getenv("SIMULATOR_ROOT")) return true;
    return false;
}

// ============================================================
// 8. حماية من الاعتراض (Anti-Interposition)
// ============================================================

static bool check_suspicious_env(void) {
    const char *envs[] = {
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "FRIDA_SERVER", "FRIDA_AGENT", "FRIDA_GADGET",
        "CYCRIPT", "CYCRIPT_PORT",
        NULL
    };
    for (int i = 0; envs[i] != NULL; i++) {
        if (getenv(envs[i]) != NULL) return true;
    }
    return false;
}

static bool is_interposed(void) {
    return check_suspicious_env();
}

// ============================================================
// 9. الاستجابة الأمنية
// ============================================================

static void protective_response(const char *reason) {
    NSLog(@"[PROTECT] Security violation: %s", reason);
    
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"Security Warning"
            message:@"A security violation has been detected. The application will now close."
            preferredStyle:UIAlertControllerStyleAlert];
        
        UIAlertAction *ok = [UIAlertAction
            actionWithTitle:@"OK"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *action) { exit(0); }];
        [alert addAction:ok];
        
        UIWindow *window = [[UIApplication sharedApplication] keyWindow];
        if (!window) {
            NSArray *windows = [[UIApplication sharedApplication] windows];
            if (windows.count > 0) window = windows[0];
        }
        if (window && window.rootViewController) {
            [window.rootViewController presentViewController:alert
                                                    animated:YES
                                                  completion:nil];
        }
    });
    
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{ exit(0); });
}

// ============================================================
// 10. الفحص الشامل
// ============================================================

static void master_security_check(void) {
    if (is_debugger_attached()) { protective_response("Debugger detected"); return; }
    if (is_jailbroken())        { protective_response("Jailbreak detected"); return; }
    if (is_injected())          { protective_response("Injection detected"); return; }
    if (is_tampered())          { protective_response("Tampering detected"); return; }
    if (is_hooked())            { protective_response("Hooking detected"); return; }
    if (is_interposed())        { protective_response("Interposition detected"); return; }
    if (is_simulator() || is_virtual_environment()) {
        protective_response("Virtual environment detected");
        return;
    }
    NSLog(@"[PROTECT] All security checks passed");
}

// ============================================================
// 11. المراقبة المستمرة
// ============================================================

static void *monitor_thread(void *arg) {
    while (1) {
        sleep(2);
        if (is_debugger_attached()) { protective_response("Debugger (monitor)"); break; }
        if (is_injected())          { protective_response("Injection (monitor)"); break; }
        if (is_hooked())            { protective_response("Hooking (monitor)"); break; }
        if (check_suspicious_env()) { protective_response("DYLD (monitor)"); break; }
    }
    return NULL;
}

static void start_monitoring(void) {
    pthread_t thread;
    pthread_create(&thread, NULL, monitor_thread, NULL);
    pthread_detach(thread);
}

// ============================================================
// 12. هوك ptrace للحماية
// ============================================================

static int (*orig_ptrace)(int, pid_t, caddr_t, int);

static int hooked_ptrace(int request, pid_t pid, caddr_t addr, int data) {
    if (request == PT_DENY_ATTACH) return 0;
    if (request == PT_ATTACH || request == PT_ATTACHEXC ||
        request == PT_CONTINUE || request == PT_STEP ||
        request == PT_READ_D || request == PT_WRITE_D) {
        NSLog(@"[PROTECT] ptrace(%d) blocked", request);
        return -1;
    }
    if (orig_ptrace) {
        return orig_ptrace(request, pid, addr, data);
    }
    return 0;
}

// ============================================================
// 13. نقطة الدخول
// ============================================================

__attribute__((constructor))
static void init_hooks() {
    NSLog(@"[HOOK] ======================================");
    NSLog(@"[HOOK] MyHook initializing...");
    NSLog(@"[HOOK] ======================================");
    
    // 1. فحص أمني أولي
    master_security_check();
    
    // 2. مراقبة مستمرة
    start_monitoring();
    
    // 3. حماية ptrace
    void *ptrace_addr = addr_from_symbol("ptrace");
    if (ptrace_addr) {
        DobbyHook(strip_pac(ptrace_addr),
                  (void *)hooked_ptrace,
                  (void **)&orig_ptrace);
        NSLog(@"[HOOK] ptrace() protected");
    }
    
    NSLog(@"[HOOK] ======================================");
    NSLog(@"[HOOK] All protections installed ✅");
    NSLog(@"[HOOK] ======================================");
}
