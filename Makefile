# ============================================================
# Theos Makefile — iOS Hook + Protections
# ============================================================

# ---------- المسارات ----------
THEOS_DEVICE_IP    ?= 
THEOS_DEVICE_PORT  ?= 22
ARCHS              ?= arm64 arm64e
TARGET             ?= iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES ?= 

# ---------- المتغيرات الأساسية ----------
include $(THEOS)/makefiles/common.mk

TWEAK_NAME         := MyHook

# ---------- الملفات المصدرية ----------
MyHook_FILES       := $(wildcard src/*.mm) $(wildcard src/*.m) $(wildcard src/*.cpp) $(wildcard src/*.c)
MyHook_CFLAGS      := -fobjc-arc -fmodules -fblocks \
                      -I$(THEOS_PROJECT_DIR)/src \
                      -I$(THEOS_PROJECT_DIR)/third_party/Dobby/include \
                      -DTARGET_OS_IPHONE=1 \
                      -Wno-deprecated-declarations \
                      -Wno-unused-function \
                      -Wno-unused-variable \
                      -Wno-format \
                      -O2

MyHook_CXXFLAGS    := $(MyHook_CFLAGS) -std=c++17 -fno-exceptions -fno-rtti

MyHook_OBJCFLAGS   := $(MyHook_CFLAGS)

MyHook_LDFLAGS     := -L$(THEOS_PROJECT_DIR)/third_party/Dobby \
                      -ldobby \
                      -framework Foundation \
                      -framework UIKit \
                      -framework Security \
                      -framework CoreGraphics \
                      -Wl,-undefined,dynamic_lookup

MyHook_FRAMEWORKS  := Foundation UIKit Security CoreGraphics

# ---------- Library (Dylib) بدل Tweak ----------
# إذا أردت بناء Tweak استخدم TWEAK_NAME
# إذا أردت Dylib استخدم LIBRARY_NAME

include $(THEOS_MAKE_PATH)/tweak.mk
# include $(THEOS_MAKE_PATH)/library.mk   # بديل للـ Dylib

# ---------- بعد البناء ----------
after-install::
	install.exec "killall -9 MyApp || true"
