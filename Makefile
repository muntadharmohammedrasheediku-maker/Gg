# ============================================================
# Theos Makefile — MyHook
# Structure: Flat (كل الملفات في الجذر)
# Supports: arm64 + arm64e
# ============================================================

# ---------- الإعدادات الأساسية ----------
ARCHS              ?= arm64 arm64e
TARGET             ?= iphone:clang:latest:14.0

# ---------- تضمين Theos ----------
include $(THEOS)/makefiles/common.mk

# ---------- اسم الـ Tweak ----------
TWEAK_NAME         := MyHook

# ---------- الملفات المصدرية (في الجذر) ----------
MyHook_FILES       := MyHook.mm

# ---------- أعلام المترجم ----------
MyHook_CFLAGS      := -fobjc-arc \
                      -fmodules \
                      -fblocks \
                      -I$(THEOS_PROJECT_DIR) \
                      -I$(THEOS_PROJECT_DIR)/include \
                      -DTARGET_OS_IPHONE=1 \
                      -DNDEBUG \
                      -O2 \
                      -Wno-deprecated-declarations \
                      -Wno-unused-function \
                      -Wno-unused-variable \
                      -Wno-format \
                      -Wno-everything

MyHook_CXXFLAGS    := $(MyHook_CFLAGS) -std=c++17

MyHook_OBJCFLAGS   := $(MyHook_CFLAGS)

# ---------- أعلام الربط ----------
MyHook_LDFLAGS     := -L$(THEOS_PROJECT_DIR) \
                      -ldobby \
                      -Wl,-undefined,dynamic_lookup \
                      -Wl,-segalign,4000

# ---------- الأطر المطلوبة ----------
MyHook_FRAMEWORKS  := Foundation \
                      UIKit \
                      Security \
                      CoreGraphics

MyHook_PRIVATE_FRAMEWORKS := 

# ---------- تضمين قواعد Tweak ----------
include $(THEOS_MAKE_PATH)/tweak.mk

# ---------- بعد التثبيت ----------
after-install::
	install.exec "killall -9 MyHookTargetApp || true"

# ---------- تنظيف إضافي ----------
after-clean::
	@rm -rf .theos packages .theos/_ 2>/dev/null || true
	@echo "✅ Cleaned"
