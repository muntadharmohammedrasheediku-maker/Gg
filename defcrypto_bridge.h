// ============================================================================
// defcrypto_bridge.h — جسر C بين C++ و ObjC
// ============================================================================

#ifndef DEFCRYPTO_BRIDGE_H
#define DEFCRYPTO_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// 1. تشفير/فك تشفير بمفتاح خام 32 بايت (AES-256-GCM افتراضياً)
// ----------------------------------------------------------------------------

// إرجاع 0 = نجاح، -1 = فشل
int sbxk_encrypt(const uint8_t *pt,  size_t pt_len,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

int sbxk_decrypt(const uint8_t *pkt, size_t pkt_len,
                 const uint8_t *key, size_t key_len,
                 const uint8_t *aad, size_t aad_len,
                 uint8_t *out, size_t out_cap, size_t *out_len);

// ----------------------------------------------------------------------------
// 2. تشفير/فك تشفير بكلمة مرور (KDF تلقائي)
// ----------------------------------------------------------------------------

int sbxk_encrypt_pwd(const uint8_t *pt,  size_t pt_len,
                     const uint8_t *pwd, size_t pwd_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

int sbxk_decrypt_pwd(const uint8_t *pkt, size_t pkt_len,
                     const uint8_t *pwd, size_t pwd_len,
                     const uint8_t *aad, size_t aad_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

// ----------------------------------------------------------------------------
// 3. تشفير/فك تشفير بث (للبيانات الكبيرة)
// ----------------------------------------------------------------------------

typedef int (*sbxk_read_fn)(void *ctx, uint8_t *buf, size_t cap, size_t *got);
typedef int (*sbxk_write_fn)(void *ctx, const uint8_t *buf, size_t len);

int sbxk_encrypt_stream(sbxk_read_fn rd, void *rd_ctx,
                        sbxk_write_fn wr, void *wr_ctx,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *aad, size_t aad_len,
                        size_t chunk_size);

int sbxk_decrypt_stream(sbxk_read_fn rd, void *rd_ctx,
                        sbxk_write_fn wr, void *wr_ctx,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *aad, size_t aad_len);

// ----------------------------------------------------------------------------
// 4. أدوات مساعدة
// ----------------------------------------------------------------------------

// توليد 32 بايت مفتاح عشوائي آمن
int sbxk_random_key(uint8_t *key_out);

// مسح آمن للمحتوى الحساس
void sbxk_wipe(void *p, size_t n);

// هل العتاد يدعم AES-NI (ARMv8 Crypto Extensions)؟
int sbxk_has_hw_aes(void);

#ifdef __cplusplus
}
#endif
#endif // DEFCRYPTO_BRIDGE_H
