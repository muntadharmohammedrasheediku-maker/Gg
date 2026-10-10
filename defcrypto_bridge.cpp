// ============================================================================
// defcrypto_bridge.cpp — تنفيذ الجسر C بين C++ و ObjC
// ============================================================================

#include "defcrypto_bridge.h"
#include "defcrypto.hpp"

#include <cstring>
#include <vector>
#include <iostream>
#include <sstream>
#include <openssl/rand.h>
#include <openssl/crypto.h>

using namespace defcrypto;

// ============================================================================
// 1. تشفير/فك تشفير بمفتاح خام 32 بايت
// ============================================================================

extern "C" int sbxk_encrypt(const uint8_t *pt,  size_t pt_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!key || !out || !out_len) return -1;
    if (key_len != 32) return -1;

    try {
        std::span<const uint8_t> pt_span(pt ? pt : (const uint8_t*)"", pt_len);
        std::span<const uint8_t> key_span(key, key_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        auto packet = CryptoBox::encrypt_message(pt_span, key_span, false, aad_span);
        if (packet.size() > out_cap) return -1;

        std::memcpy(out, packet.data(), packet.size());
        *out_len = packet.size();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] encrypt: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

extern "C" int sbxk_decrypt(const uint8_t *pkt, size_t pkt_len,
                            const uint8_t *key, size_t key_len,
                            const uint8_t *aad, size_t aad_len,
                            uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!pkt || !key || !out || !out_len) return -1;
    if (key_len != 32) return -1;

    try {
        std::span<const uint8_t> pkt_span(pkt, pkt_len);
        std::span<const uint8_t> key_span(key, key_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        auto pt = CryptoBox::decrypt_message(pkt_span, key_span, false, aad_span);
        if (pt.size() > out_cap) return -1;

        std::memcpy(out, pt.data(), pt.size());
        *out_len = pt.size();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] decrypt: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// 2. تشفير/فك تشفير بكلمة مرور (KDF تلقائي)
// ============================================================================

extern "C" int sbxk_encrypt_pwd(const uint8_t *pt,  size_t pt_len,
                                const uint8_t *pwd, size_t pwd_len,
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!pwd || !out || !out_len) return -1;
    if (pwd_len == 0) return -1;

    try {
        std::span<const uint8_t> pt_span(pt ? pt : (const uint8_t*)"", pt_len);
        std::span<const uint8_t> pwd_span(pwd, pwd_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        auto packet = CryptoBox::encrypt_message(pt_span, pwd_span, true, aad_span);
        if (packet.size() > out_cap) return -1;

        std::memcpy(out, packet.data(), packet.size());
        *out_len = packet.size();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] encrypt_pwd: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

extern "C" int sbxk_decrypt_pwd(const uint8_t *pkt, size_t pkt_len,
                                const uint8_t *pwd, size_t pwd_len,
                                const uint8_t *aad, size_t aad_len,
                                uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!pkt || !pwd || !out || !out_len) return -1;
    if (pwd_len == 0) return -1;

    try {
        std::span<const uint8_t> pkt_span(pkt, pkt_len);
        std::span<const uint8_t> pwd_span(pwd, pwd_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        auto pt = CryptoBox::decrypt_message(pkt_span, pwd_span, true, aad_span);
        if (pt.size() > out_cap) return -1;

        std::memcpy(out, pt.data(), pt.size());
        *out_len = pt.size();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] decrypt_pwd: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// 3. تشفير/فك تشفير بث (Streaming)
// ============================================================================

namespace {

// ★ التصحيح: المخزن صار char* حتى يطابق streambuf::setg المطلوب
class CallbackIStreamBuf : public std::streambuf {
public:
    CallbackIStreamBuf(sbxk_read_fn rd, void *ctx) : rd_(rd), ctx_(ctx) {}
protected:
    int_type underflow() override {
        size_t got = 0;
        int rc = rd_(ctx_, reinterpret_cast<uint8_t*>(buf_), sizeof(buf_), &got);
        if (rc != 0 || got == 0) return traits_type::eof();
        setg(buf_, buf_, buf_ + got);
        return traits_type::to_int_type(*gptr());
    }
private:
    sbxk_read_fn rd_;
    void        *ctx_;
    char         buf_[64 * 1024];
};

class CallbackOStreamBuf : public std::streambuf {
public:
    CallbackOStreamBuf(sbxk_write_fn wr, void *ctx) : wr_(wr), ctx_(ctx) {}
protected:
    int_type overflow(int_type ch) override {
        if (ch != traits_type::eof()) {
            char c = static_cast<char>(ch);
            if (wr_(ctx_, reinterpret_cast<const uint8_t*>(&c), 1) != 0)
                return traits_type::eof();
        }
        return ch;
    }
    std::streamsize xsputn(const char *s, std::streamsize n) override {
        if (wr_(ctx_, reinterpret_cast<const uint8_t*>(s), static_cast<size_t>(n)) != 0)
            return 0;
        return n;
    }
private:
    sbxk_write_fn wr_;
    void         *ctx_;
};

} // namespace

extern "C" int sbxk_encrypt_stream(sbxk_read_fn rd, void *rd_ctx,
                                   sbxk_write_fn wr, void *wr_ctx,
                                   const uint8_t *key, size_t key_len,
                                   const uint8_t *aad, size_t aad_len,
                                   size_t chunk_size)
{
    if (!rd || !wr || !key) return -1;
    if (key_len != 32) return -1;

    try {
        CallbackIStreamBuf ib(rd, rd_ctx);
        CallbackOStreamBuf ob(wr, wr_ctx);
        std::istream in(&ib);
        std::ostream out(&ob);

        std::span<const uint8_t> key_span(key, key_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        CryptoOptions opts;
        opts.chunk_size = chunk_size ? chunk_size : (1024 * 1024);

        CryptoBox::encrypt_stream(in, out, key_span, false, aad_span, opts);
        out.flush();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] encrypt_stream: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

extern "C" int sbxk_decrypt_stream(sbxk_read_fn rd, void *rd_ctx,
                                   sbxk_write_fn wr, void *wr_ctx,
                                   const uint8_t *key, size_t key_len,
                                   const uint8_t *aad, size_t aad_len)
{
    if (!rd || !wr || !key) return -1;
    if (key_len != 32) return -1;

    try {
        CallbackIStreamBuf ib(rd, rd_ctx);
        CallbackOStreamBuf ob(wr, wr_ctx);
        std::istream in(&ib);
        std::ostream out(&ob);

        std::span<const uint8_t> key_span(key, key_len);
        std::span<const uint8_t> aad_span(aad ? aad : (const uint8_t*)"", aad_len);

        CryptoBox::decrypt_stream(in, out, key_span, false, aad_span);
        out.flush();
        return 0;
    } catch (const std::exception &e) {
        std::cerr << "[bridge] decrypt_stream: " << e.what() << "\n";
        return -1;
    } catch (...) {
        return -1;
    }
}

// ============================================================================
// 4. أدوات مساعدة
// ============================================================================

extern "C" int sbxk_random_key(uint8_t *key_out) {
    if (!key_out) return -1;
    if (RAND_bytes(key_out, 32) != 1) return -1;
    return 0;
}

extern "C" void sbxk_wipe(void *p, size_t n) {
    if (p && n) OPENSSL_cleanse(p, n);
}

extern "C" int sbxk_has_hw_aes(void) {
    return CryptoBox::has_hardware_aes() ? 1 : 0;
}
