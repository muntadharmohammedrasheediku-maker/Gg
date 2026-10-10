// ============================================================================
// defcrypto.cpp — OpenSSL 3.x EVP-based encryption library
// ============================================================================

#include "defcrypto.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <bit>

// --- المروسات الشرطية الخاصة بالتوافق مع المنصات متعددة البيئات وخاصة iOS ---
#if defined(__APPLE__)
    #include <TargetConditionals.h>
    #include <sys/mman.h>
#elif defined(_WIN32) || defined(_WIN64)
    #include <windows.h>
#else
    #include <sys/mman.h>
#endif

namespace defcrypto {

namespace {

// ثوابت البروتوكول والأمان للعلامة المائية ورأس الحزمة
constexpr uint8_t MAGIC[4] = {'D', 'E', 'F', 'X'};
constexpr uint16_t PROTOCOL_VERSION = 0x0001;
constexpr size_t KEY_SIZE = 32;       // 256 bits
constexpr size_t IV_SIZE = 12;        // 96 bits for AEAD (GCM / Poly1305)
constexpr size_t TAG_SIZE = 16;       // 128 bits Authentication Tag
constexpr size_t SALT_SIZE = 16;      // 128 bits KDF Salt
constexpr size_t HEADER_MIN_SIZE = 44; // الحجم الثابت الأدنى لرأس الحزمة (Header)

constexpr uint8_t FLAG_PASSWORD = 0x01;
constexpr uint8_t FLAG_STREAMING = 0x02;

// --- تحويلات Endianness آمنة ومستقلة عن المنصة (Big-Endian Network Byte Order) ---

inline void write_u16_be(uint8_t* out, uint16_t val) noexcept {
    out[0] = static_cast<uint8_t>((val >> 8) & 0xFF);
    out[1] = static_cast<uint8_t>(val & 0xFF);
}

inline uint16_t read_u16_be(const uint8_t* in) noexcept {
    return (static_cast<uint16_t>(in[0]) << 8) | static_cast<uint16_t>(in[1]);
}

inline void write_u32_be(uint8_t* out, uint32_t val) noexcept {
    out[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    out[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    out[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    out[3] = static_cast<uint8_t>(val & 0xFF);
}

inline uint32_t read_u32_be(const uint8_t* in) noexcept {
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8)  |
            static_cast<uint32_t>(in[3]);
}

inline void write_u64_be(uint8_t* out, uint64_t val) noexcept {
    for (int i = 0; i < 8; ++i) {
        out[i] = static_cast<uint8_t>((val >> (56 - i * 8)) & 0xFF);
    }
}

inline uint64_t read_u64_be(const uint8_t* in) noexcept {
    uint64_t val = 0;
    for (int i = 0; i < 8; ++i) {
        val = (val << 8) | static_cast<uint64_t>(in[i]);
    }
    return val;
}

// مولد الأرقام العشوائية الآمن تشفيرياً (CSPRNG)
void generate_random(std::span<uint8_t> buffer) {
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw CryptoException("Failed to generate cryptographically secure random bytes.");
    }
}

// أغلفة RAII لإدارة كائنات OpenSSL 3.x تلقائياً
struct EvpCipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { if (ctx) EVP_CIPHER_CTX_free(ctx); }
};
using ScopedCipherCtx = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;

struct EvpCipherDeleter {
    void operator()(EVP_CIPHER* cipher) const { if (cipher) EVP_CIPHER_free(cipher); }
};
using ScopedCipher = std::unique_ptr<EVP_CIPHER, EvpCipherDeleter>;

struct EvpKdfDeleter {
    void operator()(EVP_KDF* kdf) const { if (kdf) EVP_KDF_free(kdf); }
};
using ScopedKdf = std::unique_ptr<EVP_KDF, EvpKdfDeleter>;

struct EvpKdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const { if (ctx) EVP_KDF_CTX_free(ctx); }
};
using ScopedKdfCtx = std::unique_ptr<EVP_KDF_CTX, EvpKdfCtxDeleter>;

} // namespace

// ============================================================================
// --- تنفيذ SecureBuffer المحصّن المتوافق مع iOS/Linux/Windows ---
// ============================================================================

void SecureBuffer::lock_memory() noexcept {
    if (!ptr_ || size_ == 0) return;

#if defined(_WIN32) || defined(_WIN64)
    VirtualLock(ptr_, size_);
#elif defined(__APPLE__) && TARGET_OS_IPHONE
    (void)mlock(ptr_, size_);
#else
    #if defined(MCL_CURRENT) || defined(__unix__) || defined(__APPLE__)
        (void)mlock(ptr_, size_);
    #endif
#endif
}

void SecureBuffer::unlock_memory() noexcept {
    if (!ptr_ || size_ == 0) return;

#if defined(_WIN32) || defined(_WIN64)
    VirtualUnlock(ptr_, size_);
#elif defined(__APPLE__) && TARGET_OS_IPHONE
    (void)munlock(ptr_, size_);
#else
    #if defined(MCL_CURRENT) || defined(__unix__) || defined(__APPLE__)
        (void)munlock(ptr_, size_);
    #endif
#endif
}

SecureBuffer::SecureBuffer(size_t size) : size_(size), capacity_(size) {
    if (size_ > 0) {
        ptr_ = new (std::nothrow) uint8_t[size_];
        if (!ptr_) throw CryptoException("Memory allocation failed.");
        std::memset(ptr_, 0, size_);
        lock_memory();
    }
}

SecureBuffer::SecureBuffer(std::span<const uint8_t> init_data) : SecureBuffer(init_data.size()) {
    if (size_ > 0 && ptr_) {
        std::memcpy(ptr_, init_data.data(), size_);
    }
}

SecureBuffer::~SecureBuffer() {
    wipe();
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept 
    : ptr_(other.ptr_), size_(other.size_), capacity_(other.capacity_) {
    other.ptr_ = nullptr;
    other.size_ = 0;
    other.capacity_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        wipe();
        ptr_ = other.ptr_;
        size_ = other.size_;
        capacity_ = other.capacity_;
        other.ptr_ = nullptr;
        other.size_ = 0;
        other.capacity_ = 0;
    }
    return *this;
}

void SecureBuffer::resize(size_t new_size) {
    if (new_size <= capacity_) {
        size_ = new_size;
        return;
    }
    auto new_ptr = new (std::nothrow) uint8_t[new_size];
    if (!new_ptr) throw CryptoException("Memory allocation failed during resize.");
    std::memset(new_ptr, 0, new_size);

    if (ptr_) {
        std::memcpy(new_ptr, ptr_, size_);
        OPENSSL_cleanse(ptr_, capacity_);
        unlock_memory();
        delete[] ptr_;
    }

    ptr_ = new_ptr;
    size_ = new_size;
    capacity_ = new_size;
    lock_memory();
}

void SecureBuffer::wipe() noexcept {
    if (ptr_) {
        OPENSSL_cleanse(ptr_, capacity_);
        unlock_memory();
        delete[] ptr_;
        ptr_ = nullptr;
    }
    size_ = 0;
    capacity_ = 0;
}

// ============================================================================
// --- إدارة المفاتيح وخوارزميات الاشتقاق (Key Management & KDF) ---
// ============================================================================

bool CryptoBox::has_hardware_aes() noexcept {
    ScopedCipher cipher(EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr));
    return cipher != nullptr;
}

namespace {

// اشتقاق فرعي لمفاتيح التشفير عبر HKDF-SHA256
SecureBuffer hkdf_expand(std::span<const uint8_t> ikm, std::span<const uint8_t> salt, std::span<const uint8_t> info, size_t out_len) {
    ScopedKdf kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr));
    if (!kdf) throw CryptoException("Failed to fetch HKDF algorithm.");

    ScopedKdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw CryptoException("Failed to create HKDF context.");

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    if (!bld) throw CryptoException("Failed to allocate OSSL_PARAM_BLD.");

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_KEY, ikm.data(), ikm.size());
    if (!salt.empty()) {
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
    }
    if (!info.empty()) {
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_INFO, info.data(), info.size());
    }

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    if (!params) throw CryptoException("Failed to build HKDF parameters.");

    SecureBuffer derived(out_len);
    int res = EVP_KDF_derive(ctx.get(), derived.data(), out_len, params);
    OSSL_PARAM_free(params);

    if (res <= 0) {
        throw CryptoException("HKDF key derivation failed.");
    }
    return derived;
}

// اشتقاق المفاتيح من كلمات المرور (Argon2id -> Scrypt -> PBKDF2)
SecureBuffer derive_key_from_password(
    std::span<const uint8_t> password,
    std::span<const uint8_t> salt,
    KdfType& selected_kdf,
    const CryptoOptions& options) 
{
    SecureBuffer derived_key(KEY_SIZE);

    // 1. محاولة Argon2id (المتاحة في OpenSSL 3.2+)
    if (selected_kdf == KdfType::Auto || selected_kdf == KdfType::Argon2id) {
        ScopedKdf kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr));
        if (kdf) {
            ScopedKdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
            if (ctx) {
                OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
                uint64_t mem_kb  = options.memory_cost_mb * 1024;
                uint64_t threads = 4;
                uint64_t iter    = options.iterations;

                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_PASSWORD,
                                                 password.data(), password.size());
                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT,
                                                 salt.data(), salt.size());
#if defined(OSSL_KDF_PARAM_ARGON2_MEMCOST)
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_ARGON2_MEMCOST, mem_kb);
#else
                OSSL_PARAM_BLD_push_uint64(bld, "memcost", mem_kb);
#endif
#if defined(OSSL_KDF_PARAM_ARGON2_LANES)
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_ARGON2_LANES, threads);
#else
                OSSL_PARAM_BLD_push_uint64(bld, "lanes", threads);
#endif
#if defined(OSSL_KDF_PARAM_THREADS)
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_THREADS, threads);
#else
                OSSL_PARAM_BLD_push_uint64(bld, "threads", threads);
#endif
#if defined(OSSL_KDF_PARAM_ITER)
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_ITER, iter);
#else
                OSSL_PARAM_BLD_push_uint64(bld, "iter", iter);
#endif

                OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
                OSSL_PARAM_BLD_free(bld);

                if (params) {
                    int res = EVP_KDF_derive(ctx.get(), derived_key.data(), KEY_SIZE, params);
                    OSSL_PARAM_free(params);
                    if (res > 0) {
                        selected_kdf = KdfType::Argon2id;
                        return derived_key;
                    }
                }
            }
        }
        if (selected_kdf == KdfType::Argon2id) {
            throw CryptoException("Argon2id KDF requested but unsupported by OpenSSL engine.");
        }
    }

    // 2. محاولة Scrypt (الافتراضية المعتمدة في OpenSSL 3.0+)
    if (selected_kdf == KdfType::Auto || selected_kdf == KdfType::Scrypt) {
        ScopedKdf kdf(EVP_KDF_fetch(nullptr, "SCRYPT", nullptr));
        if (kdf) {
            ScopedKdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
            if (ctx) {
                OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
                uint64_t N = 1ULL << 15; // N=32768 (~32MB RAM)
                uint64_t r = 8;
                uint64_t p = 1;

                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_PASSWORD, password.data(), password.size());
                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_SCRYPT_N, N);
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_SCRYPT_R, r);
                OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_SCRYPT_P, p);

                OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
                OSSL_PARAM_BLD_free(bld);

                if (params) {
                    int res = EVP_KDF_derive(ctx.get(), derived_key.data(), KEY_SIZE, params);
                    OSSL_PARAM_free(params);
                    if (res > 0) {
                        selected_kdf = KdfType::Scrypt;
                        return derived_key;
                    }
                }
            }
        }
        if (selected_kdf == KdfType::Scrypt) {
            throw CryptoException("Scrypt KDF derivation failed.");
        }
    }

    // 3. الخيار الاحتياطي الأخير: PBKDF2-HMAC-SHA256
    ScopedKdf kdf(EVP_KDF_fetch(nullptr, "PBKDF2", nullptr));
    if (!kdf) throw CryptoException("No suitable KDF algorithm available.");

    ScopedKdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw CryptoException("Failed to create PBKDF2 context.");

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    uint64_t iter = 210000;

    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_KDF_PARAM_DIGEST, "SHA256", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_PASSWORD, password.data(), password.size());
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
    OSSL_PARAM_BLD_push_uint64(bld, OSSL_KDF_PARAM_ITER, iter);

    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    OSSL_PARAM_BLD_free(bld);

    if (!params || EVP_KDF_derive(ctx.get(), derived_key.data(), KEY_SIZE, params) <= 0) {
        if (params) OSSL_PARAM_free(params);
        throw CryptoException("PBKDF2 key derivation failed.");
    }
    OSSL_PARAM_free(params);
    selected_kdf = KdfType::PBKDF2_SHA256;
    return derived_key;
}

ScopedCipher get_cipher_obj(Algorithm alg) {
    const char* cipher_name = nullptr;
    if (alg == Algorithm::AES_256_GCM) {
        cipher_name = "AES-256-GCM";
    } else if (alg == Algorithm::ChaCha20_Poly1305) {
        cipher_name = "ChaCha20-Poly1305";
    } else {
        throw CryptoException("Invalid algorithm selection.");
    }

    ScopedCipher cipher(EVP_CIPHER_fetch(nullptr, cipher_name, nullptr));
    if (!cipher) {
        throw CryptoException(std::string("Failed to fetch cipher algorithm: ") + cipher_name);
    }
    return cipher;
}

} // namespace

// ============================================================================
// --- تنفيذ تشفير وفك تشفير الرسائل (Single Message API) ---
// ============================================================================

SecureBuffer CryptoBox::encrypt_message(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> key_or_password,
    bool is_password,
    std::span<const uint8_t> aad,
    CryptoOptions options) 
{
    if (key_or_password.empty()) {
        throw CryptoException("Key or password cannot be empty.");
    }

    Algorithm selected_alg = options.algorithm;
    if (selected_alg == Algorithm::Auto) {
        selected_alg = Algorithm::AES_256_GCM;
    }

    uint8_t flags = 0;
    KdfType selected_kdf = KdfType::None;
    uint8_t salt[SALT_SIZE] = {0};

    SecureBuffer master_key;
    if (is_password) {
        flags |= FLAG_PASSWORD;
        generate_random(salt);
        selected_kdf = options.kdf_type;
        master_key = derive_key_from_password(key_or_password, salt, selected_kdf, options);
    } else {
        if (key_or_password.size() != KEY_SIZE) {
            throw CryptoException("Raw encryption key must be exactly 32 bytes (256 bits).");
        }
        master_key = SecureBuffer(key_or_password);
    }

    const char* hkdf_info = "DEFX-V1-MESSAGE-KEY";
    SecureBuffer enc_key = hkdf_expand(master_key.span(), salt,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hkdf_info), std::strlen(hkdf_info)),
        KEY_SIZE);

    uint8_t nonce[IV_SIZE];
    generate_random(nonce);

    size_t aad_len = aad.size();
    size_t header_size = HEADER_MIN_SIZE + aad_len;
    size_t total_packet_size = header_size + sizeof(uint64_t) + plaintext.size() + TAG_SIZE;

    SecureBuffer packet(total_packet_size);
    uint8_t* p = packet.data();

    std::memcpy(p, MAGIC, 4); p += 4;
    write_u16_be(p, PROTOCOL_VERSION); p += 2;
    *p++ = static_cast<uint8_t>(selected_alg);
    *p++ = flags;
    *p++ = static_cast<uint8_t>(selected_kdf);
    std::memset(p, 0, 3); p += 3;
    std::memcpy(p, salt, SALT_SIZE); p += SALT_SIZE;
    std::memcpy(p, nonce, IV_SIZE); p += IV_SIZE;
    write_u32_be(p, static_cast<uint32_t>(aad_len)); p += 4;

    if (aad_len > 0) {
        std::memcpy(p, aad.data(), aad_len);
        p += aad_len;
    }

    write_u64_be(p, static_cast<uint64_t>(plaintext.size())); p += 8;

    uint8_t* ciphertext_ptr = p;
    uint8_t* tag_ptr = ciphertext_ptr + plaintext.size();

    ScopedCipher cipher = get_cipher_obj(selected_alg);
    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoException("Failed to create cipher context.");

    OSSL_PARAM cipher_params[2];
    size_t iv_len = IV_SIZE;
    cipher_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len);
    cipher_params[1] = OSSL_PARAM_construct_end();

    if (EVP_EncryptInit_ex2(ctx.get(), cipher.get(), enc_key.data(), nonce, cipher_params) != 1) {
        throw CryptoException("Failed to initialize encryption context.");
    }

    std::span<const uint8_t> header_aad(packet.data(), header_size);
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, header_aad.data(),
                          static_cast<int>(header_aad.size())) != 1) {
        throw CryptoException("Failed to process header AAD.");
    }

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), ciphertext_ptr, &out_len, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1) {
            throw CryptoException("Encryption update failed.");
        }
    }

    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext_ptr + out_len, &out_len) != 1) {
        throw CryptoException("Encryption finalization failed.");
    }

    OSSL_PARAM tag_params[2];
    tag_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag_ptr, TAG_SIZE);
    tag_params[1] = OSSL_PARAM_construct_end();

    if (EVP_CIPHER_CTX_get_params(ctx.get(), tag_params) != 1) {
        throw CryptoException("Failed to retrieve AEAD authentication tag.");
    }

    return packet;
}

SecureBuffer CryptoBox::decrypt_message(
    std::span<const uint8_t> packet,
    std::span<const uint8_t> key_or_password,
    bool is_password,
    std::span<const uint8_t> aad) 
{
    if (packet.size() < HEADER_MIN_SIZE + sizeof(uint64_t) + TAG_SIZE) {
        throw CryptoException("Authentication failed: invalid or truncated ciphertext.");
    }

    const uint8_t* p = packet.data();

    if (std::memcmp(p, MAGIC, 4) != 0) {
        throw CryptoException("Authentication failed: invalid magic header.");
    }
    p += 4;

    uint16_t version = read_u16_be(p); p += 2;
    if (version != PROTOCOL_VERSION) {
        throw CryptoException("Authentication failed: unsupported protocol version.");
    }

    Algorithm alg = static_cast<Algorithm>(*p++);
    uint8_t flags = *p++;
    KdfType kdf_type = static_cast<KdfType>(*p++);
    p += 3;

    const uint8_t* salt = p; p += SALT_SIZE;
    const uint8_t* nonce = p; p += IV_SIZE;
    uint32_t aad_len = read_u32_be(p); p += 4;

    size_t header_size = HEADER_MIN_SIZE + aad_len;
    if (packet.size() < header_size + sizeof(uint64_t) + TAG_SIZE) {
        throw CryptoException("Authentication failed: corrupted packet structure.");
    }

    const uint8_t* packet_aad = p;
    if (aad_len != aad.size()) {
        throw CryptoException("Authentication failed: AAD length mismatch.");
    }
    if (aad_len > 0) {
        if (CRYPTO_memcmp(packet_aad, aad.data(), aad_len) != 0) {
            throw CryptoException("Authentication failed: AAD mismatch.");
        }
        p += aad_len;
    }

    uint64_t ct_len = read_u64_be(p); p += 8;

    if (packet.size() != header_size + sizeof(uint64_t) + ct_len + TAG_SIZE) {
        throw CryptoException("Authentication failed: packet length payload mismatch.");
    }

    const uint8_t* ciphertext_ptr = p;
    const uint8_t* tag_ptr = ciphertext_ptr + ct_len;

    SecureBuffer master_key;
    if (is_password) {
        if (!(flags & FLAG_PASSWORD)) {
            throw CryptoException("Authentication failed: Key/Password configuration mismatch.");
        }
        master_key = derive_key_from_password(key_or_password,
            std::span<const uint8_t>(salt, SALT_SIZE), kdf_type, {});
    } else {
        if (key_or_password.size() != KEY_SIZE) {
            throw CryptoException("Raw encryption key must be exactly 32 bytes.");
        }
        master_key = SecureBuffer(key_or_password);
    }

    const char* hkdf_info = "DEFX-V1-MESSAGE-KEY";
    SecureBuffer enc_key = hkdf_expand(master_key.span(),
        std::span<const uint8_t>(salt, SALT_SIZE),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hkdf_info), std::strlen(hkdf_info)),
        KEY_SIZE);

    ScopedCipher cipher = get_cipher_obj(alg);
    ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw CryptoException("Failed to create cipher context.");

    OSSL_PARAM cipher_params[2];
    size_t iv_len = IV_SIZE;
    cipher_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len);
    cipher_params[1] = OSSL_PARAM_construct_end();

    if (EVP_DecryptInit_ex2(ctx.get(), cipher.get(), enc_key.data(), nonce, cipher_params) != 1) {
        throw CryptoException("Failed to initialize decryption context.");
    }

    std::span<const uint8_t> header_aad(packet.data(), header_size);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, header_aad.data(),
                          static_cast<int>(header_aad.size())) != 1) {
        throw CryptoException("Failed to verify header AAD.");
    }

    SecureBuffer plaintext(ct_len);

    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &out_len, ciphertext_ptr,
                              static_cast<int>(ct_len)) != 1) {
            throw CryptoException("Failed during decryption update.");
        }
    }

    OSSL_PARAM tag_params[2];
    tag_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                     const_cast<uint8_t*>(tag_ptr), TAG_SIZE);
    tag_params[1] = OSSL_PARAM_construct_end();

    if (EVP_CIPHER_CTX_set_params(ctx.get(), tag_params) != 1) {
        throw CryptoException("Failed to set AEAD tag parameter.");
    }

    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + out_len, &out_len);
    if (ret <= 0) {
        plaintext.wipe();
        throw CryptoException("Authentication failed: invalid ciphertext, tag, or metadata.");
    }

    return plaintext;
}

// ============================================================================
// --- تنفيذ التشفير التدفيقي للملفات والبث (Streaming API) ---
// ============================================================================

void CryptoBox::encrypt_stream(
    std::istream& input,
    std::ostream& output,
    std::span<const uint8_t> key_or_password,
    bool is_password,
    std::span<const uint8_t> aad,
    CryptoOptions options) 
{
    if (key_or_password.empty()) throw CryptoException("Key or password cannot be empty.");

    Algorithm selected_alg = (options.algorithm == Algorithm::Auto)
                             ? Algorithm::AES_256_GCM : options.algorithm;
    uint8_t flags = FLAG_STREAMING;
    KdfType selected_kdf = KdfType::None;
    uint8_t salt[SALT_SIZE] = {0};

    SecureBuffer master_key;
    if (is_password) {
        flags |= FLAG_PASSWORD;
        generate_random(salt);
        selected_kdf = options.kdf_type;
        master_key = derive_key_from_password(key_or_password, salt, selected_kdf, options);
    } else {
        if (key_or_password.size() != KEY_SIZE) throw CryptoException("Raw key must be 32 bytes.");
        master_key = SecureBuffer(key_or_password);
    }

    const char* hkdf_info = "DEFX-V1-STREAM-KEY";
    SecureBuffer enc_key = hkdf_expand(master_key.span(), salt,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hkdf_info), std::strlen(hkdf_info)),
        KEY_SIZE);

    uint8_t master_iv[IV_SIZE];
    generate_random(master_iv);

    size_t aad_len = aad.size();
    size_t header_size = HEADER_MIN_SIZE + aad_len;
    SecureBuffer header(header_size);
    uint8_t* p = header.data();

    std::memcpy(p, MAGIC, 4); p += 4;
    write_u16_be(p, PROTOCOL_VERSION); p += 2;
    *p++ = static_cast<uint8_t>(selected_alg);
    *p++ = flags;
    *p++ = static_cast<uint8_t>(selected_kdf);
    std::memset(p, 0, 3); p += 3;
    std::memcpy(p, salt, SALT_SIZE); p += SALT_SIZE;
    std::memcpy(p, master_iv, IV_SIZE); p += IV_SIZE;
    write_u32_be(p, static_cast<uint32_t>(aad_len)); p += 4;
    if (aad_len > 0) std::memcpy(p, aad.data(), aad_len);

    output.write(reinterpret_cast<const char*>(header.data()), header_size);

    ScopedCipher cipher = get_cipher_obj(selected_alg);
    SecureBuffer read_buf(options.chunk_size);
    SecureBuffer cipher_buf(options.chunk_size + TAG_SIZE);

    uint64_t seq_num = 0;
    bool is_final = false;

    while (!is_final) {
        input.read(reinterpret_cast<char*>(read_buf.data()), options.chunk_size);
        size_t bytes_read = static_cast<size_t>(input.gcount());

        if (input.eof() || bytes_read < options.chunk_size) {
            is_final = true;
        }

        uint8_t chunk_iv[IV_SIZE];
        std::memcpy(chunk_iv, master_iv, IV_SIZE);
        uint64_t current_seq_be = 0;
        write_u64_be(reinterpret_cast<uint8_t*>(&current_seq_be), seq_num);
        for (size_t i = 0; i < 8; ++i) {
            chunk_iv[IV_SIZE - 8 + i] ^= reinterpret_cast<uint8_t*>(&current_seq_be)[i];
        }

        uint8_t chunk_aad[9];
        write_u64_be(chunk_aad, seq_num);
        chunk_aad[8] = is_final ? 0x01 : 0x00;

        ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
        OSSL_PARAM cipher_params[2];
        size_t iv_len = IV_SIZE;
        cipher_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len);
        cipher_params[1] = OSSL_PARAM_construct_end();

        EVP_EncryptInit_ex2(ctx.get(), cipher.get(), enc_key.data(), chunk_iv, cipher_params);

        int out_len = 0;
        EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, chunk_aad, 9);

        if (bytes_read > 0) {
            EVP_EncryptUpdate(ctx.get(), cipher_buf.data(), &out_len, read_buf.data(),
                              static_cast<int>(bytes_read));
        }

        int final_len = 0;
        EVP_EncryptFinal_ex(ctx.get(), cipher_buf.data() + out_len, &final_len);
        size_t chunk_ct_len = out_len + final_len;

        uint8_t tag[TAG_SIZE];
        OSSL_PARAM tag_params[2];
        tag_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAG_SIZE);
        tag_params[1] = OSSL_PARAM_construct_end();
        EVP_CIPHER_CTX_get_params(ctx.get(), tag_params);

        uint8_t chunk_header[5];
        write_u32_be(chunk_header, static_cast<uint32_t>(chunk_ct_len));
        chunk_header[4] = is_final ? 0x01 : 0x00;

        output.write(reinterpret_cast<const char*>(chunk_header), 5);
        if (chunk_ct_len > 0) {
            output.write(reinterpret_cast<const char*>(cipher_buf.data()), chunk_ct_len);
        }
        output.write(reinterpret_cast<const char*>(tag), TAG_SIZE);

        seq_num++;
    }
}

void CryptoBox::decrypt_stream(
    std::istream& input,
    std::ostream& output,
    std::span<const uint8_t> key_or_password,
    bool is_password,
    std::span<const uint8_t> aad) 
{
    SecureBuffer fixed_header(HEADER_MIN_SIZE);
    input.read(reinterpret_cast<char*>(fixed_header.data()), HEADER_MIN_SIZE);
    if (input.gcount() < static_cast<std::streamsize>(HEADER_MIN_SIZE)) {
        throw CryptoException("Authentication failed: invalid or truncated stream header.");
    }

    const uint8_t* p = fixed_header.data();
    if (std::memcmp(p, MAGIC, 4) != 0) throw CryptoException("Authentication failed: bad magic.");
    p += 4;

    uint16_t version = read_u16_be(p); p += 2;
    if (version != PROTOCOL_VERSION) throw CryptoException("Authentication failed: version mismatch.");

    Algorithm alg = static_cast<Algorithm>(*p++);
    uint8_t flags = *p++;
    KdfType kdf_type = static_cast<KdfType>(*p++);
    p += 3;

    const uint8_t* salt = p; p += SALT_SIZE;
    const uint8_t* master_iv = p; p += IV_SIZE;
    uint32_t aad_len = read_u32_be(p);

    if (aad_len != aad.size()) throw CryptoException("Authentication failed: AAD length mismatch.");

    SecureBuffer full_header(HEADER_MIN_SIZE + aad_len);
    std::memcpy(full_header.data(), fixed_header.data(), HEADER_MIN_SIZE);

    if (aad_len > 0) {
        input.read(reinterpret_cast<char*>(full_header.data() + HEADER_MIN_SIZE), aad_len);
        if (input.gcount() < static_cast<std::streamsize>(aad_len)) {
            throw CryptoException("Authentication failed: truncated stream AAD.");
        }
        if (CRYPTO_memcmp(full_header.data() + HEADER_MIN_SIZE, aad.data(), aad_len) != 0) {
            throw CryptoException("Authentication failed: AAD content mismatch.");
        }
    }

    SecureBuffer master_key;
    if (is_password) {
        master_key = derive_key_from_password(key_or_password,
            std::span<const uint8_t>(salt, SALT_SIZE), kdf_type, {});
    } else {
        if (key_or_password.size() != KEY_SIZE) throw CryptoException("Raw key must be 32 bytes.");
        master_key = SecureBuffer(key_or_password);
    }

    const char* hkdf_info = "DEFX-V1-STREAM-KEY";
    SecureBuffer enc_key = hkdf_expand(master_key.span(),
        std::span<const uint8_t>(salt, SALT_SIZE),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(hkdf_info), std::strlen(hkdf_info)),
        KEY_SIZE);

    ScopedCipher cipher = get_cipher_obj(alg);
    uint64_t seq_num = 0;
    bool is_final_reached = false;

    while (!is_final_reached) {
        uint8_t chunk_header[5];
        input.read(reinterpret_cast<char*>(chunk_header), 5);
        if (input.gcount() == 0 && is_final_reached) break;
        if (input.gcount() < 5) throw CryptoException("Authentication failed: truncated stream chunk.");

        uint32_t chunk_ct_len = read_u32_be(chunk_header);
        bool chunk_is_final = (chunk_header[4] == 0x01);

        SecureBuffer ct_buf(chunk_ct_len);
        if (chunk_ct_len > 0) {
            input.read(reinterpret_cast<char*>(ct_buf.data()), chunk_ct_len);
            if (input.gcount() < static_cast<std::streamsize>(chunk_ct_len)) {
                throw CryptoException("Authentication failed: truncated chunk payload.");
            }
        }

        uint8_t tag[TAG_SIZE];
        input.read(reinterpret_cast<char*>(tag), TAG_SIZE);
        if (input.gcount() < static_cast<std::streamsize>(TAG_SIZE)) {
            throw CryptoException("Authentication failed: truncated chunk tag.");
        }

        uint8_t chunk_iv[IV_SIZE];
        std::memcpy(chunk_iv, master_iv, IV_SIZE);
        uint64_t current_seq_be = 0;
        write_u64_be(reinterpret_cast<uint8_t*>(&current_seq_be), seq_num);
        for (size_t i = 0; i < 8; ++i) {
            chunk_iv[IV_SIZE - 8 + i] ^= reinterpret_cast<uint8_t*>(&current_seq_be)[i];
        }

        uint8_t chunk_aad[9];
        write_u64_be(chunk_aad, seq_num);
        chunk_aad[8] = chunk_is_final ? 0x01 : 0x00;

        ScopedCipherCtx ctx(EVP_CIPHER_CTX_new());
        OSSL_PARAM cipher_params[2];
        size_t iv_len = IV_SIZE;
        cipher_params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &iv_len);
        cipher_params[1] = OSSL_PARAM_construct_end();

        EVP_DecryptInit_ex2(ctx.get(), cipher.get(), enc_key.data(), chunk_iv, cipher_params);

        int out_len = 0;
        EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, chunk_aad, 9);

        SecureBuffer pt_buf(chunk_ct_len);
        if (chunk_ct_len > 0) {
            EVP_DecryptUpdate(ctx.get(), pt_buf.data(), &out_len, ct_buf.data(),
                              static_cast<int>(chunk_ct_len));
        }

        OSSL_PARAM tag_params[2];
        tag_params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, TAG_SIZE);
        tag_params[1] = OSSL_PARAM_construct_end();
        EVP_CIPHER_CTX_set_params(ctx.get(), tag_params);

        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx.get(), pt_buf.data() + out_len, &final_len) <= 0) {
            throw CryptoException("Authentication failed: corrupted chunk ciphertext or tampered stream.");
        }

        size_t total_pt = out_len + final_len;
        if (total_pt > 0) {
            output.write(reinterpret_cast<const char*>(pt_buf.data()), total_pt);
        }

        if (chunk_is_final) {
            is_final_reached = true;
        }
        seq_num++;
    }

    char extra_byte;
    if (input.read(&extra_byte, 1)) {
        throw CryptoException("Authentication failed: trailing data injected after stream end.");
    }
}

// ============================================================================
// wrapper عام للدالة المشتقة من كلمة المرور (يستخدم من الجسر)
// ============================================================================

SecureBuffer CryptoBox::derive_from_password_direct(
    std::span<const uint8_t> password,
    std::span<const uint8_t> salt,
    KdfType& selected_kdf,
    const CryptoOptions& options)
{
    return derive_key_from_password(password, salt, selected_kdf, options);
}

} // namespace defcrypto
