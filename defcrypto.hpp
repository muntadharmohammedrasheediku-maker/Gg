#ifndef DEFCRYPTO_HPP
#define DEFCRYPTO_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <span>
#include <memory>
#include <stdexcept>
#include <iostream>

namespace defcrypto {

// استثناء أمني موحد يمنع تسريب تفاصيل التشفير الداخلية
class CryptoException : public std::runtime_error {
public:
    explicit CryptoException(const std::string& msg) 
        : std::runtime_error("Cryptographic Error: " + msg) {}
};

// خوارزميات التشفير المعتمدة
enum class Algorithm : uint8_t {
    Auto = 0,               // اختيار تلقائي بناءً على دعم المعالج لـ AES-NI
    AES_256_GCM = 1,
    ChaCha20_Poly1305 = 2
};

// خوارزميات اشتقاق المفاتيح
enum class KdfType : uint8_t {
    Auto = 0,               // تفضيل Argon2id -> Scrypt -> PBKDF2
    Argon2id = 1,
    Scrypt = 2,
    PBKDF2_SHA256 = 3,
    None = 0xFF
};

// إعدادات التشفير القابلة للضبط
struct CryptoOptions {
    Algorithm algorithm = Algorithm::Auto;
    KdfType kdf_type = KdfType::Auto;
    size_t memory_cost_mb = 64; // لـ Argon2id و Scrypt
    size_t iterations = 3;      // لـ Argon2id و PBKDF2
    size_t chunk_size = 1024 * 1024; // 1 MB للبث التدفيقي (Streaming)
};

// وعاء ذاكرة آمن RAII يمنع النسخ ويضمن المسح والإغلاق بالذاكرة
class SecureBuffer {
private:
    uint8_t* ptr_ = nullptr;
    size_t size_ = 0;
    size_t capacity_ = 0;

    void lock_memory() noexcept;
    void unlock_memory() noexcept;

public:
    SecureBuffer() noexcept = default;
    explicit SecureBuffer(size_t size);
    explicit SecureBuffer(std::span<const uint8_t> init_data);
    ~SecureBuffer();

    // منع النسخ
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // دعم النقل فقط (Move Semantics)
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    void resize(size_t new_size);
    void wipe() noexcept;

    [[nodiscard]] uint8_t* data() noexcept { return ptr_; }
    [[nodiscard]] const uint8_t* data() const noexcept { return ptr_; }
    [[nodiscard]] size_t size() const noexcept { return size_; }
    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::span<const uint8_t> span() const noexcept { return {ptr_, size_}; }
    [[nodiscard]] std::span<uint8_t> writable_span() noexcept { return {ptr_, size_}; }
};

// الواجهة الرئيسة للمكتبة (CryptoBox)
class CryptoBox {
public:
    // 1. تشفير وفك تشفير الرسائل القليلة/المتوسطة في الذاكرة
    static SecureBuffer encrypt_message(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> key_or_password,
        bool is_password,
        std::span<const uint8_t> aad = {},
        CryptoOptions options = {}
    );

    static SecureBuffer decrypt_message(
        std::span<const uint8_t> packet,
        std::span<const uint8_t> key_or_password,
        bool is_password,
        std::span<const uint8_t> aad = {}
    );

    // 2. تشفير وفك تشفير البث/الملفات الكبيرة (Streaming) بأثر ذاكرة ثابت O(1)
    static void encrypt_stream(
        std::istream& input,
        std::ostream& output,
        std::span<const uint8_t> key_or_password,
        bool is_password,
        std::span<const uint8_t> aad = {},
        CryptoOptions options = {}
    );

    static void decrypt_stream(
        std::istream& input,
        std::ostream& output,
        std::span<const uint8_t> key_or_password,
        bool is_password,
        std::span<const uint8_t> aad = {}
    );

    // فحص دعم العتاد لـ AES-NI
    static bool has_hardware_aes() noexcept;

    // ★ جديد: اشتقاق مفتاح مباشر من كلمة مرور (public wrapper للجسر)
    static SecureBuffer derive_from_password_direct(
        std::span<const uint8_t> password,
        std::span<const uint8_t> salt,
        KdfType& selected_kdf,
        const CryptoOptions& options);
};

} // namespace defcrypto

#endif // DEFCRYPTO_HPP
