// ==========================================================================
// aegis.cpp — Anti-Cheat SDK (Single File Edition)
// C++20 / OpenSSL 3.0+ / POSIX sockets
//
// Build:
//   Linux:  g++ -std=c++20 -O2 -Wall -Wextra -pthread -lssl -lcrypto aegis.cpp -o aegis
//   macOS:  clang++ -std=c++20 -O2 -Wall -Wextra -pthread \
//                   -I$(brew --prefix openssl)/include \
//                   -L$(brew --prefix openssl)/lib \
//                   -lssl -lcrypto aegis.cpp -o aegis
//
// Run:
//   ./aegis --selftest
//   ./aegis --serve --port 8443 [--model weights.bin]
// ==========================================================================

#define _GNU_SOURCE
#include <algorithm>
#include <atomic>
#include <array>
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// POSIX
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/rand.h>

// ==========================================================================
// SECTION 1 — TYPES
// ==========================================================================
namespace aegis {

inline constexpr std::size_t kSeqLen  = 30;
inline constexpr std::size_t kFeature = 10;

struct PlayerFrame {
    double t{0};
    float  aim_x{0};
    float  aim_y{0};
    float  aim_speed{0};
    float  aim_jerk{0};
    float  fire_interval{0};
    float  move_speed{0};
    float  reaction_time{0};
    float  fov_visible{0};
    float  kill_distance{0};
};

struct RiskVerdict {
    float human_score{0.5f};
    float anomaly_score{0.0f};
    float iso_score{0.0f};
    bool  integrity_ok{true};
    std::size_t frames{0};
    std::size_t total{0};
    std::vector<std::string> reasons;

    bool suspicious() const noexcept {
        return human_score < 0.30f || anomaly_score < -0.5f
            || iso_score < -0.4f || !integrity_ok;
    }
};

} // namespace aegis

// ==========================================================================
// SECTION 2 — RING BUFFER (SPSC lock-free)
// ==========================================================================
namespace aegis {

template <typename T, std::size_t N>
class RingBuffer {
    static_assert((N & (N - 1)) == 0, "N must be power of two");
public:
    RingBuffer() : buf_(N) {}

    bool push(const T& v) noexcept {
        const auto w = write_.load(std::memory_order_relaxed);
        const auto r = read_.load(std::memory_order_acquire);
        if ((w - r) >= N) return false;
        buf_[w & (N - 1)] = v;
        write_.store(w + 1, std::memory_order_release);
        return true;
    }

    std::optional<T> pop() noexcept {
        const auto r = read_.load(std::memory_order_relaxed);
        const auto w = write_.load(std::memory_order_acquire);
        if (r == w) return std::nullopt;
        T v = buf_[r & (N - 1)];
        read_.store(r + 1, std::memory_order_release);
        return v;
    }

    std::size_t size() const noexcept {
        return write_.load(std::memory_order_acquire)
             - read_.load(std::memory_order_acquire);
    }
    static constexpr std::size_t capacity() noexcept { return N; }

private:
    std::vector<T> buf_;
    alignas(64) std::atomic<std::size_t> write_{0};
    alignas(64) std::atomic<std::size_t> read_{0};
};

} // namespace aegis

// ==========================================================================
// SECTION 3 — STATISTICS
// ==========================================================================
namespace aegis::stats {

inline double median(std::span<const double> xs) {
    if (xs.empty()) return 0.0;
    std::vector<double> s(xs.begin(), xs.end());
    const auto mid = s.size() / 2;
    std::nth_element(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(mid), s.end());
    double hi = s[mid];
    if (s.size() % 2) return hi;
    std::nth_element(s.begin(), s.begin() + static_cast<std::ptrdiff_t>(mid - 1),
                     s.begin() + static_cast<std::ptrdiff_t>(mid));
    double lo = s[mid - 1];
    return (lo + hi) * 0.5;
}

inline double robust_sigma(std::span<const double> xs) {
    if (xs.size() < 3) return 0.0;
    const double med = median(xs);
    std::vector<double> dev(xs.size());
    std::transform(xs.begin(), xs.end(), dev.begin(),
                   [med](double v) { return std::abs(v - med); });
    const double mad = median(std::span<const double>(dev));
    return 1.4826 * mad;
}

inline double mad_zscore(std::span<const double> xs) {
    if (xs.size() < 3) return 0.0;
    const double med = median(xs);
    const double sig = robust_sigma(xs);
    if (sig < 1e-9) return 0.0;
    return (xs.back() - med) / sig;
}

inline double isolation_score(std::span<const double> xs, unsigned seed = 42) {
    if (xs.size() < 4) return 0.0;
    const std::size_t subsample = std::min<std::size_t>(xs.size(), 32);
    const std::size_t trees     = 50;
    const double      max_depth = std::log2(static_cast<double>(subsample));

    std::mt19937 rng(seed);
    double total_depth = 0.0;

    for (std::size_t t = 0; t < trees; ++t) {
        std::vector<double> s(subsample);
        std::uniform_int_distribution<std::size_t> idx(0, xs.size() - 1);
        for (auto& v : s) v = xs[idx(rng)];

        double lo = *std::min_element(s.begin(), s.end());
        double hi = *std::max_element(s.begin(), s.end());
        if (hi - lo < 1e-12) { total_depth += 1.0; continue; }

        const double pivot  = lo + (hi - lo) *
                              std::uniform_real_distribution<double>(0, 1)(rng);
        const double target = xs.back();
        double depth = 0.0;
        while (depth < max_depth) {
            if (target < pivot) hi = pivot;
            else                lo = pivot;
            if (hi - lo < 1e-12) break;
            depth += 1.0;
        }
        total_depth += depth;
    }
    const double avg_depth = total_depth / static_cast<double>(trees);
    const double c = 2.0 * (std::log(subsample - 1.0) + 0.5772156649)
                   - (2.0 * (subsample - 1.0) / subsample);
    double score = std::pow(2.0, -avg_depth / std::max(1e-9, c));
    return 2.0 * score - 1.0;
}

class EWMA {
public:
    explicit EWMA(double alpha) : alpha_(alpha) {}
    double update(double x) noexcept {
        s_ = (s_ == 0.0) ? x : alpha_ * x + (1.0 - alpha_) * s_;
        return s_;
    }
    double value() const noexcept { return s_; }
private:
    double alpha_;
    double s_{0.0};
};

} // namespace aegis::stats

// ==========================================================================
// SECTION 4 — FEATURES
// ==========================================================================
namespace aegis {

inline std::vector<float> frame_matrix(const std::vector<PlayerFrame>& frames) {
    std::vector<float> out(kSeqLen * kFeature, 0.f);
    const std::size_t n = std::min(frames.size(), kSeqLen);
    const std::size_t start = frames.size() - n;
    for (std::size_t i = 0; i < n; ++i) {
        const auto& f = frames[start + i];
        const std::size_t base = i * kFeature;
        out[base + 0] = f.aim_x;
        out[base + 1] = f.aim_y;
        out[base + 2] = f.aim_speed;
        out[base + 3] = f.aim_jerk;
        out[base + 4] = f.fire_interval;
        out[base + 5] = f.move_speed;
        out[base + 6] = f.reaction_time;
        out[base + 7] = f.fov_visible;
        out[base + 8] = f.kill_distance;
        out[base + 9] = static_cast<float>(i)
                      / static_cast<float>(std::max<std::size_t>(1, n - 1));
    }
    return out;
}

struct FeatureSummary {
    double mean_react{0}, min_react{0}, std_dev_react{0};
    double mean_fire{0},  min_fire{0};
    double mean_jerk{0};
    double mean_speed{0};
};

inline FeatureSummary summarize(const std::vector<PlayerFrame>& frames) {
    FeatureSummary s;
    if (frames.empty()) return s;
    std::vector<double> react, fire, jerk, speed;
    react.reserve(frames.size());
    fire.reserve(frames.size());
    jerk.reserve(frames.size());
    speed.reserve(frames.size());
    for (const auto& f : frames) {
        react.push_back(f.reaction_time);
        fire.push_back(f.fire_interval);
        jerk.push_back(f.aim_jerk);
        speed.push_back(f.aim_speed);
    }
    auto mean = [](const std::vector<double>& v) {
        double s2 = 0; for (double x : v) s2 += x; return s2 / v.size();
    };
    s.mean_react = mean(react);
    s.min_react  = *std::min_element(react.begin(), react.end());
    s.mean_fire  = mean(fire);
    s.min_fire   = *std::min_element(fire.begin(), fire.end());
    s.mean_jerk  = mean(jerk);
    s.mean_speed = mean(speed);

    double var = 0.0;
    for (double r : react) var += (r - s.mean_react) * (r - s.mean_react);
    s.std_dev_react = std::sqrt(var / static_cast<double>(react.size()));
    return s;
}

} // namespace aegis

// ==========================================================================
// SECTION 5 — LSTM INFERENCE
// ==========================================================================
namespace aegis {

class LSTM {
public:
    LSTM() = default;

    void load(const std::string& path, std::size_t input_dim,
              std::size_t hidden, std::size_t layers) {
        std::ifstream f(path, std::ios::binary);
        if (!f) throw std::runtime_error("lstm: cannot open " + path);

        input_dim_ = input_dim;
        hidden_    = hidden;
        layers_    = layers;
        layers_.clear();

        std::size_t in = input_dim;
        for (std::size_t L = 0; L < layers; ++L) {
            Layer layer;
            const std::size_t gate_rows = 4 * hidden;
            read_vec<float>(f, layer.W, gate_rows * (in + hidden));
            read_vec<float>(f, layer.b, gate_rows);
            layers_.push_back(std::move(layer));
            in = hidden;
        }
        read_vec<float>(f, head_W_, hidden);
        f.read(reinterpret_cast<char*>(&head_b_), sizeof(float));
        if (!f) throw std::runtime_error("lstm: short read head");
        loaded_ = true;
    }

    float forward(const std::vector<float>& seq, std::size_t T) const {
        if (!loaded_) throw std::runtime_error("lstm: not loaded");
        if (seq.size() < T * input_dim_) throw std::runtime_error("lstm: seq too small");

        std::vector<float> h(hidden_, 0.f), c(hidden_, 0.f);
        std::vector<float> input, gates(4 * hidden_), concat;

        for (std::size_t t = 0; t < T; ++t) {
            input.assign(seq.begin() + static_cast<std::ptrdiff_t>(t * input_dim_),
                         seq.begin() + static_cast<std::ptrdiff_t>((t + 1) * input_dim_));
            for (std::size_t L = 0; L < layers_; ++L) {
                concat.clear();
                concat.insert(concat.end(), input.begin(), input.end());
                concat.insert(concat.end(), h.begin(), h.end());

                const auto& layer = layers_[L];
                const std::size_t in_dim = (L == 0) ? input_dim_ : hidden_;
                const std::size_t cols   = in_dim + hidden_;
                std::fill(gates.begin(), gates.end(), 0.f);

                for (std::size_t r = 0; r < 4 * hidden_; ++r) {
                    float acc = layer.b[r];
                    const float* Wrow = layer.W.data() + r * cols;
                    for (std::size_t k = 0; k < cols; ++k) acc += Wrow[k] * concat[k];
                    gates[r] = acc;
                }

                std::vector<float> h_new(hidden_), c_new(hidden_);
                for (std::size_t j = 0; j < hidden_; ++j) {
                    const float i_g = sigmoid(gates[j]);
                    const float f_g = sigmoid(gates[hidden_ + j]);
                    const float g_g = std::tanh(gates[2 * hidden_ + j]);
                    const float o_g = sigmoid(gates[3 * hidden_ + j]);
                    const float cj  = f_g * c[j] + i_g * g_g;
                    c_new[j] = cj;
                    h_new[j] = o_g * std::tanh(cj);
                }
                h.swap(h_new);
                c.swap(c_new);
                input = h;
            }
        }

        float acc = head_b_;
        for (std::size_t j = 0; j < hidden_; ++j) acc += head_W_[j] * h[j];
        return sigmoid(acc);
    }

    bool loaded() const noexcept { return loaded_; }
    std::size_t input_dim() const noexcept { return input_dim_; }
    std::size_t hidden() const noexcept { return hidden_; }
    std::size_t layers() const noexcept { return layers_; }

private:
    struct Layer {
        std::vector<float> W;
        std::vector<float> b;
    };
    static inline float sigmoid(float x) { return 1.f / (1.f + std::exp(-x)); }

    template <typename T>
    static void read_vec(std::ifstream& f, std::vector<T>& v, std::size_t n) {
        v.resize(n);
        f.read(reinterpret_cast<char*>(v.data()),
               static_cast<std::streamsize>(n * sizeof(T)));
        if (!f) throw std::runtime_error("lstm: short read");
    }

    std::vector<Layer> layers_;
    std::vector<float> head_W_;
    float head_b_{0.f};
    std::size_t input_dim_{0}, hidden_{0}, layers_{0};
    bool loaded_{false};
};

} // namespace aegis

// ==========================================================================
// SECTION 6 — AES-256-GCM
// ==========================================================================
namespace aegis {

class AESGCM {
public:
    static constexpr std::size_t kKeyLen   = 32;
    static constexpr std::size_t kNonceLen = 12;
    static constexpr std::size_t kTagLen   = 16;

    static std::vector<uint8_t> random_key() {
        std::vector<uint8_t> k(kKeyLen);
        if (RAND_bytes(k.data(), static_cast<int>(k.size())) != 1)
            throw std::runtime_error("AESGCM: RAND_bytes failed");
        return k;
    }

    AESGCM() = default;
    explicit AESGCM(const std::vector<uint8_t>& key) : key_(key) {
        if (key_.size() != kKeyLen) throw std::runtime_error("AESGCM: bad key length");
    }

    // Layout: nonce(12) || ciphertext || tag(16)
    std::vector<uint8_t> seal(const uint8_t* data, std::size_t len) const {
        if (key_.size() != kKeyLen) throw std::runtime_error("AESGCM: no key");
        std::vector<uint8_t> out(kNonceLen + len + kTagLen);
        if (RAND_bytes(out.data(), static_cast<int>(kNonceLen)) != 1)
            throw std::runtime_error("AESGCM: nonce rand failed");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("AESGCM: ctx");
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key_.data(), out.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: init");
        }
        int outlen = 0;
        uint8_t* ct = out.data() + kNonceLen;
        if (EVP_EncryptUpdate(ctx, ct, &outlen, data,
                              static_cast<int>(len)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: update");
        }
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, ct + outlen, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: final");
        }
        uint8_t* tag = out.data() + kNonceLen + len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, kTagLen, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: get_tag");
        }
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::vector<uint8_t> seal(const std::vector<uint8_t>& data) const {
        return seal(data.data(), data.size());
    }

    std::vector<uint8_t> open(const uint8_t* data, std::size_t len) const {
        if (key_.size() != kKeyLen) throw std::runtime_error("AESGCM: no key");
        if (len < kNonceLen + kTagLen) throw std::runtime_error("AESGCM: short input");
        const std::size_t ct_len = len - kNonceLen - kTagLen;
        std::vector<uint8_t> out(ct_len);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("AESGCM: ctx");
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                               key_.data(), data) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: init");
        }
        int outlen = 0;
        if (EVP_DecryptUpdate(ctx, out.data(), &outlen,
                              data + kNonceLen,
                              static_cast<int>(ct_len)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: update");
        }
        uint8_t tag[kTagLen];
        std::memcpy(tag, data + kNonceLen + ct_len, kTagLen);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, kTagLen, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: set_tag");
        }
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, out.data() + outlen, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("AESGCM: auth failed");
        }
        EVP_CIPHER_CTX_free(ctx);
        return out;
    }

    std::vector<uint8_t> open(const std::vector<uint8_t>& data) const {
        return open(data.data(), data.size());
    }

private:
    std::vector<uint8_t> key_;
};

} // namespace aegis

// ==========================================================================
// SECTION 7 — SESSIONS
// ==========================================================================
namespace aegis {

class Session {
public:
    using Clock = std::chrono::steady_clock;
    static constexpr std::size_t kCap = 512;

    explicit Session(std::string id)
        : id_(std::move(id)), last_seen_(Clock::now()) {}

    void ingest(const PlayerFrame& f) {
        std::lock_guard lk(m_);
        if (frames_.size() >= kCap) frames_.erase(frames_.begin());
        frames_.push_back(f);
        ++total_;
        last_seen_ = Clock::now();
    }

    std::vector<PlayerFrame> snapshot(std::size_t n) const {
        std::lock_guard lk(m_);
        const std::size_t take = std::min(n, frames_.size());
        return std::vector<PlayerFrame>(
            frames_.end() - static_cast<std::ptrdiff_t>(take),
            frames_.end());
    }

    const std::string& id() const noexcept { return id_; }
    std::size_t count() const noexcept { return total_; }
    Clock::time_point last_seen() const noexcept { return last_seen_; }

private:
    std::string id_;
    mutable std::mutex m_;
    std::vector<PlayerFrame> frames_;
    std::size_t total_{0};
    Clock::time_point last_seen_{};
};

class SessionRegistry {
public:
    std::shared_ptr<Session> get_or_create(const std::string& id) {
        std::lock_guard lk(m_);
        auto it = sessions_.find(id);
        if (it != sessions_.end()) return it->second;
        auto s = std::make_shared<Session>(id);
        sessions_.emplace(id, s);
        return s;
    }

    void gc(std::chrono::seconds ttl) {
        std::lock_guard lk(m_);
        const auto now = Session::Clock::now();
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (now - it->second->last_seen() > ttl) it = sessions_.erase(it);
            else ++it;
        }
    }

    std::size_t size() const {
        std::lock_guard lk(m_);
        return sessions_.size();
    }

private:
    mutable std::mutex m_;
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
};

} // namespace aegis

// ==========================================================================
// SECTION 8 — JSON HELPERS (minimal, no dep)
// ==========================================================================
namespace aegis::jsonlite {

inline std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;
        }
    }
    return out;
}

inline std::string jstr(const std::string& j, const std::string& k) {
    const auto key = "\"" + k + "\":\"";
    auto p = j.find(key);
    if (p == std::string::npos) return {};
    p += key.size();
    auto q = j.find('"', p);
    return q == std::string::npos ? std::string{} : j.substr(p, q - p);
}

inline float jnum(const std::string& j, const std::string& k, float def = 0.f) {
    const auto key = "\"" + k + "\":";
    auto p = j.find(key);
    if (p == std::string::npos) return def;
    p += key.size();
    try { return std::stof(j.substr(p)); } catch (...) { return def; }
}

inline bool jbool(const std::string& j, const std::string& k) {
    const auto key = "\"" + k + "\":";
    auto p = j.find(key);
    if (p == std::string::npos) return false;
    p += key.size();
    return j.compare(p, 4, "true") == 0;
}

} // namespace aegis::jsonlite

// ==========================================================================
// SECTION 9 — ANALYZER
// ==========================================================================
namespace aegis {

class Analyzer {
public:
    Analyzer() = default;
    void set_model(LSTM* m) { model_ = m; }

    RiskVerdict evaluate(const std::vector<PlayerFrame>& frames,
                         std::size_t total) const {
        RiskVerdict v;
        v.frames = frames.size();
        v.total  = total;

        if (frames.empty()) return v;

        // 1. ML
        if (model_ && model_->loaded() && frames.size() >= 5) {
            try {
                const auto seq = frame_matrix(frames);
                v.human_score = model_->forward(seq, kSeqLen);
            } catch (...) {
                v.human_score = 0.5f;
            }
        } else {
            // No model: neutral score
            v.human_score = 0.5f;
        }

        // 2. Statistical z-scores
        std::vector<double> speeds, jerks, reacts, fires;
        speeds.reserve(frames.size());
        jerks.reserve(frames.size());
        reacts.reserve(frames.size());
        fires.reserve(frames.size());
        for (const auto& f : frames) {
            speeds.push_back(f.aim_speed);
            jerks.push_back(f.aim_jerk);
            reacts.push_back(f.reaction_time);
            fires.push_back(f.fire_interval);
        }

        double combined = 0.0;
        combined += stats::mad_zscore(speeds);
        combined += stats::mad_zscore(jerks);
        combined += stats::mad_zscore(reacts);
        combined += stats::mad_zscore(fires);
        v.anomaly_score = static_cast<float>(
            std::clamp(-combined / 6.0, -1.0, 1.0));

        v.iso_score = static_cast<float>(stats::isolation_score(speeds));

        // 3. Reasons
        const auto summary = summarize(frames);
        if (v.human_score < 0.30f) {
            v.reasons.push_back("ml.human_prob=" + std::to_string(v.human_score));
        }
        if (v.anomaly_score < -0.5f) {
            v.reasons.push_back("stat.anomaly=" + std::to_string(v.anomaly_score));
        }
        if (v.iso_score < -0.4f) {
            v.reasons.push_back("iso.score=" + std::to_string(v.iso_score));
        }
        if (summary.min_react < 0.08) {
            v.reasons.push_back("reaction.min=" + std::to_string(summary.min_react));
        }
        if (summary.min_fire < 0.02) {
            v.reasons.push_back("fire.min=" + std::to_string(summary.min_fire));
        }
        return v;
    }

    std::string to_json(const RiskVerdict& v, const std::string& sid) const {
        std::ostringstream o;
        o << "{"
          << "\"status\":\"" << (v.suspicious() ? "flagged" : "clean") << "\","
          << "\"session\":\"" << jsonlite::escape(sid) << "\","
          << "\"human\":" << v.human_score << ","
          << "\"anomaly\":" << v.anomaly_score << ","
          << "\"iso\":" << v.iso_score << ","
          << "\"frames\":" << v.frames << ","
          << "\"total\":" << v.total << ","
          << "\"reasons\":[";
        for (std::size_t i = 0; i < v.reasons.size(); ++i) {
            if (i) o << ",";
            o << "\"" << jsonlite::escape(v.reasons[i]) << "\"";
        }
        o << "]}";
        return o.str();
    }

private:
    LSTM* model_{nullptr};
};

} // namespace aegis

// ==========================================================================
// SECTION 10 — HTTP SERVER
// ==========================================================================
namespace aegis {

class Server {
public:
    struct Config {
        std::string bind_addr{"0.0.0.0"};
        uint16_t    port{8443};
        std::size_t workers{4};
        std::chrono::seconds gc_interval{60};
        std::chrono::seconds session_ttl{600};
    };

    using Handler = std::function<std::string(const std::string& json_body,
                                              const std::string& session_id)>;

    Server(Config cfg, AESGCM cipher, Handler handler)
        : cfg_(std::move(cfg)),
          cipher_(std::move(cipher)),
          handler_(std::move(handler)) {}

    ~Server() { stop(); }

    void start() {
        listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd_ < 0) throw std::runtime_error("socket() failed");
        int one = 1;
        ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(cfg_.port);
        ::inet_pton(AF_INET, cfg_.bind_addr.c_str(), &addr.sin_addr);

        if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&addr),
                   sizeof(addr)) < 0)
            throw std::runtime_error("bind() failed");
        if (::listen(listen_fd_, 64) < 0)
            throw std::runtime_error("listen() failed");

        running_.store(true);
        for (std::size_t i = 0; i < cfg_.workers; ++i)
            workers_.emplace_back([this] { accept_loop(); });

        gc_thread_ = std::thread([this] {
            while (running_.load()) {
                std::this_thread::sleep_for(cfg_.gc_interval);
                registry_.gc(cfg_.session_ttl);
            }
        });

        std::cout << "[aegis] listening on " << cfg_.bind_addr
                  << ":" << cfg_.port
                  << " workers=" << cfg_.workers << "\n";
    }

    void stop() {
        if (!running_.exchange(false)) return;
        if (listen_fd_ >= 0) {
            ::shutdown(listen_fd_, SHUT_RDWR);
            ::close(listen_fd_);
        }
        for (auto& t : workers_)   if (t.joinable()) t.join();
        if (gc_thread_.joinable()) gc_thread_.join();
    }

    std::vector<uint8_t> key() const { return key_; }
    const AESGCM& cipher() const { return cipher_; }

private:
    static std::string http_body(const std::string& req) {
        const auto pos = req.find("\r\n\r\n");
        return pos == std::string::npos ? std::string{} : req.substr(pos + 4);
    }

    static std::string http_response(int code, const std::string& body) {
        const char* reason = (code == 200) ? "OK" : "Bad Request";
        std::string out = "HTTP/1.1 " + std::to_string(code) + " "
                        + reason + "\r\n";
        out += "Content-Type: application/json\r\n";
        out += "Content-Length: " + std::to_string(body.size()) + "\r\n";
        out += "Connection: close\r\n\r\n";
        out += body;
        return out;
    }

    void accept_loop() {
        for (;;) {
            sockaddr_in cli{};
            socklen_t len = sizeof(cli);
            int fd = ::accept(listen_fd_, reinterpret_cast<sockaddr*>(&cli),
                              &len);
            if (fd < 0) {
                if (!running_.load()) return;
                continue;
            }
            try { handle_client(fd); }
            catch (const std::exception& e) {
                std::cerr << "[aegis] client error: " << e.what() << "\n";
            }
            ::close(fd);
        }
    }

    void handle_client(int fd) {
        std::string req;
        req.reserve(4096);
        char buf[4096];
        for (;;) {
            ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            req.append(buf, static_cast<std::size_t>(n));
            if (req.size() > (1u << 20)) break;
            if (req.find("\r\n\r\n") != std::string::npos &&
                req.find("Content-Length:") != std::string::npos) {
                if (req.size() > req.find("\r\n\r\n") + 4 + 16) break;
            }
        }

        if (req.rfind("GET /key", 0) == 0) {
            const auto resp = http_response(200, "{\"status\":\"ok\"}");
            ::send(fd, resp.data(), resp.size(), 0);
            return;
        }

        if (req.rfind("POST /verdict", 0) != 0) {
            const auto resp = http_response(400, "{\"error\":\"bad_route\"}");
            ::send(fd, resp.data(), resp.size(), 0);
            return;
        }

        const std::string body = http_body(req);
        if (body.empty()) {
            const auto resp = http_response(400, "{\"error\":\"empty_body\"}");
            ::send(fd, resp.data(), resp.size(), 0);
            return;
        }

        std::string json;
        try {
            const auto plain = cipher_.open(
                reinterpret_cast<const uint8_t*>(body.data()), body.size());
            json.assign(plain.begin(), plain.end());
        } catch (const std::exception& e) {
            const auto resp = http_response(
                400, std::string("{\"error\":\"decrypt:") +
                     jsonlite::escape(e.what()) + "\"}");
            ::send(fd, resp.data(), resp.size(), 0);
            return;
        }

        const std::string sid = jsonlite::jstr(json, "session");
        std::string reply;
        try {
            reply = handler_ ? handler_(json, sid.empty() ? "unknown" : sid)
                             : "{\"status\":\"no_handler\"}";
        } catch (const std::exception& e) {
            reply = std::string("{\"error\":\"handler:") +
                    jsonlite::escape(e.what()) + "\"}";
        }
        const auto resp = http_response(200, reply);
        ::send(fd, resp.data(), resp.size(), 0);
    }

    Config cfg_;
    AESGCM cipher_;
    std::vector<uint8_t> key_;  // reserved for future use
    Handler handler_;
    int listen_fd_{-1};
    std::atomic<bool> running_{false};
    std::vector<std::thread> workers_;
    SessionRegistry registry_;
    std::thread gc_thread_;
};

} // namespace aegis

// ==========================================================================
// SECTION 11 — SELF-TEST
// ==========================================================================
namespace aegis::selftest {

inline int g_fail = 0;
#define CHECK(cond) do {                                              \
    if (!(cond)) {                                                    \
        std::cerr << "FAIL: " #cond " @ " << __LINE__ << "\n";        \
        ++g_fail;                                                     \
    }                                                                 \
} while (0)

inline void test_median() {
    std::vector<double> a{5, 1, 3, 2, 4};
    CHECK(std::abs(stats::median(a) - 3.0) < 1e-9);
    std::vector<double> b{4, 1, 3, 2};
    CHECK(std::abs(stats::median(b) - 2.5) < 1e-9);
    std::vector<double> empty;
    CHECK(stats::median(empty) == 0.0);
}

inline void test_mad() {
    std::vector<double> xs{10, 10, 10, 10, 100};
    CHECK(stats::mad_zscore(xs) > 2.0);
}

inline void test_isolation() {
    std::vector<double> xs{1, 2, 3, 4, 5, 6, 7, 8, 9, 50};
    CHECK(stats::isolation_score(xs) < 1.0);
}

inline void test_crypto_roundtrip() {
    auto key = AESGCM::random_key();
    AESGCM c(key);
    std::string msg = "hello aegis 12345";
    std::vector<uint8_t> data(msg.begin(), msg.end());
    auto sealed = c.seal(data);
    CHECK(sealed.size() >= AESGCM::kNonceLen + AESGCM::kTagLen);
    auto opened = c.open(sealed);
    CHECK(opened.size() == data.size());
    CHECK(std::memcmp(opened.data(), data.data(), data.size()) == 0);

    sealed[sealed.size() / 2] ^= 0x01;
    bool threw = false;
    try { (void)c.open(sealed); } catch (...) { threw = true; }
    CHECK(threw);
}

inline void test_features() {
    std::vector<PlayerFrame> frames;
    for (int i = 0; i < 40; ++i) {
        PlayerFrame f;
        f.t = i * 0.05;
        f.aim_speed = 100.f + static_cast<float>(i);
        f.reaction_time = 0.2f;
        f.fire_interval = 0.1f;
        frames.push_back(f);
    }
    const auto m = frame_matrix(frames);
    CHECK(m.size() == kSeqLen * kFeature);
    const auto s = summarize(frames);
    CHECK(s.mean_react > 0.19 && s.mean_react < 0.21);
    CHECK(std::abs(s.min_fire - 0.1) < 1e-6);
}

inline void test_session_registry() {
    SessionRegistry reg;
    auto s1 = reg.get_or_create("a");
    auto s2 = reg.get_or_create("a");
    auto s3 = reg.get_or_create("b");
    CHECK(s1 == s2);
    CHECK(s1 != s3);
    CHECK(reg.size() == 2);
}

inline void test_session_ingest() {
    Session s("x");
    for (int i = 0; i < 10; ++i) {
        PlayerFrame f; f.t = i;
        s.ingest(f);
    }
    CHECK(s.count() == 10);
    auto snap = s.snapshot(5);
    CHECK(snap.size() == 5);
    CHECK(snap.front().t == 5.0);
    CHECK(snap.back().t == 9.0);
}

inline void test_ring_buffer() {
    RingBuffer<int, 8> rb;
    for (int i = 0; i < 8; ++i) CHECK(rb.push(i));
    CHECK(!rb.push(99));           // full
    CHECK(rb.size() == 8);
    auto v = rb.pop();
    CHECK(v.has_value() && *v == 0);
    CHECK(rb.push(99));            // room now
    CHECK(rb.size() == 8);
}

inline void test_analyzer_statonly() {
    Analyzer a;
    std::vector<PlayerFrame> frames;
    for (int i = 0; i < 20; ++i) {
        PlayerFrame f;
        f.aim_speed     = 180.f + static_cast<float>(i % 5);
        f.aim_jerk      = 12.f;
        f.reaction_time = 0.24f;
        f.fire_interval = 0.12f;
        frames.push_back(f);
    }
    auto v = a.evaluate(frames, frames.size());
    CHECK(v.frames == 20);
    CHECK(v.human_score == 0.5f);  // no model => neutral
    // In a clean sample anomaly should not fire
    CHECK(v.anomaly_score > -0.9f);
}

inline int run_all() {
    std::cout << "== aegis selftest ==\n";
    test_median();
    test_mad();
    test_isolation();
    test_crypto_roundtrip();
    test_features();
    test_session_registry();
    test_session_ingest();
    test_ring_buffer();
    test_analyzer_statonly();

    if (g_fail) {
        std::cerr << g_fail << " test(s) FAILED\n";
        return 1;
    }
    std::cout << "ALL TESTS PASSED\n";
    return 0;
}

} // namespace aegis::selftest

// ==========================================================================
// SECTION 12 — MAIN
// ==========================================================================
namespace {

void print_usage(const char* argv0) {
    std::cout <<
        "Usage:\n"
        "  " << argv0 << " --selftest\n"
        "  " << argv0 << " --serve [--port N] [--bind ADDR] [--model path] [--workers N]\n"
        "\n"
        "Endpoints:\n"
        "  GET  /key      returns {\"status\":\"ok\"} (dev)\n"
        "  POST /verdict  AES-256-GCM sealed JSON body\n";
}

struct ServeOptions {
    uint16_t    port{8443};
    std::string bind{"0.0.0.0"};
    std::string model;
    std::size_t workers{4};
};

ServeOptions parse_serve(int argc, char** argv) {
    ServeOptions o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if      (a == "--port"    && i + 1 < argc) o.port    = static_cast<uint16_t>(std::stoi(argv[++i]));
        else if (a == "--bind"    && i + 1 < argc) o.bind    = argv[++i];
        else if (a == "--model"   && i + 1 < argc) o.model   = argv[++i];
        else if (a == "--workers" && i + 1 < argc) o.workers = static_cast<std::size_t>(std::stoi(argv[++i]));
    }
    return o;
}

int run_server(const ServeOptions& opt) {
    using namespace aegis;

    LSTM lstm;
    if (!opt.model.empty()) {
        try {
            lstm.load(opt.model, kFeature, 64, 2);
            std::cout << "[aegis] model loaded from " << opt.model << "\n";
        } catch (const std::exception& e) {
            std::cerr << "[aegis] model load failed: " << e.what() << "\n";
        }
    } else {
        std::cout << "[aegis] running without LSTM (statistics only)\n";
    }

    auto key = AESGCM::random_key();
    AESGCM cipher(key);

    std::cout << "[aegis] ephemeral AES-256-GCM key: ";
    for (auto b : key) {
        char hex[3]; std::snprintf(hex, sizeof(hex), "%02x", b);
        std::cout << hex;
    }
    std::cout << "\n";

    SessionRegistry registry;
    Analyzer analyzer;
    if (lstm.loaded()) analyzer.set_model(&lstm);

    auto handler = [&](const std::string& body,
                       const std::string& sid) -> std::string {
        auto sess = registry.get_or_create(sid);

        PlayerFrame f;
        f.t             = jsonlite::jnum(body, "t");
        f.aim_x         = jsonlite::jnum(body, "aim_x");
        f.aim_y         = jsonlite::jnum(body, "aim_y");
        f.aim_speed     = jsonlite::jnum(body, "aim_speed");
        f.aim_jerk      = jsonlite::jnum(body, "aim_jerk");
        f.fire_interval = jsonlite::jnum(body, "fire_interval");
        f.move_speed    = jsonlite::jnum(body, "move_speed");
        f.reaction_time = jsonlite::jnum(body, "reaction_time");
        f.fov_visible   = jsonlite::jnum(body, "fov_visible");
        f.kill_distance = jsonlite::jnum(body, "kill_distance");
        sess->ingest(f);

        const auto frames = sess->snapshot(kSeqLen);
        const auto verdict = analyzer.evaluate(frames, sess->count());
        return analyzer.to_json(verdict, sid);
    };

    Server::Config cfg;
    cfg.bind_addr = opt.bind;
    cfg.port      = opt.port;
    cfg.workers   = opt.workers;

    Server server(cfg, std::move(cipher), std::move(handler));
    server.start();

    std::cout << "[aegis] ready. Ctrl+C to stop.\n";
    for (;;) std::this_thread::sleep_for(std::chrono::hours(24));
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string cmd = argv[1];
    if (cmd == "--selftest") return aegis::selftest::run_all();
    if (cmd == "--serve")    return run_server(parse_serve(argc, argv));

    print_usage(argv[0]);
    return 1;
}
