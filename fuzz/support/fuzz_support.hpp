//
//  fuzz_support.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  The differential fuzz harness's shared pieces: reading a fuzz input, the adversarial values the targets
//  substitute in, the divergence report, and the client for the JSON-lines oracle processes of scripts/oracles/.
//  Test-only, built with -DSNICHOLLS_CRYPTO_BUILD_FUZZ=ON; never part of the library.
//

#ifndef snicholls_crypto_fuzz_support_hpp
#define snicholls_crypto_fuzz_support_hpp

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cerrno>

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;

namespace snicholls::crypto::fuzz {

// The input, read front to back; past the end every read is zeros, so any input is a whole case
class input {
public:
    input(const std::uint8_t* p, std::size_t n) noexcept : p_(p), n_(n) {}
    std::uint8_t byte() noexcept { return i_ < n_ ? p_[i_++] : 0; }
    template <std::size_t N>
    std::array<std::uint8_t, N> take() noexcept
    {
        std::array<std::uint8_t, N> out{};
        for (auto& b : out)
            b = byte();
        return out;
    }
    std::vector<std::uint8_t> rest() noexcept
    {
        std::vector<std::uint8_t> out(p_ + (i_ < n_ ? i_ : n_), p_ + n_);
        i_ = n_;
        return out;
    }
    std::vector<std::uint8_t> take_upto(std::size_t max) noexcept
    {
        const std::size_t k = byte() % (max + 1);
        std::vector<std::uint8_t> out;
        for (std::size_t j = 0; j < k && i_ < n_; ++j)
            out.push_back(p_[i_++]);
        return out;
    }

private:
    const std::uint8_t* p_;
    std::size_t n_;
    std::size_t i_ = 0;
};

inline std::string hex(std::span<const std::uint8_t> b)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    for (auto x : b) {
        s += d[x >> 4];
        s += d[x & 15];
    }
    return s;
}

// A divergence: the case is printed and the process aborts, so libFuzzer keeps the input as a crash artifact,
// which fuzz/run.sh minimises into fuzz/regressions/<target>/
[[noreturn]] inline void divergence(const char* target, const std::string& what)
{
    std::fprintf(stderr, "\n==== DIVERGENCE in %s: %s\n", target, what.c_str());
    std::fflush(stderr);
    std::abort();
}

// The control: with SNICHOLLS_CRYPTO_FUZZ_CONTROL=1 in the environment, an input that starts with "DIVERGE" is
// reported as a divergence, so the report, the abort, libFuzzer's artifact and fuzz/run.sh's minimisation can be
// seen to work (the CTest fuzz.<target>.control expects it to fail)
inline void control(const char* target, const std::uint8_t* data, std::size_t size)
{
    static const bool on = std::getenv("SNICHOLLS_CRYPTO_FUZZ_CONTROL") != nullptr;
    if (on && size >= 7 && std::memcmp(data, "DIVERGE", 7) == 0)
        divergence(target, "the control case (SNICHOLLS_CRYPTO_FUZZ_CONTROL)");
}

// secp256k1's adversarial scalars and field elements (big-endian): 0, 1, n - 1, n, n + 1, (n - 1)/2, (n + 1)/2,
// p - 1, p, 2^256 - 1
inline std::array<std::uint8_t, 32> secp256k1_edge(std::uint8_t which) noexcept
{
    static const char* table[] = {
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142",
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    const char* h = table[which % (sizeof table / sizeof table[0])];
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        auto v = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i] = static_cast<std::uint8_t>(v(h[2 * i]) << 4 | v(h[2 * i + 1]));
    }
    return out;
}

// Every small-order Curve25519 point in every encoding (as the oracle generator's SMALL_ORDER)
inline std::array<std::uint8_t, 32> curve25519_small_order(std::uint8_t which) noexcept
{
    static const char* table[] = {
        "0100000000000000000000000000000000000000000000000000000000000000",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    };
    const char* h = table[which % (sizeof table / sizeof table[0])];
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 32; ++i) {
        auto v = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
        out[i] = static_cast<std::uint8_t>(v(h[2 * i]) << 4 | v(h[2 * i + 1]));
    }
    return out;
}

// ---------------------------------------------------------------------------------------------------------------
// The JSON-lines oracles (scripts/oracles/): one process per program, started once and asked one line at a time

inline std::string json_string(std::string_view s)
{
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') {
            out += '\\';
            out += static_cast<char>(c);
        } else if (c < 0x20 || c >= 0x7f) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\u%04x", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out + "\"";
}

class oracle_process {
public:
    explicit oracle_process(std::vector<std::string> argv)
    {
        int in[2], out[2];
        if (pipe(in) != 0 || pipe(out) != 0)
            std::abort();
        posix_spawn_file_actions_t fa;
        posix_spawn_file_actions_init(&fa);
        posix_spawn_file_actions_adddup2(&fa, in[0], 0);
        posix_spawn_file_actions_adddup2(&fa, out[1], 1);
        posix_spawn_file_actions_addclose(&fa, in[1]);
        posix_spawn_file_actions_addclose(&fa, out[0]);
        std::vector<char*> args;
        for (auto& a : argv)
            args.push_back(a.data());
        args.push_back(nullptr);
        if (posix_spawn(&pid_, args[0], &fa, nullptr, args.data(), environ) != 0) {
            std::fprintf(stderr, "fuzz: cannot start oracle %s\n", args[0]);
            std::abort();
        }
        posix_spawn_file_actions_destroy(&fa);
        close(in[0]);
        close(out[1]);
        to_ = in[1];
        from_ = out[0];
    }
    oracle_process(const oracle_process&) = delete;
    oracle_process& operator=(const oracle_process&) = delete;

    // One request (a JSON object's members, without braces) and its answer line. Reads and writes are retried on
    // EINTR: libFuzzer's -timeout arms a periodic SIGALRM, which would otherwise end a read early and look like an
    // oracle that exited
    std::string ask(const std::string& members)
    {
        const std::string request = "{" + members + "}\n";
        for (std::size_t done = 0; done < request.size();) {
            const ssize_t n = write(to_, request.data() + done, request.size() - done);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0) {
                std::fprintf(stderr, "fuzz: an oracle stopped reading\n");
                std::abort();
            }
            done += static_cast<std::size_t>(n);
        }
        std::string line;
        for (;;) {
            if (pos_ == len_) {
                const ssize_t n = read(from_, buf_, sizeof buf_);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n <= 0)
                    break;
                pos_ = 0;
                len_ = static_cast<std::size_t>(n);
            }
            const char c = buf_[pos_++];
            if (c == '\n')
                break;
            line += c;
        }
        if (line.empty()) {
            std::fprintf(stderr, "fuzz: an oracle exited\n");
            std::abort();
        }
        if (line.find("\"crash\"") != std::string::npos) {
            std::fprintf(stderr, "fuzz: an oracle crashed on {%s}: %s\n", members.c_str(), line.c_str());
            std::abort();
        }
        return line;
    }

private:
    pid_t pid_ = 0;
    int to_ = -1;
    int from_ = -1;
    char buf_[4096];
    std::size_t pos_ = 0, len_ = 0;
};

// A string member of an answer, or "" (the oracles write compact JSON; values are hex, text or numbers)
inline std::string field(const std::string& answer, std::string_view key)
{
    const std::string k = "\"" + std::string(key) + "\":";
    const auto at = answer.find(k);
    if (at == std::string::npos)
        return {};
    auto i = at + k.size();
    if (i < answer.size() && answer[i] == '"') {
        std::string out;
        for (++i; i < answer.size() && answer[i] != '"'; ++i)
            out += answer[i];
        return out;
    }
    std::string out;
    for (; i < answer.size() && answer[i] != ',' && answer[i] != '}'; ++i)
        out += answer[i];
    return out;
}

inline bool refused(const std::string& answer) { return answer.find("\"error\"") != std::string::npos; }

inline std::string env_or(const char* name, const char* fallback)
{
    const char* v = std::getenv(name);
    return v && *v ? v : fallback;
}

// The Python oracle (scripts/oracles/python/oracle.py) and the Rust one, built by fuzz/run.sh
inline oracle_process& python_oracle()
{
    static oracle_process p({env_or("ORACLES_HOME", "/opt/oracles") + "/venv/bin/python", "-I",
                             std::string(SNICHOLLS_CRYPTO_SOURCE_DIR) + "/scripts/oracles/python/oracle.py"});
    return p;
}

inline oracle_process& rust_oracle()
{
    static oracle_process p({env_or("CARGO_TARGET_DIR", "/opt/oracles/rust-target") + "/release/snicholls-crypto-oracle"});
    return p;
}

} // namespace snicholls::crypto::fuzz

#endif /* snicholls_crypto_fuzz_support_hpp */
