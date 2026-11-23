//
//  text_fuzz.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Differential fuzzing of the text formats against the JSON-lines oracles (scripts/oracles/): base58check
//  against python base58, segwit addresses against the BIP-173 / BIP-350 reference code, mnemonics against
//  python-mnemonic, derivation paths against the bip32 crate. The input is the text itself, after one selector
//  byte; mutations of valid text come from the seed corpus (fuzz/corpus/text).
//
//  The rules (tests/fixtures/README.md): segwit must agree both ways; base58check too, except that python base58
//  strips trailing whitespace, which this library refuses; this library reads only canonical mnemonics and paths,
//  so where it reads text the oracle must read the same value.
//
#include "support/fuzz_support.hpp"

#include <snicholls/crypto/address/base58check.hpp>
#include <snicholls/crypto/address/bech32.hpp>
#include <snicholls/crypto/bip39/mnemonic.hpp>
#include <snicholls/crypto/hd/path.hpp>

namespace f = snicholls::crypto::fuzz;
namespace a = snicholls::crypto::address;
namespace b = snicholls::crypto::bip39;
using snicholls::crypto::hd::derivation_path;

static std::string str(const std::vector<std::uint8_t>& v) { return std::string(v.begin(), v.end()); }

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
    f::control("text", data, size);
    const char* T = "text";
    f::input in(data, size);
    const std::uint8_t which = in.byte();
    const std::string t = str(in.rest());
    if (t.size() > 400)
        return 0;
    const std::string q = f::json_string(t);

    switch (which % 4) {
    case 0: {   // base58check
        const auto ours = a::base58check_decode<128>(t);
        const auto ans = f::python_oracle().ask("\"lib\":\"base58\",\"op\":\"base58check_decode\",\"t\":" + q);
        auto payload = [](const auto& p) { return f::hex(std::span<const std::uint8_t>(p.data(), p.size())); };
        if (ours && (f::refused(ans) || payload(*ours) != f::field(ans, "p")))
            f::divergence(T, "base58check read here, not by python base58 alike: " + q + ": " + ans);
        if (!ours && !f::refused(ans)) {
            // python base58's rule: b58decode strips trailing whitespace first (str.rstrip: also U+001C to U+001F,
            // U+0085 and U+00A0, the code points this harness sends those bytes as). This library refuses the
            // whitespace (CLAUDE.md rule 8); without it, it must read the same payload
            std::string stripped = t;
            auto space = [](unsigned char c) {
                return c == ' ' || (c >= 0x09 && c <= 0x0d) || (c >= 0x1c && c <= 0x1f) || c == 0x85 || c == 0xa0;
            };
            while (!stripped.empty() && space(static_cast<unsigned char>(stripped.back())))
                stripped.pop_back();
            const auto again = a::base58check_decode<128>(stripped);
            if (stripped == t || !again || payload(*again) != f::field(ans, "p"))
                f::divergence(T, "base58check refused here, read by python base58 for no stated reason: " + q + ": " + ans);
        }
        break;
    }
    case 1: {   // segwit, on the main and test networks
        for (const char* hrp : {"bc", "tb"}) {
            const auto ours = a::segwit_decode(hrp, t);
            const auto ans = f::python_oracle().ask(std::string("\"lib\":\"bip350_ref\",\"op\":\"segwit_decode\",\"hrp\":\"") +
                                                    hrp + "\",\"addr\":" + q);
            if (static_cast<bool>(ours) != !f::refused(ans))
                f::divergence(T, std::string("segwit (") + hrp + ") " + q + ": " + ans);
            if (ours && (std::to_string(ours->version) != f::field(ans, "ver") ||
                         f::hex(std::span<const std::uint8_t>(ours->program.data(), ours->program.size())) != f::field(ans, "prog")))
                f::divergence(T, "segwit program " + q);
        }
        break;
    }
    case 2: {   // mnemonic
        const auto ours = b::parse(t);
        const auto ans = f::python_oracle().ask("\"lib\":\"mnemonic\",\"op\":\"bip39_to_entropy\",\"words\":" + q);
        if (ours) {
            const auto e = b::to_entropy(*ours);
            if (f::refused(ans) || f::hex(e.reveal().first(ours->entropy_size())) != f::field(ans, "e"))
                f::divergence(T, "mnemonic read here, not by python-mnemonic alike: " + q + ": " + ans);
        }
        break;
    }
    case 3: {   // derivation path
        const auto ours = derivation_path::parse(t);
        auto ans = f::rust_oracle().ask("\"lib\":\"bip32_rs\",\"op\":\"path_parse\",\"path\":" + q);
        if (ours && f::refused(ans) && t.find('H') != std::string::npos) {
            // the bip32 crate's rule: it reads the marks ' and h, not H (which this library's grammar also reads)
            std::string marked = t;
            for (auto& c : marked)
                if (c == 'H')
                    c = '\'';
            ans = f::rust_oracle().ask("\"lib\":\"bip32_rs\",\"op\":\"path_parse\",\"path\":" + f::json_string(marked));
        }
        if (ours) {
            std::string want;
            for (const auto i : ours->indices())
                want += (want.empty() ? "" : ",") + std::to_string(i);
            if (f::refused(ans) || f::field(ans, "indices") != want)
                f::divergence(T, "path read here, not by the bip32 crate alike: " + q + ": " + ans);
        }
        break;
    }
    }
    return 0;
}
