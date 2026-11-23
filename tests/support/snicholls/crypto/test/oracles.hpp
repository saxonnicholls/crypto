//
//  oracles.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Test support for the cross-implementation fixtures, tests/fixtures/oracles/ (scripts/generate_oracle_fixtures.py):
//  each file's rows, refusing to run on a file that is missing or holds fewer rows than its header states.
//  Test-only; not installed, not part of the library.
//

#ifndef snicholls_crypto_test_oracles_hpp
#define snicholls_crypto_test_oracles_hpp

#include <snicholls/crypto/test/fixtures.hpp>

#include <cstdint>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace snicholls::crypto::test {

// The rows of tests/fixtures/oracles/<name>; the "# <n> cases" header line must match the rows read
inline std::vector<std::vector<std::string>> oracle_rows(const std::string& name)
{
    auto rows = read_fixture("oracles/" + name);
    std::ifstream in(std::string(SNICHOLLS_CRYPTO_FIXTURE_DIR) + "/oracles/" + name);
    std::size_t stated = 0;
    for (std::string line; std::getline(in, line);)
        if (line.size() > 2 && line[0] == '#' && line.find(" cases") != std::string::npos)
            stated = std::stoul(line.substr(2));
    if (stated == 0 || stated != rows.size())
        throw std::runtime_error("oracle fixture " + name + ": the header and the rows disagree");
    return rows;
}

// A byte view of a vector, for the library's spans
inline std::span<const std::uint8_t> view(const std::vector<std::uint8_t>& v) noexcept { return {v.data(), v.size()}; }

template <class V>
std::string text_of(const V& v) { return std::string(v.data(), v.size()); }

} // namespace snicholls::crypto::test

#endif /* snicholls_crypto_test_oracles_hpp */
