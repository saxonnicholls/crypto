//
//  fixtures.hpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
//  Test support: reads the line-based fixtures under tests/fixtures/ ("#" comments, space-separated fields).
//  Test-only; not installed, not part of the library.
//

#ifndef snicholls_crypto_test_fixtures_hpp
#define snicholls_crypto_test_fixtures_hpp

#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace snicholls::crypto::test {

// Every non-comment line of tests/fixtures/<name>, split on spaces; "-" stays "-" for the caller to read as empty
inline std::vector<std::vector<std::string>> read_fixture(const std::string& name)
{
    std::ifstream in(std::string(SNICHOLLS_CRYPTO_FIXTURE_DIR) + "/" + name);
    if (!in)
        throw std::runtime_error("fixture not found: " + name);
    std::vector<std::vector<std::string>> rows;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream fields(line);
        std::vector<std::string> row;
        for (std::string f; fields >> f;)
            row.push_back(f == "-" ? std::string() : f);
        rows.push_back(std::move(row));
    }
    return rows;
}

} // namespace snicholls::crypto::test

#endif /* snicholls_crypto_test_fixtures_hpp */
