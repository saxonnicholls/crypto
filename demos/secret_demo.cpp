//
//  secret_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// Key material in a buffer that wipes itself.
#include <snicholls/crypto/secret.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <utility>

int main()
{
    //! [secret]
    std::array<std::uint8_t, 32> from_somewhere{};
    from_somewhere[0] = 0x42;
    snicholls::crypto::secret_bytes<32> key(std::move(from_somewhere));   // takes the bytes, wipes the array
    snicholls::crypto::secret_bytes<32> second = key.clone();             // copies are explicit
    snicholls::crypto::secret_bytes<32> moved = std::move(key);           // a move wipes the source
    const std::uint8_t first = moved.reveal()[0];                         // reveal(): the one way in
    //! [secret]
    std::printf("first byte %#x; source array wiped: %s; moved-from wiped: %s; clone equal: %s\n", first,
                from_somewhere[0] == 0 ? "yes" : "no", key.reveal()[0] == 0 ? "yes" : "no", second == moved ? "yes" : "no");
    return first == 0x42 && from_somewhere[0] == 0 && key.reveal()[0] == 0 && second == moved ? 0 : 1;
}
