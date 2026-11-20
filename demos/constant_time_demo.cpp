//
//  constant_time_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//

// A secret condition becomes a mask, never a branch.
#include <snicholls/crypto/constant_time.hpp>

#include <array>
#include <cstdint>
#include <cstdio>

int main()
{
    //! [ct]
    namespace ct = snicholls::crypto::ct;
    const std::uint64_t secret_bit = 1;                     // say, a bit of a private key
    const std::uint64_t mask = ct::mask_from_bit(secret_bit);
    std::uint32_t a = 10, b = 20;
    ct::conditional_swap(mask, a, b);                       // swapped, with no branch on secret_bit
    const auto chosen = ct::select<std::uint32_t>(ct::mask_less(a, b), a, b);   // min(a, b) without a branch

    const std::array<std::uint8_t, 4> tag{1, 2, 3, 4}, expected{1, 2, 3, 4};
    const bool same = ct::equal(tag, expected);             // a MAC check that does not stop at the first difference
    //! [ct]
    std::printf("after swap: a = %u, b = %u; smaller = %u; tags equal: %s\n", a, b, chosen, same ? "yes" : "no");
    return a == 20 && b == 10 && chosen == 10 && same ? 0 : 1;
}
