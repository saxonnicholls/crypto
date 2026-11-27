//
//  ecdsa_demo.cpp
//  snicholls-crypto
//
//  Copyright 2010-2026 Saxon Herschel Nicholls
//
// ECDSA on P-384 (ES384, TLS's ecdsa_secp384r1_sha384): RFC 6979 appendix A.2.6's published test key and its
// SHA-384 signature of "sample" verify, through JOSE's r || s and DER, and fail for another message.
#include <snicholls/crypto/detail/hashes.hpp>
#include <snicholls/crypto/p384/ecdsa.hpp>
#include <snicholls/crypto/test/hex.hpp>

#include <cstdio>
#include <string>
#include <string_view>

int main()
{
    using snicholls::crypto::test::hex;
    using snicholls::crypto::test::to_hex;
    auto bytes = [](std::string_view s) { return std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); };
    //! [p384]
    namespace p384 = snicholls::crypto::p384;
    // RFC 6979's published test key and signature; a real key comes from a CSPRNG
    const auto key = p384::private_key::from_bytes(
        hex<48>("6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5")).unwrap();
    const p384::public_key pub = key.public_key();
    const p384::signature sig{hex<48>("94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46"),
                              hex<48>("99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8")};
    const auto ok = p384::verify_message(pub, bytes("sample"), p384::signature::from_jose(sig.jose()));   // ES384: r || s
    const auto der = sig.der();                                                                          // TLS, X.509
    const auto from_der = p384::signature::from_der(std::span<const std::uint8_t>(der.data(), der.size()));
    const auto wrong = p384::verify_message(pub, bytes("other"), sig);                                  // errc::invalid_signature
    //! [p384]
    const bool der_back = from_der.is_ok() && from_der.unwrap() == sig;
    std::printf("public key %s\nverifies: %s; other message: %s; DER round trip: %s\n", to_hex(pub.compressed()).c_str(),
                ok.is_ok() ? "yes" : "no", wrong.is_ok() ? "accepted" : "refused", der_back ? "yes" : "no");
    return ok.is_ok() && !wrong.is_ok() && der_back &&
                   to_hex(pub.point().x.to_bytes()) ==
                       "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13"
               ? 0
               : 1;
}
