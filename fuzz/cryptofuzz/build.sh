#!/bin/bash -eu
#
#  build.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  Builds Cryptofuzz with the snicholls-crypto module and libsecp256k1's module beside it, so Cryptofuzz's
#  differential driver compares the two on secp256k1 (fuzz/cryptofuzz/README.md). Written as OSS-Fuzz runs a
#  build script ($SRC, $OUT, $CC, $CXX, $CFLAGS, $CXXFLAGS, $LIB_FUZZING_ENGINE), with defaults for a local run.
#  Expects, under $SRC: cryptofuzz (with its submodules), snicholls-crypto (with its), secp256k1 at v0.7.0 (the
#  internal API Cryptofuzz's secp256k1 module is written against: v0.8.0 renamed secp256k1_eckey_pubkey_serialize).
#
#      SRC=/path/to/src OUT=/path/to/out fuzz/cryptofuzz/build.sh
#

SRC="${SRC:-$PWD/src}"
OUT="${OUT:-$PWD/out}"
export CC="${CC:-clang}" CXX="${CXX:-clang++}"
export CFLAGS="${CFLAGS:--fsanitize=address,undefined,fuzzer-no-link -O2 -g}"
export CXXFLAGS="${CXXFLAGS:--fsanitize=address,undefined,fuzzer-no-link -O2 -g}"
LIB_FUZZING_ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
set -euo pipefail
mkdir -p "$OUT"

# libsecp256k1, for Cryptofuzz's secp256k1 module (as its docs/secp256k1.md builds it)
cd "$SRC/secp256k1"
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBUILD_SHARED_LIBS=OFF -DSECP256K1_BUILD_TESTS=OFF \
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF -DSECP256K1_BUILD_BENCHMARK=OFF -DSECP256K1_ENABLE_MODULE_RECOVERY=ON \
    -DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON -DSECP256K1_ENABLE_MODULE_ECDH=ON -DSECP256K1_EXPERIMENTAL=ON >/dev/null
cmake --build build -j"$(nproc)" >/dev/null
export SECP256K1_INCLUDE_PATH="$SRC/secp256k1"
export LIBSECP256K1_A_PATH="$(find "$SRC/secp256k1/build" -name libsecp256k1.a | head -1)"

# The module, and its registration in Cryptofuzz's entry point and module list (idempotent)
cd "$SRC/cryptofuzz"
mkdir -p modules/snicholls-crypto
cp "$SRC/snicholls-crypto/fuzz/cryptofuzz/module.h" "$SRC/snicholls-crypto/fuzz/cryptofuzz/module.cpp" \
   "$SRC/snicholls-crypto/fuzz/cryptofuzz/Makefile" modules/snicholls-crypto/
python3 - <<'PATCH'
s = open("entry.cpp").read()
if "CRYPTOFUZZ_SNICHOLLS_CRYPTO" not in s:
    inc = "#if defined(CRYPTOFUZZ_SECP256K1)\n  #include <modules/secp256k1/module.h>\n#endif\n"
    load = "#if defined(CRYPTOFUZZ_SECP256K1)\n    driver->LoadModule( std::make_shared<cryptofuzz::module::secp256k1>() );\n#endif\n"
    assert inc in s and load in s, "entry.cpp has changed: register the module by hand"
    s = s.replace(inc, inc + "\n#if defined(CRYPTOFUZZ_SNICHOLLS_CRYPTO)\n  #include <modules/snicholls-crypto/module.h>\n#endif\n")
    s = s.replace(load, load + "\n#if defined(CRYPTOFUZZ_SNICHOLLS_CRYPTO)\n    driver->LoadModule( std::make_shared<cryptofuzz::module::snicholls_crypto>() );\n#endif\n")
    open("entry.cpp", "w").write(s)
r = open("gen_repository.py").read()
if 'Module("snicholls-crypto")' not in r:
    # the list is kept sorted (gen_repository.py asserts it): before the first name that sorts after ours
    import re
    names = re.findall(r'^modules\.Add\( Module\("([^"]+)"\) \)$', r, re.M)
    assert names, "gen_repository.py has changed: add the module's name by hand"
    after = [n for n in names if n > "snicholls-crypto"]
    line = 'modules.Add( Module("snicholls-crypto") )\n'
    if after:
        anchor = 'modules.Add( Module("%s") )\n' % after[0]
        r = r.replace(anchor, line + anchor, 1)
    else:
        anchor = 'modules.Add( Module("%s") )\n' % names[-1]
        r = r.replace(anchor, anchor + line, 1)
    open("gen_repository.py", "w").write(r)
PATCH

# Cryptofuzz's generated tables, which every module's build includes
python3 gen_repository.py

# Only what both modules offer: the secp256k1 and Ed25519 operations of module.h
printf '%s' '"--force-module=snicholls-crypto --operations=ECC_PrivateToPublic,ECC_ValidatePubkey,ECDSA_Sign,ECDSA_Verify,ECDSA_Recover,Schnorr_Sign,Schnorr_Verify --curves=secp256k1,ed25519 --digests=NULL,SHA256"' > extra_options.h

export CXXFLAGS="$CXXFLAGS -DCRYPTOFUZZ_NO_OPENSSL -DCRYPTOFUZZ_SECP256K1 -DCRYPTOFUZZ_SNICHOLLS_CRYPTO"
( cd modules/snicholls-crypto && SNICHOLLS_CRYPTO_PATH="$SRC/snicholls-crypto" make -j"$(nproc)" )
( cd modules/secp256k1 && make -j"$(nproc)" )
LIBFUZZER_LINK="$LIB_FUZZING_ENGINE" make -j"$(nproc)" cryptofuzz
cp cryptofuzz "$OUT/cryptofuzz-snicholls-crypto"
echo "build.sh: $OUT/cryptofuzz-snicholls-crypto"
