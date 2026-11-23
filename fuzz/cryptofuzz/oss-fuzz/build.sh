#!/bin/bash -eu
#
#  build.sh
#  snicholls-crypto
#
#  Copyright 2010-2026 Saxon Herschel Nicholls
#
#  OSS-Fuzz's build script for snicholls-crypto (fuzz/cryptofuzz/README.md, route 2): the module's own build,
#  with OSS-Fuzz's compilers, flags and $LIB_FUZZING_ENGINE.
#
"$SRC/snicholls-crypto/fuzz/cryptofuzz/build.sh"
