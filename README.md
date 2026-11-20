# snicholls-crypto

Elliptic curves, signatures and wallet key derivation, header-only C++20, constant-time wherever a secret is
involved. Part of the snicholls libraries; it depends on snicholls-core and nothing else.

Status: experimental (0.1, unreleased).

## Building

    git submodule update --init
    make test-werror     # every test, demo and boundary check, warnings as errors
    make docs            # Doxygen, warnings as errors
    make ubuntu          # the same on Ubuntu in Docker, with sanitizers and the Valgrind constant-time check

The design rules, the layout and the contract every change keeps are in CLAUDE.md.
