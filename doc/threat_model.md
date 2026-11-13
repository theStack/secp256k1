# Threat model of libsecp256k1

## 1. Scope and assumptions

This document describes the threat model of libsecp256k1: the assumed attacker model, the security goals of the library, and the resulting vulnerability reporting policy.

### 1.1 Covered code and versions

In scope is the library itself (`src/` and `include/`, excluding the items below) in the latest release and on the `master` branch, including all modules and configuration options that do not require `--enable-experimental` (Autotools) or `-DSECP256K1_EXPERIMENTAL=ON` (CMake). Currently, the only experimental option is the ARM32 assembly implementation.

Out of scope are tests, benchmarks, examples, precomputation tools, the build system, everything in `contrib/`, `sage/` and `tools/` (including the test vector generation scripts), and builds with `-DVERIFY`. `contrib/` contains code that is not part of the library, even where applications copy it. Issues in out-of-scope code, including examples that demonstrate insecure API usage, are welcome as regular public issues.

### 1.2 Secret data

Secret data means:

- Secret keys, including keypair objects.
- Secret nonces and the randomness used to derive them, such as the auxiliary randomness for signing and the MuSig2 session randomness.
- Shared secrets, such as ECDH results.
- Other inputs and outputs that the API documents as secret.
- Intermediate values derived from any of the above that are not intended to be public.

Public keys, signatures, messages, public nonces and other values that a protocol publishes are not secret, and neither is information the library intentionally reveals, such as whether a secret key or a derived nonce is valid. Functions that only process public data, such as signature verification, are intentionally variable-time.

### 1.3 Attacker model

The security goals assume attackers with the following capabilities:

- **Input attacker:** supplies arbitrary data to any API function argument that takes external input, such as serialized public keys, signatures, messages and tweaks.
- **Protocol attacker:** participates in a multi-party protocol, such as a malicious co-signer in MuSig2, and deviates arbitrarily from it.
- **Timing and cache observer:** measures the execution time of library operations, remotely or locally, or observes memory access patterns through shared caches.
- **Later memory reader:** obtains memory contents of the process after a library call has returned, for example through an unrelated memory disclosure bug in the application. Protection against this attacker is best-effort (see 2.4).

### 1.4 Non-goals

The following are outside the security goals:

- Physical attacks, such as power analysis, electromagnetic analysis and fault injection. The library includes hardening that can make some of these attacks harder, such as context randomization (blinding) and auxiliary randomness in nonce derivation, but makes no claim about how effective it is.
- Speculative execution attacks and other microarchitectural leaks that are not caused by secret-dependent control flow or memory access in the library's code.
- Hardware on which basic arithmetic instructions have data-dependent timing, such as ARM32 cores with an early-terminating multiplier.
- An attacker who can read or modify process memory while the library operates on secret data, and mechanisms that copy process memory elsewhere, such as swapping, core dumps and hibernation.
- Weak or reused randomness supplied by the caller. The library does not provide a random number generator.
- Misbehavior of code supplied by the caller, such as custom nonce functions, hash functions, callbacks and compile-time overrides of library defaults.

## 2. Security goals

### 2.1 Cryptographic correctness

The library must correctly implement the algorithms and protocols it provides, in accordance with their specifications and the API documentation. This includes key derivation and validation, nonce derivation and protocol state handling (including measures against nonce reuse), use of caller-provided randomness as specified, validation of externally supplied inputs, and handling of exceptional conditions and failure cases, including the documented return and output values on failure. API documentation that would lead a caller who follows it to use the library insecurely also violates this goal.

### 2.2 Robustness and availability

Valid and adversarial inputs within the documented API contract must not cause crashes, memory corruption, undefined behavior or disproportionate resource consumption.

Violations of documented API preconditions are out of scope, such as passing invalid pointers or uninitialized objects, modifying opaque objects other than through the API, and violating the thread-safety rules for context objects. The library only performs lightweight sanity checks on its objects, such as checking magic bytes. Expensive consistency checks, such as checking that an internal group element lies on the curve, are not intended. Externally supplied inputs must nevertheless be validated as required by the API.

Aborting through the illegal argument callback on a detected API violation is intended. Aborting through the error callback is intended if the cause lies outside the library, such as memory exhaustion, hardware failure, miscompilation or memory corruption by the application. If valid or adversarial inputs can trigger the error callback while the API is used as documented, this is a bug.

### 2.3 Side-channel resistance

In production builds (see 3.2), code that operates on secret data (see 1.2) must not have secret-dependent control flow or memory access (including table lookups), and must not use instructions or library functions with secret-dependent timing (subject to the exclusions in 1.4). This applies to the compiled code: a violation introduced by compiler optimizations or platform-specific behavior counts, even if the source code is constant-time.

### 2.4 Clearing of secret data

The library must clear secret data from memory it manages once it is no longer needed. This covers stack variables and buffers, unintended copies, and caller-owned objects that the API documents as cleared, such as a MuSig2 secret nonce after signing and outputs on failure (not clearing these also violates 2.1). Clearing operations must be implemented in a way that prevents their removal by compiler optimizations.

The result is best-effort: the library cannot clear copies that the compiler keeps in registers or stack slots. Clearing other caller-owned memory, such as the buffer a secret key was passed in, is the caller's responsibility.

## 3. Vulnerability reporting policy

### 3.1 Tested configurations

For the reporting matrix in 3.3, a tested configuration is one of the following platform and compiler combinations covered by CI, built with any released version of the listed compiler:

| Operating system | Architecture | Compiler              |
|------------------|--------------|-----------------------|
| Linux            | x86_64       | GCC, Clang            |
| Linux            | i686         | GCC, Clang            |
| Linux            | ARM32        | GCC                   |
| Linux            | ARM64        | GCC, Clang            |
| Linux            | s390x        | GCC                   |
| Linux            | PPC64LE      | GCC                   |
| macOS            | x86_64       | GCC, Clang            |
| macOS            | ARM64        | GCC, Clang            |
| Windows          | x86_64       | MSVC, clang-cl, MinGW |
| Windows          | x86          | MSVC, MinGW           |

The ARM32 row refers to the generic C implementation. The ARM32 assembly implementation is experimental and therefore out of scope (see 1.1).

Unreleased compiler versions such as development snapshots, bare-metal targets and all platforms not listed are other configurations. The list may change as platform and compiler support evolves. Automated constant-time tests cover only some of these configurations and parts of the API, and are not a proof of constant-time behavior. Side-channel issues in production builds are nevertheless S (see 3.3) in all tested configurations.

### 3.2 Build modes

A *production build* uses `-O1` (or `-O`) to `-O3` (the build system default is `-O2`), or `/O2` with MSVC, without sanitizers, coverage or other instrumentation. Builds with `-O0`, `-Og`, `-Os`, `-Oz`, `-Ofast`, `/Od` or `/O1` are not production builds. Size-optimized builds (`-Os`, `-Oz`, `/O1`) are excluded because they make it more likely that the compiler turns branch-free code into secret-dependent branches. CI runs the automated constant-time tests mainly at `-O2`; `-O1` and `-O3` are covered only on Linux x86_64 (`-O3` only with Clang).

### 3.3 Reporting matrix

- **S (security issue):** report privately as described in [SECURITY.md](../SECURITY.md).
- **P (public issue):** report as a regular public issue or open a pull request. These are handled as regular bugs, not confidentially.

A *tested production build* is a production build (see 3.2) of a tested configuration (see 3.1). *Other builds* are all other builds that are in scope (see 1.1). If an issue violates more than one security goal, it is S if it is S under any of them.

| Violated security goal                   | Tested production builds | Other builds |
|------------------------------------------|:------------------------:|:------------:|
| Cryptographic correctness<sup>1)</sup>   |            S             |      S       |
| Robustness and availability<sup>1)</sup> |            S             |      S       |
| Side-channel resistance                  |            S             |      P       |
| Clearing of secret data<sup>2)</sup>     |            P             |      P       |

<sup>1)</sup> If such an issue turns out to be caused by a compiler bug, it may be resolved in the compiler rather than in the library.

<sup>2)</sup> P because exploiting leftover secret data requires a separate memory disclosure (the later memory reader in 1.3), and the protection is best-effort (see 2.4).

The matrix applies to issues with a plausible security impact, i.e., issues that an attacker as described in 1.3 can trigger or exploit, or that can lead to disclosure of secret data or to incorrect results in honest use. Issues without such an impact, such as undefined behavior without any observable effect or documentation errors that do not lead to insecure use, are always P. If in doubt, report privately.

Issues that fall under the non-goals in 1.4, or that require violating documented API preconditions (see 2.2), are not considered vulnerabilities and do not need to be reported privately. They can be raised publicly, for example as hardening suggestions, but there is no commitment to address them.
