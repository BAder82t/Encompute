// Shared by the evaluator shim (this crate) and the client shim
// (encompute-openfhe-client). Plain C++, not exposed through cxx.
#pragma once

#include <cstdint>
#include <mutex>
#include <string>

#include "openfhe.h"

namespace encompute_openfhe {

// OpenFHE v1.5.1 is not safe to call from several threads at once, even on
// separate contexts (ADR-001). Every OpenFHE call, including destruction of
// OpenFHE objects, holds this lock. It is not recursive.
std::mutex& openfhe_mutex();

// CKKS context for Encompute's parameters (FLEXIBLEAUTO, HYBRID, ternary,
// 128-bit classical). ring_dim == 0 lets OpenFHE choose; slots == 0 is full
// packing. Caller holds openfhe_mutex().
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> make_context(
    uint32_t ring_dim, uint32_t mult_depth, uint32_t scale_bits,
    uint32_t first_mod_bits, uint32_t num_large_digits, uint32_t slots);

// BGV-RNS context for exact programs (ADR-009): plaintext modulus 65537,
// 128-bit classical, HYBRID key switching, FIXEDAUTO. Evaluation is exact
// modular arithmetic with no randomness, so it is reproducible byte for
// byte (the basis of re-execution verification, ADR-009). Caller holds
// openfhe_mutex().
lbcrypto::CryptoContext<lbcrypto::DCRTPoly> make_bgv_context(uint32_t mult_depth);

// Plaintext modulus of the BGV context.
constexpr int64_t kBgvPlaintextModulus = 65537;

// Evaluation keys live in OpenFHE's global maps under their key tag. Holders
// (a client after keygen, an evaluator after loading) retain the tag; the
// keys are erased when the last holder releases it. Caller holds the mutex.
void retain_key_tag(const std::string& tag);
void release_key_tag(const std::string& tag);

}  // namespace encompute_openfhe
