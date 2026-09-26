// Evaluator-side OpenFHE BinFHE shim for exact programs: Boolean gates on
// LWE ciphertexts, with bootstrapping keys loaded from the client. No key
// generation, encryption or decryption here (the client shim has those).
// Integer semantics live in Rust (encompute-openfhe-exact), not here.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace encompute_openfhe {

struct BinContextImpl;
struct BinCiphertextImpl;

class BinContext {
 public:
  explicit BinContext(std::unique_ptr<BinContextImpl> impl);
  ~BinContext();
  std::unique_ptr<BinContextImpl> impl;
};

class BinCiphertext {
 public:
  explicit BinCiphertext(std::unique_ptr<BinCiphertextImpl> impl);
  ~BinCiphertext();
  std::unique_ptr<BinCiphertextImpl> impl;
};

// A BinFHE context for a vetted parameter set ("STD128", GINX bootstrapping).
std::unique_ptr<BinContext> bin_new_context(rust::Str paramset);
// LWE dimension n and modulus q of the context (parameter identity checks).
uint64_t bin_lwe_n(const BinContext& ctx);
uint64_t bin_lwe_q(const BinContext& ctx);
// Load the client's bootstrapping keys (refresh and switching keys).
void bin_load_keys(BinContext& ctx, rust::Slice<const uint8_t> refresh,
                   rust::Slice<const uint8_t> switching);
// Deserialize a ciphertext; refused unless it belongs to this parameter set.
std::unique_ptr<BinCiphertext> bin_load(const BinContext& ctx, rust::Slice<const uint8_t> bytes);
rust::Vec<uint8_t> bin_store(const BinCiphertext& ct);
// A two-input gate: 0 OR, 1 AND, 2 NOR, 3 NAND, 4 XOR, 5 XNOR (bootstrapped).
std::unique_ptr<BinCiphertext> bin_gate(const BinContext& ctx, uint8_t gate,
                                        const BinCiphertext& a, const BinCiphertext& b);
// NOT (no bootstrapping).
std::unique_ptr<BinCiphertext> bin_not(const BinContext& ctx, const BinCiphertext& a);
// A trivial encryption of a public bit.
std::unique_ptr<BinCiphertext> bin_constant(const BinContext& ctx, bool value);
std::unique_ptr<BinCiphertext> bin_clone(const BinCiphertext& ct);

}  // namespace encompute_openfhe
