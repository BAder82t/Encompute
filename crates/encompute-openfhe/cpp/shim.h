// Evaluator-side shim over OpenFHE CKKS, exposed to Rust through cxx.
// Holds no secret key and offers no key generation or decryption.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "rust/cxx.h"

namespace encompute_openfhe {

// Defined in shim.cc so OpenFHE headers stay out of the cxx-generated code.
struct ContextImpl;
struct CiphertextImpl;

class Context {
 public:
  explicit Context(std::unique_ptr<ContextImpl> impl);
  ~Context();
  std::unique_ptr<ContextImpl> impl;
};

class Ciphertext {
 public:
  explicit Ciphertext(std::unique_ptr<CiphertextImpl> impl);
  ~Ciphertext();
  std::unique_ptr<CiphertextImpl> impl;
};

std::unique_ptr<Context> new_context(uint32_t ring_dim, uint32_t mult_depth,
                                     uint32_t scale_bits,
                                     uint32_t first_mod_bits,
                                     uint32_t num_large_digits,
                                     uint32_t slots);
uint32_t ring_dimension(const Context& ctx);
uint32_t log_qp(const Context& ctx);

// Load evaluation keys exported by a client (see the client shim for the
// framing). Returns the key tag. Throws if they belong to another context.
rust::String load_evaluation_keys(Context& ctx, rust::Slice<const uint8_t> bytes);

std::unique_ptr<Ciphertext> load_ciphertext(const Context& ctx,
                                            rust::Slice<const uint8_t> bytes);
rust::Vec<uint8_t> store_ciphertext(const Ciphertext& ct);

std::unique_ptr<Ciphertext> add(const Context& ctx, const Ciphertext& a, const Ciphertext& b);
std::unique_ptr<Ciphertext> sub(const Context& ctx, const Ciphertext& a, const Ciphertext& b);
std::unique_ptr<Ciphertext> neg(const Context& ctx, const Ciphertext& a);
std::unique_ptr<Ciphertext> mul(const Context& ctx, const Ciphertext& a, const Ciphertext& b);
std::unique_ptr<Ciphertext> add_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p);
std::unique_ptr<Ciphertext> mul_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p);
std::unique_ptr<Ciphertext> add_const(const Context& ctx, const Ciphertext& a, double c);
std::unique_ptr<Ciphertext> mul_const(const Context& ctx, const Ciphertext& a, double c);
std::unique_ptr<Ciphertext> rotate(const Context& ctx, const Ciphertext& a, int32_t k);
uint32_t level(const Ciphertext& ct);

}  // namespace encompute_openfhe
