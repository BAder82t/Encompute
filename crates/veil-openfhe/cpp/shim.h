// Thin C++ shim over OpenFHE CKKS, exposed to Rust through cxx.
//
// Key roles: `Context` is the evaluator (crypto context, public key,
// evaluation keys); `SecretKey` is the client's decryption key and is never
// needed by evaluation functions.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace veil_openfhe {

// Defined in shim.cc so OpenFHE headers stay out of the cxx-generated code.
struct ContextImpl;
struct SecretKeyImpl;
struct CiphertextImpl;

class Context {
 public:
  explicit Context(std::unique_ptr<ContextImpl> impl);
  ~Context();
  std::unique_ptr<ContextImpl> impl;
};

class SecretKey {
 public:
  explicit SecretKey(std::unique_ptr<SecretKeyImpl> impl);
  ~SecretKey();
  std::unique_ptr<SecretKeyImpl> impl;
};

class Ciphertext {
 public:
  explicit Ciphertext(std::unique_ptr<CiphertextImpl> impl);
  ~Ciphertext();
  std::unique_ptr<CiphertextImpl> impl;
};

// ring_dim == 0 lets OpenFHE choose the smallest 128-bit-compliant ring.
std::unique_ptr<Context> new_context(uint32_t ring_dim, uint32_t mult_depth,
                                     uint32_t scale_bits,
                                     uint32_t first_mod_bits,
                                     uint32_t num_large_digits,
                                     uint32_t slots);
// Generates the key pair, relinearization and rotation keys. Keeps the
// public and evaluation keys in `ctx`; returns the secret key.
std::unique_ptr<SecretKey> keygen(Context& ctx,
                                  rust::Slice<const int32_t> rotations);

uint32_t ring_dimension(const Context& ctx);
uint32_t log_qp(const Context& ctx);

std::unique_ptr<Ciphertext> encrypt(const Context& ctx,
                                    rust::Slice<const double> values);
rust::Vec<double> decrypt(const Context& ctx, const SecretKey& sk,
                          const Ciphertext& ct);

std::unique_ptr<Ciphertext> add(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b);
std::unique_ptr<Ciphertext> sub(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b);
std::unique_ptr<Ciphertext> neg(const Context& ctx, const Ciphertext& a);
std::unique_ptr<Ciphertext> mul(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b);
std::unique_ptr<Ciphertext> add_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p);
std::unique_ptr<Ciphertext> mul_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p);
std::unique_ptr<Ciphertext> add_const(const Context& ctx, const Ciphertext& a,
                                      double c);
std::unique_ptr<Ciphertext> mul_const(const Context& ctx, const Ciphertext& a,
                                      double c);
std::unique_ptr<Ciphertext> rotate(const Context& ctx, const Ciphertext& a,
                                   int32_t k);

size_t serialized_size(const Ciphertext& ct);
uint32_t level(const Ciphertext& ct);

}  // namespace veil_openfhe
