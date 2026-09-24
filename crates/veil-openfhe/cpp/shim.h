// Thin C++ shim over OpenFHE CKKS, exposed to Rust through cxx.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace veil_openfhe {

// Defined in shim.cc so OpenFHE headers stay out of the cxx-generated code.
struct CkksContextImpl;
struct CiphertextImpl;

class CkksContext {
 public:
  explicit CkksContext(std::unique_ptr<CkksContextImpl> impl);
  ~CkksContext();
  std::unique_ptr<CkksContextImpl> impl;
};

class Ciphertext {
 public:
  explicit Ciphertext(std::unique_ptr<CiphertextImpl> impl);
  ~Ciphertext();
  std::unique_ptr<CiphertextImpl> impl;
};

std::unique_ptr<CkksContext> new_ckks_context(uint32_t mult_depth,
                                              uint32_t scale_mod_size,
                                              uint32_t batch_size);
uint32_t ring_dimension(const CkksContext& ctx);
std::unique_ptr<Ciphertext> encrypt(const CkksContext& ctx,
                                    rust::Slice<const double> values);
std::unique_ptr<Ciphertext> add(const CkksContext& ctx, const Ciphertext& a,
                                const Ciphertext& b);
rust::Vec<double> decrypt(const CkksContext& ctx, const Ciphertext& ct,
                          size_t len);

}  // namespace veil_openfhe
