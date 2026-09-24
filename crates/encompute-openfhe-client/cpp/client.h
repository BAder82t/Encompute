// Client-side shim: the only code that generates keys, encrypts or decrypts.
// Not linked into the evaluator binary.
#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace encompute_openfhe_client {

struct ClientImpl;

class Client {
 public:
  explicit Client(std::unique_ptr<ClientImpl> impl);
  ~Client();
  std::unique_ptr<ClientImpl> impl;
};

// Fresh key pair, relinearization key and one rotation key per entry.
std::unique_ptr<Client> generate(uint32_t ring_dim, uint32_t mult_depth,
                                 uint32_t scale_bits, uint32_t first_mod_bits,
                                 uint32_t num_large_digits, uint32_t slots,
                                 rust::Slice<const int32_t> rotations);
// Restore a client from `export_secret_key` output (holds both halves of the
// key pair). Evaluation keys are not regenerated.
std::unique_ptr<Client> restore(uint32_t ring_dim, uint32_t mult_depth,
                                uint32_t scale_bits, uint32_t first_mod_bits,
                                uint32_t num_large_digits, uint32_t slots,
                                rust::Slice<const uint8_t> secret);

rust::Vec<uint8_t> export_evaluation_keys(const Client& c);
rust::Vec<uint8_t> export_secret_key(const Client& c);
rust::Vec<uint8_t> encrypt(const Client& c, rust::Slice<const double> values);
rust::Vec<double> decrypt(const Client& c, rust::Slice<const uint8_t> ciphertext);

}  // namespace encompute_openfhe_client
