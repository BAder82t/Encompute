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

// BGV (exact programs): fresh keys and relinearization key; restore.
std::unique_ptr<Client> bgv_generate(uint32_t mult_depth);
std::unique_ptr<Client> bgv_restore(uint32_t mult_depth, rust::Slice<const uint8_t> secret);
// Encrypt an integer in [0, 65537) into slot 0; decrypt slot 0 into [0, 65537).
rust::Vec<uint8_t> bgv_encrypt(const Client& c, int64_t value);
int64_t bgv_decrypt(const Client& c, rust::Slice<const uint8_t> ciphertext);

rust::Vec<uint8_t> export_evaluation_keys(const Client& c);
rust::Vec<uint8_t> export_secret_key(const Client& c);
rust::Vec<uint8_t> encrypt(const Client& c, rust::Slice<const double> values);
rust::Vec<double> decrypt(const Client& c, rust::Slice<const uint8_t> ciphertext);

}  // namespace encompute_openfhe_client

// --- BinFHE (exact programs): the only code that holds the LWE secret key.
namespace encompute_openfhe_client {

struct BinClientImpl;

class BinClient {
 public:
  explicit BinClient(std::unique_ptr<BinClientImpl> impl);
  ~BinClient();
  std::unique_ptr<BinClientImpl> impl;
};

// A fresh secret key and bootstrapping keys for a vetted parameter set.
std::unique_ptr<BinClient> bin_generate(rust::Str paramset);
// Restore from `bin_export_secret` (bootstrapping keys are not regenerated).
std::unique_ptr<BinClient> bin_restore(rust::Str paramset, rust::Slice<const uint8_t> secret);
rust::Vec<uint8_t> bin_export_secret(const BinClient& c);
// The bootstrapping keys the evaluator needs: refresh key, switching key.
rust::Vec<uint8_t> bin_export_refresh_key(const BinClient& c);
rust::Vec<uint8_t> bin_export_switching_key(const BinClient& c);
rust::Vec<uint8_t> bin_encrypt(const BinClient& c, bool bit);
bool bin_decrypt(const BinClient& c, rust::Slice<const uint8_t> ciphertext);

}  // namespace encompute_openfhe_client
