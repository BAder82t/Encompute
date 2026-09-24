#include "shim.h"

#include <mutex>
#include <shared_mutex>
#include <vector>

#include "openfhe.h"

namespace veil_openfhe {

using lbcrypto::DCRTPoly;

struct CkksContextImpl {
  lbcrypto::CryptoContext<DCRTPoly> cc;
  lbcrypto::KeyPair<DCRTPoly> keys;
};

struct CiphertextImpl {
  lbcrypto::Ciphertext<DCRTPoly> ct;
};

CkksContext::CkksContext(std::unique_ptr<CkksContextImpl> impl)
    : impl(std::move(impl)) {}
CkksContext::~CkksContext() = default;

Ciphertext::Ciphertext(std::unique_ptr<CiphertextImpl> impl)
    : impl(std::move(impl)) {}
Ciphertext::~Ciphertext() = default;

namespace {
// OpenFHE parameter generation and context setup mutate process-global state
// (parameter maps, NTT/CRT precomputation tables) without locking, and
// concurrent GenCryptoContext calls corrupt the heap. Context creation takes
// this lock exclusively; every other call takes it shared, so it never reads
// those tables while another thread is writing them.
std::shared_mutex g_openfhe_globals;

std::unique_ptr<Ciphertext> wrap(lbcrypto::Ciphertext<DCRTPoly> ct) {
  auto impl = std::make_unique<CiphertextImpl>();
  impl->ct = std::move(ct);
  return std::make_unique<Ciphertext>(std::move(impl));
}
}  // namespace

std::unique_ptr<CkksContext> new_ckks_context(uint32_t mult_depth,
                                              uint32_t scale_mod_size,
                                              uint32_t batch_size) {
  std::unique_lock lock(g_openfhe_globals);
  lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
  params.SetMultiplicativeDepth(mult_depth);
  params.SetScalingModSize(scale_mod_size);
  params.SetBatchSize(batch_size);
  params.SetSecurityLevel(lbcrypto::HEStd_128_classic);

  auto impl = std::make_unique<CkksContextImpl>();
  impl->cc = lbcrypto::GenCryptoContext(params);
  impl->cc->Enable(lbcrypto::PKE);
  impl->cc->Enable(lbcrypto::KEYSWITCH);
  impl->cc->Enable(lbcrypto::LEVELEDSHE);
  impl->keys = impl->cc->KeyGen();
  impl->cc->EvalMultKeyGen(impl->keys.secretKey);
  return std::make_unique<CkksContext>(std::move(impl));
}

uint32_t ring_dimension(const CkksContext& ctx) {
  std::shared_lock lock(g_openfhe_globals);
  return ctx.impl->cc->GetRingDimension();
}

std::unique_ptr<Ciphertext> encrypt(const CkksContext& ctx,
                                    rust::Slice<const double> values) {
  std::shared_lock lock(g_openfhe_globals);
  std::vector<double> v(values.begin(), values.end());
  auto& c = *ctx.impl;
  auto pt = c.cc->MakeCKKSPackedPlaintext(v);
  return wrap(c.cc->Encrypt(c.keys.publicKey, pt));
}

std::unique_ptr<Ciphertext> add(const CkksContext& ctx, const Ciphertext& a,
                                const Ciphertext& b) {
  std::shared_lock lock(g_openfhe_globals);
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, b.impl->ct));
}

rust::Vec<double> decrypt(const CkksContext& ctx, const Ciphertext& ct,
                          size_t len) {
  std::shared_lock lock(g_openfhe_globals);
  lbcrypto::Plaintext pt;
  ctx.impl->cc->Decrypt(ctx.impl->keys.secretKey, ct.impl->ct, &pt);
  pt->SetLength(len);
  rust::Vec<double> out;
  for (double x : pt->GetRealPackedValue()) out.push_back(x);
  return out;
}

}  // namespace veil_openfhe
