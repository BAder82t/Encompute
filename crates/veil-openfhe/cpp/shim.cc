#include "shim.h"

#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace veil_openfhe {

using lbcrypto::DCRTPoly;

struct ContextImpl {
  lbcrypto::CryptoContext<DCRTPoly> cc;
  lbcrypto::PublicKey<DCRTPoly> pk;
  std::string key_tag;
  uint32_t slots = 0;
};

struct SecretKeyImpl {
  lbcrypto::PrivateKey<DCRTPoly> sk;
};

struct CiphertextImpl {
  lbcrypto::Ciphertext<DCRTPoly> ct;
};

namespace {
// OpenFHE v1.5.1 is not safe to call from several threads at once, even on
// separate contexts: concurrent GenCryptoContext corrupts the heap, and
// concurrent evaluation (encrypt, arithmetic, rotation, decrypt) corrupts
// results. Neither a reader/writer split nor locking only the encoding or
// only the evaluation paths was enough (ADR-001), so every call holds this
// lock. OpenFHE still parallelizes inside each call with OpenMP.
std::mutex g_openfhe;

std::unique_ptr<Ciphertext> wrap(lbcrypto::Ciphertext<DCRTPoly> ct) {
  auto impl = std::make_unique<CiphertextImpl>();
  impl->ct = std::move(ct);
  return std::make_unique<Ciphertext>(std::move(impl));
}

std::vector<double> to_vec(rust::Slice<const double> s) {
  return std::vector<double>(s.begin(), s.end());
}

// Plaintext at the ciphertext's level so the scaling factors line up.
lbcrypto::Plaintext encode_like(const ContextImpl& c,
                                const lbcrypto::Ciphertext<DCRTPoly>& ct,
                                rust::Slice<const double> p,
                                uint32_t noise_scale_deg) {
  return c.cc->MakeCKKSPackedPlaintext(to_vec(p), noise_scale_deg,
                                       ct->GetLevel(), nullptr, c.slots);
}
}  // namespace

Context::Context(std::unique_ptr<ContextImpl> impl) : impl(std::move(impl)) {}
Context::~Context() {
  if (impl && !impl->key_tag.empty()) {
    std::lock_guard lock(g_openfhe);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(impl->key_tag);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(
        impl->key_tag);
  }
}

SecretKey::SecretKey(std::unique_ptr<SecretKeyImpl> impl)
    : impl(std::move(impl)) {}
SecretKey::~SecretKey() = default;

Ciphertext::Ciphertext(std::unique_ptr<CiphertextImpl> impl)
    : impl(std::move(impl)) {}
Ciphertext::~Ciphertext() = default;

std::unique_ptr<Context> new_context(uint32_t ring_dim, uint32_t mult_depth,
                                     uint32_t scale_bits,
                                     uint32_t first_mod_bits,
                                     uint32_t num_large_digits,
                                     uint32_t slots) {
  std::lock_guard lock(g_openfhe);
  lbcrypto::CCParams<lbcrypto::CryptoContextCKKSRNS> params;
  params.SetSecurityLevel(lbcrypto::HEStd_128_classic);
  params.SetSecretKeyDist(lbcrypto::UNIFORM_TERNARY);
  params.SetScalingTechnique(lbcrypto::FLEXIBLEAUTO);
  params.SetKeySwitchTechnique(lbcrypto::HYBRID);
  params.SetRingDim(ring_dim);
  params.SetMultiplicativeDepth(mult_depth);
  params.SetScalingModSize(scale_bits);
  params.SetFirstModSize(first_mod_bits);
  params.SetNumLargeDigits(num_large_digits);
  params.SetBatchSize(slots);

  auto impl = std::make_unique<ContextImpl>();
  impl->cc = lbcrypto::GenCryptoContext(params);
  impl->cc->Enable(lbcrypto::PKE);
  impl->cc->Enable(lbcrypto::KEYSWITCH);
  impl->cc->Enable(lbcrypto::LEVELEDSHE);
  impl->slots = slots;
  return std::make_unique<Context>(std::move(impl));
}

std::unique_ptr<SecretKey> keygen(Context& ctx,
                                  rust::Slice<const int32_t> rotations) {
  std::lock_guard lock(g_openfhe);
  auto& c = *ctx.impl;
  auto kp = c.cc->KeyGen();
  c.cc->EvalMultKeyGen(kp.secretKey);
  std::vector<int32_t> rot(rotations.begin(), rotations.end());
  if (!rot.empty()) c.cc->EvalRotateKeyGen(kp.secretKey, rot);
  c.pk = kp.publicKey;
  c.key_tag = kp.secretKey->GetKeyTag();
  auto impl = std::make_unique<SecretKeyImpl>();
  impl->sk = kp.secretKey;
  return std::make_unique<SecretKey>(std::move(impl));
}

uint32_t ring_dimension(const Context& ctx) {
  std::lock_guard lock(g_openfhe);
  return ctx.impl->cc->GetRingDimension();
}

uint32_t log_qp(const Context& ctx) {
  std::lock_guard lock(g_openfhe);
  auto params = std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(
      ctx.impl->cc->GetCryptoParameters());
  return params->GetParamsQP()->GetModulus().GetMSB();
}

std::unique_ptr<Ciphertext> encrypt(const Context& ctx,
                                    rust::Slice<const double> values) {
  std::lock_guard lock(g_openfhe);
  auto& c = *ctx.impl;
  auto pt = c.cc->MakeCKKSPackedPlaintext(to_vec(values), 1, 0, nullptr,
                                          c.slots);
  return wrap(c.cc->Encrypt(c.pk, pt));
}

rust::Vec<double> decrypt(const Context& ctx, const SecretKey& sk,
                          const Ciphertext& ct) {
  std::lock_guard lock(g_openfhe);
  lbcrypto::Plaintext pt;
  ctx.impl->cc->Decrypt(sk.impl->sk, ct.impl->ct, &pt);
  pt->SetLength(ctx.impl->slots);
  rust::Vec<double> out;
  for (double x : pt->GetRealPackedValue()) out.push_back(x);
  return out;
}

std::unique_ptr<Ciphertext> add(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> sub(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalSub(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> neg(const Context& ctx, const Ciphertext& a) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalNegate(a.impl->ct));
}

std::unique_ptr<Ciphertext> mul(const Context& ctx, const Ciphertext& a,
                                const Ciphertext& b) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalMult(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> add_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p) {
  std::lock_guard lock(g_openfhe);
  auto& c = *ctx.impl;
  auto pt = encode_like(c, a.impl->ct, p, a.impl->ct->GetNoiseScaleDeg());
  return wrap(c.cc->EvalAdd(a.impl->ct, pt));
}

std::unique_ptr<Ciphertext> mul_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p) {
  std::lock_guard lock(g_openfhe);
  auto& c = *ctx.impl;
  auto ct = a.impl->ct;
  // FLEXIBLEAUTO rescales lazily; rescale first so the plaintext is
  // encoded at the level the product is computed at.
  if (ct->GetNoiseScaleDeg() == 2) ct = c.cc->Rescale(ct);
  auto pt = encode_like(c, ct, p, 1);
  return wrap(c.cc->EvalMult(ct, pt));
}

std::unique_ptr<Ciphertext> add_const(const Context& ctx, const Ciphertext& a,
                                      double k) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, k));
}

std::unique_ptr<Ciphertext> mul_const(const Context& ctx, const Ciphertext& a,
                                      double k) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalMult(a.impl->ct, k));
}

std::unique_ptr<Ciphertext> rotate(const Context& ctx, const Ciphertext& a,
                                   int32_t k) {
  std::lock_guard lock(g_openfhe);
  return wrap(ctx.impl->cc->EvalRotate(a.impl->ct, k));
}

size_t serialized_size(const Ciphertext& ct) {
  std::lock_guard lock(g_openfhe);
  std::stringstream s;
  lbcrypto::Serial::Serialize(ct.impl->ct, s, lbcrypto::SerType::BINARY);
  return s.str().size();
}

uint32_t level(const Ciphertext& ct) {
  std::lock_guard lock(g_openfhe);
  return ct.impl->ct->GetLevel();
}

}  // namespace veil_openfhe
