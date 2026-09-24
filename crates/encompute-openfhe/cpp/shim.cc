#include "shim.h"

#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "common.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace encompute_openfhe {

using lbcrypto::DCRTPoly;
using Guard = std::lock_guard<std::mutex>;

std::mutex& openfhe_mutex() {
  static std::mutex m;
  return m;
}

lbcrypto::CryptoContext<DCRTPoly> make_context(uint32_t ring_dim,
                                               uint32_t mult_depth,
                                               uint32_t scale_bits,
                                               uint32_t first_mod_bits,
                                               uint32_t num_large_digits,
                                               uint32_t slots) {
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
  auto cc = lbcrypto::GenCryptoContext(params);
  cc->Enable(lbcrypto::PKE);
  cc->Enable(lbcrypto::KEYSWITCH);
  cc->Enable(lbcrypto::LEVELEDSHE);
  return cc;
}

namespace {
std::map<std::string, int>& tag_counts() {
  static std::map<std::string, int> m;
  return m;
}
}  // namespace

void retain_key_tag(const std::string& tag) { ++tag_counts()[tag]; }

void release_key_tag(const std::string& tag) {
  auto it = tag_counts().find(tag);
  if (it == tag_counts().end()) return;
  if (--it->second == 0) {
    tag_counts().erase(it);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(tag);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(tag);
  }
}

struct ContextImpl {
  lbcrypto::CryptoContext<DCRTPoly> cc;
  std::vector<std::string> key_tags;
  uint32_t slots = 0;
};

struct CiphertextImpl {
  lbcrypto::Ciphertext<DCRTPoly> ct;
};

// Wrapper destructors release OpenFHE objects inside the lock. Wrappers are
// never destroyed while the lock is held: shim functions only create them.
Context::Context(std::unique_ptr<ContextImpl> impl) : impl(std::move(impl)) {}
Context::~Context() {
  Guard lock(openfhe_mutex());
  if (impl) {
    for (const auto& tag : impl->key_tags) release_key_tag(tag);
  }
  impl.reset();
}

Ciphertext::Ciphertext(std::unique_ptr<CiphertextImpl> impl)
    : impl(std::move(impl)) {}
Ciphertext::~Ciphertext() {
  Guard lock(openfhe_mutex());
  impl.reset();
}

namespace {
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

// Framing written by the client shim: u32 tag length, tag, u64 length + the
// relinearization keys, u64 length + the rotation keys (OpenFHE binary).
struct Reader {
  const uint8_t* p;
  size_t n;
  std::string take(size_t k) {
    if (k > n) throw std::runtime_error("evaluation keys are truncated");
    std::string s(reinterpret_cast<const char*>(p), k);
    p += k;
    n -= k;
    return s;
  }
  uint64_t u64(size_t width) {
    std::string b = take(width);
    uint64_t v = 0;
    for (size_t i = 0; i < width; ++i)
      v |= static_cast<uint64_t>(static_cast<uint8_t>(b[i])) << (8 * i);
    return v;
  }
};
}  // namespace

std::unique_ptr<Context> new_context(uint32_t ring_dim, uint32_t mult_depth,
                                     uint32_t scale_bits,
                                     uint32_t first_mod_bits,
                                     uint32_t num_large_digits,
                                     uint32_t slots) {
  Guard lock(openfhe_mutex());
  auto impl = std::make_unique<ContextImpl>();
  impl->cc = make_context(ring_dim, mult_depth, scale_bits, first_mod_bits,
                          num_large_digits, slots);
  impl->slots = slots;
  return std::make_unique<Context>(std::move(impl));
}

uint32_t ring_dimension(const Context& ctx) {
  Guard lock(openfhe_mutex());
  return ctx.impl->cc->GetRingDimension();
}

uint32_t log_qp(const Context& ctx) {
  Guard lock(openfhe_mutex());
  auto params = std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(
      ctx.impl->cc->GetCryptoParameters());
  return params->GetParamsQP()->GetModulus().GetMSB();
}

rust::String load_evaluation_keys(Context& ctx,
                                  rust::Slice<const uint8_t> bytes) {
  Guard lock(openfhe_mutex());
  Reader r{bytes.data(), bytes.size()};
  std::string tag = r.take(r.u64(4));
  std::istringstream mult(r.take(r.u64(8)));
  std::istringstream rot(r.take(r.u64(8)));
  if (r.n != 0) throw std::runtime_error("trailing bytes after evaluation keys");
  using CC = lbcrypto::CryptoContextImpl<DCRTPoly>;
  // In a single process the client's keygen already put these keys in
  // OpenFHE's global maps (OpenFHE refuses to insert a tag twice), so only
  // deserialize keys this process does not have yet.
  const auto& loaded = CC::GetAllEvalMultKeys();
  if (loaded.find(tag) == loaded.end()) {
    if (!CC::DeserializeEvalMultKey(mult, lbcrypto::SerType::BINARY))
      throw std::runtime_error("evaluation keys could not be deserialized");
    // An empty rotation section means the program uses no rotations.
    if (rot.rdbuf()->in_avail() > 0 &&
        !CC::DeserializeEvalAutomorphismKey(rot, lbcrypto::SerType::BINARY))
      throw std::runtime_error("rotation keys could not be deserialized");
  }
  // The keys must belong to this context (same parameters).
  const auto& mk = CC::GetEvalMultKeyVector(tag);
  if (mk.empty() || mk[0]->GetCryptoContext() != ctx.impl->cc)
    throw std::runtime_error("evaluation keys belong to another parameter set");
  retain_key_tag(tag);
  ctx.impl->key_tags.push_back(tag);
  return rust::String(tag);
}

std::unique_ptr<Ciphertext> load_ciphertext(const Context& ctx,
                                            rust::Slice<const uint8_t> bytes) {
  Guard lock(openfhe_mutex());
  std::istringstream s(std::string(reinterpret_cast<const char*>(bytes.data()),
                                   bytes.size()));
  lbcrypto::Ciphertext<DCRTPoly> ct;
  lbcrypto::Serial::Deserialize(ct, s, lbcrypto::SerType::BINARY);
  if (!ct) throw std::runtime_error("ciphertext could not be deserialized");
  if (ct->GetCryptoContext() != ctx.impl->cc)
    throw std::runtime_error("ciphertext belongs to another parameter set");
  const auto& tags = ctx.impl->key_tags;
  if (std::find(tags.begin(), tags.end(), ct->GetKeyTag()) == tags.end())
    throw std::runtime_error("ciphertext is under a key whose evaluation keys are not loaded");
  return wrap(ct);
}

rust::Vec<uint8_t> store_ciphertext(const Ciphertext& ct) {
  Guard lock(openfhe_mutex());
  std::ostringstream s;
  lbcrypto::Serial::Serialize(ct.impl->ct, s, lbcrypto::SerType::BINARY);
  std::string str = s.str();
  rust::Vec<uint8_t> out;
  out.reserve(str.size());
  for (char c : str) out.push_back(static_cast<uint8_t>(c));
  return out;
}

std::unique_ptr<Ciphertext> add(const Context& ctx, const Ciphertext& a, const Ciphertext& b) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> sub(const Context& ctx, const Ciphertext& a, const Ciphertext& b) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalSub(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> neg(const Context& ctx, const Ciphertext& a) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalNegate(a.impl->ct));
}

std::unique_ptr<Ciphertext> mul(const Context& ctx, const Ciphertext& a, const Ciphertext& b) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalMult(a.impl->ct, b.impl->ct));
}

std::unique_ptr<Ciphertext> add_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p) {
  Guard lock(openfhe_mutex());
  auto& c = *ctx.impl;
  auto pt = encode_like(c, a.impl->ct, p, a.impl->ct->GetNoiseScaleDeg());
  return wrap(c.cc->EvalAdd(a.impl->ct, pt));
}

std::unique_ptr<Ciphertext> mul_plain(const Context& ctx, const Ciphertext& a,
                                      rust::Slice<const double> p) {
  Guard lock(openfhe_mutex());
  auto& c = *ctx.impl;
  auto ct = a.impl->ct;
  // FLEXIBLEAUTO rescales lazily; rescale first so the plaintext is encoded
  // at the level the product is computed at.
  if (ct->GetNoiseScaleDeg() == 2) ct = c.cc->Rescale(ct);
  auto pt = encode_like(c, ct, p, 1);
  return wrap(c.cc->EvalMult(ct, pt));
}

std::unique_ptr<Ciphertext> add_const(const Context& ctx, const Ciphertext& a, double k) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, k));
}

std::unique_ptr<Ciphertext> mul_const(const Context& ctx, const Ciphertext& a, double k) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalMult(a.impl->ct, k));
}

std::unique_ptr<Ciphertext> rotate(const Context& ctx, const Ciphertext& a, int32_t k) {
  Guard lock(openfhe_mutex());
  return wrap(ctx.impl->cc->EvalRotate(a.impl->ct, k));
}

uint32_t level(const Ciphertext& ct) {
  Guard lock(openfhe_mutex());
  return ct.impl->ct->GetLevel();
}

}  // namespace encompute_openfhe
