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

lbcrypto::CryptoContext<DCRTPoly> make_bgv_context(uint32_t mult_depth) {
  lbcrypto::CCParams<lbcrypto::CryptoContextBGVRNS> params;
  params.SetPlaintextModulus(kBgvPlaintextModulus);
  params.SetMultiplicativeDepth(mult_depth);
  params.SetSecurityLevel(lbcrypto::HEStd_128_classic);
  params.SetKeySwitchTechnique(lbcrypto::HYBRID);
  params.SetScalingTechnique(lbcrypto::FIXEDAUTO);
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

// A loaded evaluation-key set lives in OpenFHE's process-wide maps under its
// own tag: the client's key tag and the SHA-256 of the uploaded bytes. This
// is the loaded copy's tag, never the client's. The maps find keys by the
// ciphertext's tag alone and keep the first keys inserted under a tag, so
// under the client's tag, whoever uploads first would own it (the key-tag
// squat). Under a tag that names the bytes, two uploads never meet.
// `external_tags` maps a loaded copy's tag back to the client's tag.
std::map<std::string, std::string>& external_tags() {
  static std::map<std::string, std::string> m;
  return m;
}

std::string loaded_tag(const std::string& tag, const std::string& sha) {
  return tag + "#" + sha;
}
}  // namespace

void retain_key_tag(const std::string& tag) { ++tag_counts()[tag]; }

void release_key_tag(const std::string& tag) {
  auto it = tag_counts().find(tag);
  if (it == tag_counts().end()) return;
  if (--it->second == 0) {
    tag_counts().erase(it);
    external_tags().erase(tag);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys(tag);
    lbcrypto::CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys(tag);
  }
}

struct ContextImpl {
  lbcrypto::CryptoContext<DCRTPoly> cc;
  // The loaded copies' tags (released with the context), and the client's
  // key tag each ciphertext's tag is mapped to.
  std::vector<std::string> key_tags;
  std::map<std::string, std::string> loaded_by_client_tag;
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

std::unique_ptr<Context> new_bgv_context(uint32_t mult_depth) {
  Guard lock(openfhe_mutex());
  auto impl = std::make_unique<ContextImpl>();
  impl->cc = make_bgv_context(mult_depth);
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

namespace {
using CC = lbcrypto::CryptoContextImpl<DCRTPoly>;
using EvalKeyVector = std::vector<lbcrypto::EvalKey<DCRTPoly>>;
using AutomorphismKeys = std::map<uint32_t, lbcrypto::EvalKey<DCRTPoly>>;

const char* const kForeignKeys = "evaluation keys belong to another parameter set";

// A polynomial over exactly `params` (every tower's modulus and length), in
// evaluation form: what key switching indexes without further checks.
bool poly_matches(const DCRTPoly& p, const std::shared_ptr<DCRTPoly::Params>& params) {
  if (!p.GetParams() || *p.GetParams() != *params) return false;
  if (p.GetFormat() != Format::EVALUATION) return false;
  const auto& towers = p.GetAllElements();
  const auto& want = params->GetParams();
  if (towers.size() != want.size()) return false;
  for (size_t i = 0; i < towers.size(); ++i) {
    const auto& v = towers[i].GetValues();  // throws if absent
    if (v.GetLength() != params->GetRingDimension() || v.GetModulus() != want[i]->GetModulus())
      return false;
  }
  return true;
}

// A hybrid key-switching key for `cc` under `tag`: one (a, b) pair per
// digit of Q, each over Q·P.
void check_key(const lbcrypto::EvalKey<DCRTPoly>& k, const lbcrypto::CryptoContext<DCRTPoly>& cc,
               const std::string& tag) {
  if (!k || k->GetCryptoContext() != cc) throw std::runtime_error(kForeignKeys);
  if (k->GetKeyTag() != tag)
    throw std::runtime_error("evaluation keys carry another key tag than the one they are sent under");
  auto params = std::dynamic_pointer_cast<lbcrypto::CryptoParametersRNS>(cc->GetCryptoParameters());
  if (!params) throw std::runtime_error(kForeignKeys);
  const auto& qp = params->GetParamsQP();
  const size_t digits = params->GetNumPartQ();
  const auto& a = k->GetAVector();
  const auto& b = k->GetBVector();
  if (a.size() != digits || b.size() != digits) throw std::runtime_error(kForeignKeys);
  for (size_t i = 0; i < digits; ++i)
    if (!poly_matches(a[i], qp) || !poly_matches(b[i], qp)) throw std::runtime_error(kForeignKeys);
}

template <typename T>
T deserialize_keys(std::istringstream& in, const char* what) {
  T keys;
  try {
    lbcrypto::Serial::Deserialize(keys, in, lbcrypto::SerType::BINARY);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string(what) + " could not be deserialized: " + e.what());
  }
  if (in.peek() != std::char_traits<char>::eof())
    throw std::runtime_error(std::string("trailing bytes after the ") + what);
  return keys;
}

}  // namespace

rust::String load_evaluation_keys(Context& ctx, rust::Slice<const uint8_t> bytes,
                                  rust::Str digest) {
  Guard lock(openfhe_mutex());
  Reader r{bytes.data(), bytes.size()};
  std::string tag = r.take(r.u64(4));
  std::string mult_bytes = r.take(r.u64(8));
  std::string rot_bytes = r.take(r.u64(8));
  if (r.n != 0) throw std::runtime_error("trailing bytes after evaluation keys");
  if (tag.empty()) throw std::runtime_error("evaluation keys name no key tag");
  const std::string sha(digest);

  // OpenFHE finds keys by the ciphertext's key tag alone, in process-wide
  // maps where the first keys inserted under a tag stay. So nothing is
  // inserted until the upload is fully checked, and the keys are inserted
  // under a tag of their own (the client's tag and the SHA-256 of the
  // upload): another client's keys relabelled with a victim's tag land
  // beside the victim's, never in front of them, and a ciphertext runs only
  // under the keys of the context that loaded them.
  const std::string itag = loaded_tag(tag, sha);
  const auto& loaded_mult = CC::GetAllEvalMultKeys();
  const auto& loaded_rot = CC::GetAllEvalAutomorphismKeys();
  const bool present = loaded_mult.find(itag) != loaded_mult.end() ||
                       loaded_rot.find(itag) != loaded_rot.end();
  if (present) {
    // The same bytes again: they were checked when first inserted.
    auto mk = loaded_mult.find(itag);
    if (mk == loaded_mult.end() || mk->second.empty() ||
        mk->second[0]->GetCryptoContext() != ctx.impl->cc)
      throw std::runtime_error(kForeignKeys);
    retain_key_tag(itag);
    ctx.impl->key_tags.push_back(itag);
    ctx.impl->loaded_by_client_tag[tag] = itag;
    return rust::String(tag);
  }

  // Deserialize into local maps (DeserializeEvalMultKey would insert into
  // the global maps before any check).
  std::istringstream mult_in(mult_bytes);
  auto mult = deserialize_keys<std::map<std::string, EvalKeyVector>>(mult_in, "evaluation keys");
  if (mult.size() != 1 || mult.begin()->first != tag || mult.begin()->second.empty())
    throw std::runtime_error("evaluation keys must hold exactly the keys of their stated key tag");
  for (const auto& k : mult.begin()->second) check_key(k, ctx.impl->cc, tag);

  std::shared_ptr<AutomorphismKeys> rot;
  // An empty rotation section means the program uses no rotations.
  if (!rot_bytes.empty()) {
    std::istringstream rot_in(rot_bytes);
    auto rots = deserialize_keys<std::map<std::string, std::shared_ptr<AutomorphismKeys>>>(
        rot_in, "rotation keys");
    if (rots.size() != 1 || rots.begin()->first != tag || !rots.begin()->second ||
        rots.begin()->second->empty())
      throw std::runtime_error("rotation keys must hold exactly the keys of their stated key tag");
    for (const auto& [index, k] : *rots.begin()->second) check_key(k, ctx.impl->cc, tag);
    rot = rots.begin()->second;
  }

  // Every key now carries the loaded copy's tag, as the maps are keyed by it.
  for (auto& k : mult.begin()->second) k->SetKeyTag(itag);
  if (rot)
    for (auto& entry : *rot) entry.second->SetKeyTag(itag);
  CC::InsertEvalMultKey(mult.begin()->second, itag);
  if (rot) CC::InsertEvalAutomorphismKey(rot, itag);
  external_tags()[itag] = tag;
  retain_key_tag(itag);
  ctx.impl->key_tags.push_back(itag);
  ctx.impl->loaded_by_client_tag[tag] = itag;
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
  // The client's tag names the keys this context loaded under it; the loaded
  // copy's tag is what OpenFHE looks the keys up by.
  const auto& loaded = ctx.impl->loaded_by_client_tag;
  auto it = loaded.find(ct->GetKeyTag());
  if (it == loaded.end())
    throw std::runtime_error("ciphertext is under a key whose evaluation keys are not loaded");
  ct->SetKeyTag(it->second);
  return wrap(ct);
}

rust::Vec<uint8_t> store_ciphertext(const Ciphertext& ct) {
  Guard lock(openfhe_mutex());
  std::ostringstream s;
  // A ciphertext leaves under the client's key tag (its client checks it),
  // not the loaded copy's. Every shim call holds the lock, so the tag is
  // put back before anyone else sees the ciphertext.
  const std::string loaded = ct.impl->ct->GetKeyTag();
  auto client = external_tags().find(loaded);
  if (client != external_tags().end()) ct.impl->ct->SetKeyTag(client->second);
  try {
    lbcrypto::Serial::Serialize(ct.impl->ct, s, lbcrypto::SerType::BINARY);
  } catch (...) {
    ct.impl->ct->SetKeyTag(loaded);
    throw;
  }
  ct.impl->ct->SetKeyTag(loaded);
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

std::unique_ptr<Ciphertext> clone_ciphertext(const Ciphertext& ct) {
  Guard lock(openfhe_mutex());
  return wrap(ct.impl->ct->Clone());
}

namespace {
// Packed plaintext holding `c` in slot 0 (deterministic encoding).
lbcrypto::Plaintext bgv_scalar(const ContextImpl& c, int64_t k) {
  return c.cc->MakePackedPlaintext(std::vector<int64_t>{k});
}
}  // namespace

std::unique_ptr<Ciphertext> bgv_add_scalar(const Context& ctx, const Ciphertext& a, int64_t c) {
  Guard lock(openfhe_mutex());
  auto pt = bgv_scalar(*ctx.impl, c);
  return wrap(ctx.impl->cc->EvalAdd(a.impl->ct, pt));
}

std::unique_ptr<Ciphertext> bgv_mul_scalar(const Context& ctx, const Ciphertext& a, int64_t c) {
  Guard lock(openfhe_mutex());
  auto pt = bgv_scalar(*ctx.impl, c);
  return wrap(ctx.impl->cc->EvalMult(a.impl->ct, pt));
}

}  // namespace encompute_openfhe
