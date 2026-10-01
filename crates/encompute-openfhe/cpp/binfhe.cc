#include "binfhe.h"

#include <cmath>
#include <sstream>
#include <stdexcept>

#include "binfhecontext.h"
#include "binfhecontext-ser.h"
#include "common.h"
#include "encompute-openfhe/src/binfhe.rs.h"

// OpenMP's runtime, when OpenFHE was built with it (weak: absent otherwise).
extern "C" void omp_set_num_threads(int) __attribute__((weak));

namespace encompute_openfhe {

void bin_worker_init() {
  if (omp_set_num_threads) omp_set_num_threads(1);
}


using lbcrypto::BinFHEContext;
using lbcrypto::LWECiphertext;

struct BinContextImpl {
  BinFHEContext cc;
  bool keys = false;
};

struct BinCiphertextImpl {
  LWECiphertext ct;
};

BinContext::BinContext(std::unique_ptr<BinContextImpl> i) : impl(std::move(i)) {}
BinContext::~BinContext() {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  impl.reset();
}
BinCiphertext::BinCiphertext(std::unique_ptr<BinCiphertextImpl> i) : impl(std::move(i)) {}
BinCiphertext::~BinCiphertext() {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  impl.reset();
}

static std::unique_ptr<BinCiphertext> wrap(LWECiphertext ct) {
  auto i = std::make_unique<BinCiphertextImpl>();
  i->ct = std::move(ct);
  return std::make_unique<BinCiphertext>(std::move(i));
}

static lbcrypto::BINFHE_METHOD method_of(const std::string& name) {
  return name.find("LMKCDEY") != std::string::npos ? lbcrypto::LMKCDEY : lbcrypto::GINX;
}

lbcrypto::BINFHE_PARAMSET bin_paramset(const std::string& name) {
  if (name == "STD128") return lbcrypto::STD128;
  if (name == "STD128Q") return lbcrypto::STD128Q;
  if (name == "STD128_LMKCDEY") return lbcrypto::STD128_LMKCDEY;
  throw std::runtime_error("unsupported BinFHE parameter set " + name +
                           " (vetted: STD128, STD128Q)");
}

std::unique_ptr<BinContext> bin_new_context(rust::Str paramset) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto i = std::make_unique<BinContextImpl>();
  i->cc.GenerateBinFHEContext(bin_paramset(std::string(paramset)), method_of(std::string(paramset)));
  return std::make_unique<BinContext>(std::move(i));
}

uint64_t bin_lwe_n(const BinContext& ctx) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return const_cast<BinFHEContext&>(ctx.impl->cc).GetParams()->GetLWEParams()->Getn();
}

uint64_t bin_lwe_q(const BinContext& ctx) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return const_cast<BinFHEContext&>(ctx.impl->cc).GetParams()->GetLWEParams()->Getq().ConvertToInt();
}

template <typename T>
static T deserialize(rust::Slice<const uint8_t> bytes, const char* what) {
  T obj;
  try {
    std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::istringstream in(s);
    lbcrypto::Serial::Deserialize(obj, in, lbcrypto::SerType::BINARY);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("malformed ") + what + ": " + e.what());
  }
  if (!obj) throw std::runtime_error(std::string("malformed ") + what);
  return obj;
}

namespace {
const char* const kForeignKeys = "bootstrapping keys are for another parameter set";

// A ring polynomial over exactly `params` (modulus and length), in
// evaluation form.
bool poly_matches(const lbcrypto::NativePoly& p, const std::shared_ptr<lbcrypto::ILNativeParams>& params) {
  if (!p.GetParams() || *p.GetParams() != *params) return false;
  if (p.GetFormat() != Format::EVALUATION) return false;
  const auto& v = p.GetValues();  // throws if absent
  return v.GetLength() == params->GetRingDimension() && v.GetModulus() == params->GetModulus();
}

// The refresh key is what the accumulator indexes without bounds checks:
// for GINX, [1][2][n] RGSW keys of (digitsG - 1) * 2 rows of 2 polynomials
// over the ring (N, Q). Any other method or shape is refused.
void check_refresh_key(BinFHEContext& cc, const lbcrypto::RingGSWACCKey& bs) {
  const auto& params = cc.GetParams();
  const auto& rgsw = params->GetRingGSWParams();
  const auto& lwe = params->GetLWEParams();
  if (rgsw->GetMethod() != lbcrypto::GINX)
    throw std::runtime_error("only GINX bootstrapping keys are vetted: keys are for another parameter set");
  const size_t n = lwe->Getn();
  const size_t rows = (rgsw->GetDigitsG() - 1) << 1;
  const auto& ring = rgsw->GetPolyParams();
  const auto& k = bs->GetElements();
  if (k.size() != 1 || k[0].size() != 2) throw std::runtime_error(kForeignKeys);
  for (const auto& half : k[0]) {
    if (half.size() != n) throw std::runtime_error(kForeignKeys);
    for (const auto& ek : half) {
      if (!ek) throw std::runtime_error(kForeignKeys);
      const auto& el = ek->GetElements();
      if (el.size() != rows) throw std::runtime_error(kForeignKeys);
      for (const auto& row : el) {
        if (row.size() != 2 || !poly_matches(row[0], ring) || !poly_matches(row[1], ring))
          throw std::runtime_error(kForeignKeys);
      }
    }
  }
}

// The switching key maps an LWE key of dimension N to one of dimension n
// modulo qKS: [N][baseKS][digits] vectors of length n, and as many values.
void check_switching_key(BinFHEContext& cc, const lbcrypto::LWESwitchingKey& ks) {
  const auto& lwe = cc.GetParams()->GetLWEParams();
  const size_t n = lwe->Getn();
  const size_t big_n = lwe->GetN();
  const size_t base = lwe->GetBaseKS();
  const NativeInteger q_ks = lwe->GetqKS();
  if (base < 2) throw std::runtime_error(kForeignKeys);
  const size_t digits = static_cast<size_t>(
      std::ceil(std::log(q_ks.ConvertToDouble()) / std::log(static_cast<double>(base))));
  const auto& a = ks->GetElementsA();
  const auto& b = ks->GetElementsB();
  if (a.size() != big_n || b.size() != big_n) throw std::runtime_error(kForeignKeys);
  for (size_t i = 0; i < big_n; ++i) {
    if (a[i].size() != base || b[i].size() != base) throw std::runtime_error(kForeignKeys);
    for (size_t j = 0; j < base; ++j) {
      if (a[i][j].size() != digits || b[i][j].size() != digits) throw std::runtime_error(kForeignKeys);
      for (size_t d = 0; d < digits; ++d) {
        if (a[i][j][d].GetLength() != n || a[i][j][d].GetModulus() != q_ks || b[i][j][d] >= q_ks)
          throw std::runtime_error(kForeignKeys);
      }
    }
  }
}
}  // namespace

void bin_load_keys(BinContext& ctx, rust::Slice<const uint8_t> refresh,
                   rust::Slice<const uint8_t> switching) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto bs = deserialize<lbcrypto::RingGSWACCKey>(refresh, "BinFHE refresh key");
  auto ks = deserialize<lbcrypto::LWESwitchingKey>(switching, "BinFHE switching key");
  // The keys' structure is the uploader's word: check every dimension and
  // modulus against the vetted context before any gate indexes them.
  check_refresh_key(ctx.impl->cc, bs);
  check_switching_key(ctx.impl->cc, ks);
  lbcrypto::RingGSWBTKey key;
  key.BSkey = bs;
  key.KSkey = ks;
  ctx.impl->cc.BTKeyLoad(key);
  ctx.impl->keys = true;
}

std::unique_ptr<BinCiphertext> bin_load(const BinContext& ctx, rust::Slice<const uint8_t> bytes) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto ct = deserialize<LWECiphertext>(bytes, "BinFHE ciphertext");
  auto p = const_cast<BinFHEContext&>(ctx.impl->cc).GetParams()->GetLWEParams();
  if (ct->GetLength() != p->Getn() || ct->GetModulus() != p->Getq()) {
    throw std::runtime_error("ciphertext is for another parameter set");
  }
  return wrap(std::move(ct));
}

rust::Vec<uint8_t> bin_store(const BinCiphertext& ct) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  std::ostringstream out;
  lbcrypto::Serial::Serialize(ct.impl->ct, out, lbcrypto::SerType::BINARY);
  auto s = out.str();
  rust::Vec<uint8_t> v;
  v.reserve(s.size());
  for (char c : s) v.push_back(static_cast<uint8_t>(c));
  return v;
}

std::unique_ptr<BinCiphertext> bin_gate(const BinContext& ctx, uint8_t gate,
                                        const BinCiphertext& a, const BinCiphertext& b) {
  static const lbcrypto::BINGATE gates[] = {lbcrypto::OR,  lbcrypto::AND, lbcrypto::NOR,
                                            lbcrypto::NAND, lbcrypto::XOR, lbcrypto::XNOR};
  if (gate > 5) throw std::runtime_error("unknown BinFHE gate");
  std::lock_guard<std::mutex> g(openfhe_mutex());
  if (!ctx.impl->keys) throw std::runtime_error("no bootstrapping keys loaded");
  if (a.impl->ct == b.impl->ct) {
    // OpenFHE refuses a gate whose operands are one ciphertext object
    // (x & x, x ^ x ...): the identities give the result without a
    // bootstrap. OR, AND: x; NOR, NAND: NOT x; XOR: 0; XNOR: 1.
    switch (gate) {
      case 0:
      case 1:
        return wrap(std::make_shared<lbcrypto::LWECiphertextImpl>(*a.impl->ct));
      case 2:
      case 3:
        return wrap(ctx.impl->cc.EvalNOT(a.impl->ct));
      case 4:
        return wrap(ctx.impl->cc.EvalConstant(false));
      default:
        return wrap(ctx.impl->cc.EvalConstant(true));
    }
  }
  return wrap(ctx.impl->cc.EvalBinGate(gates[gate], a.impl->ct, b.impl->ct));
}

std::unique_ptr<BinCiphertext> bin_gate_concurrent(const BinContext& ctx, uint8_t gate,
                                                   const BinCiphertext& a, const BinCiphertext& b) {
  static const lbcrypto::BINGATE gates[] = {lbcrypto::OR,  lbcrypto::AND, lbcrypto::NOR,
                                            lbcrypto::NAND, lbcrypto::XOR, lbcrypto::XNOR};
  if (gate > 5) throw std::runtime_error("unknown BinFHE gate");
  if (!ctx.impl->keys) throw std::runtime_error("no bootstrapping keys loaded");
  if (a.impl->ct == b.impl->ct) {
    // One ciphertext object twice: OpenFHE refuses it; the identities
    // answer (these calls lock, as they may touch shared state).
    std::lock_guard<std::mutex> g(openfhe_mutex());
    switch (gate) {
      case 0:
      case 1:
        return wrap(std::make_shared<lbcrypto::LWECiphertextImpl>(*a.impl->ct));
      case 2:
      case 3:
        return wrap(ctx.impl->cc.EvalNOT(a.impl->ct));
      case 4:
        return wrap(ctx.impl->cc.EvalConstant(false));
      default:
        return wrap(ctx.impl->cc.EvalConstant(true));
    }
  }
  auto out = ctx.impl->cc.EvalBinGate(gates[gate], a.impl->ct, b.impl->ct);
  // Wrapping allocates only; the destructor of the wrapper still locks.
  auto i = std::make_unique<BinCiphertextImpl>();
  i->ct = std::move(out);
  return std::make_unique<BinCiphertext>(std::move(i));
}

std::unique_ptr<BinCiphertext> bin_not(const BinContext& ctx, const BinCiphertext& a) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return wrap(ctx.impl->cc.EvalNOT(a.impl->ct));
}

std::unique_ptr<BinCiphertext> bin_constant(const BinContext& ctx, bool value) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return wrap(ctx.impl->cc.EvalConstant(value));
}

std::unique_ptr<BinCiphertext> bin_clone(const BinCiphertext& ct) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return wrap(std::make_shared<lbcrypto::LWECiphertextImpl>(*ct.impl->ct));
}

}  // namespace encompute_openfhe
