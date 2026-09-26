#include "binfhe.h"

#include <sstream>
#include <stdexcept>

#include "binfhecontext.h"
#include "binfhecontext-ser.h"
#include "common.h"
#include "encompute-openfhe/src/binfhe.rs.h"

namespace encompute_openfhe {

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

void bin_load_keys(BinContext& ctx, rust::Slice<const uint8_t> refresh,
                   rust::Slice<const uint8_t> switching) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto bs = deserialize<lbcrypto::RingGSWACCKey>(refresh, "BinFHE refresh key");
  auto ks = deserialize<lbcrypto::LWESwitchingKey>(switching, "BinFHE switching key");
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
  return wrap(ctx.impl->cc.EvalBinGate(gates[gate], a.impl->ct, b.impl->ct));
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
