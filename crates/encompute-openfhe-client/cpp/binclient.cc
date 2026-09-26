// Client-side BinFHE: key generation, encryption, decryption. Never linked
// into the evaluator.
#include <sstream>
#include <stdexcept>

#include "binfhecontext.h"
#include "binfhecontext-ser.h"
#include "client.h"
#include "common.h"
#include "encompute-openfhe-client/src/lib.rs.h"

namespace encompute_openfhe_client {

using encompute_openfhe::openfhe_mutex;

struct BinClientImpl {
  lbcrypto::BinFHEContext cc;
  lbcrypto::LWEPrivateKey sk;
  bool keys = false;
};

BinClient::BinClient(std::unique_ptr<BinClientImpl> i) : impl(std::move(i)) {}
BinClient::~BinClient() {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  impl.reset();
}

static lbcrypto::BINFHE_PARAMSET paramset_of(const std::string& name) {
  if (name == "STD128") return lbcrypto::STD128;
  if (name == "STD128Q") return lbcrypto::STD128Q;
  if (name == "STD128_LMKCDEY") return lbcrypto::STD128_LMKCDEY;
  throw std::runtime_error("unsupported BinFHE parameter set " + name);
}


static lbcrypto::BINFHE_METHOD method_of(const std::string& name) {
  return name.find("LMKCDEY") != std::string::npos ? lbcrypto::LMKCDEY : lbcrypto::GINX;
}

template <typename T>
static rust::Vec<uint8_t> ser(const T& obj) {
  std::ostringstream out;
  lbcrypto::Serial::Serialize(obj, out, lbcrypto::SerType::BINARY);
  auto s = out.str();
  rust::Vec<uint8_t> v;
  v.reserve(s.size());
  for (char c : s) v.push_back(static_cast<uint8_t>(c));
  return v;
}

std::unique_ptr<BinClient> bin_generate(rust::Str paramset) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto i = std::make_unique<BinClientImpl>();
  i->cc.GenerateBinFHEContext(paramset_of(std::string(paramset)), method_of(std::string(paramset)));
  i->sk = i->cc.KeyGen();
  i->cc.BTKeyGen(i->sk);
  i->keys = true;
  return std::make_unique<BinClient>(std::move(i));
}

std::unique_ptr<BinClient> bin_restore(rust::Str paramset, rust::Slice<const uint8_t> secret) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  auto i = std::make_unique<BinClientImpl>();
  i->cc.GenerateBinFHEContext(paramset_of(std::string(paramset)), method_of(std::string(paramset)));
  try {
    std::string s(reinterpret_cast<const char*>(secret.data()), secret.size());
    std::istringstream in(s);
    lbcrypto::Serial::Deserialize(i->sk, in, lbcrypto::SerType::BINARY);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("malformed BinFHE secret key: ") + e.what());
  }
  if (!i->sk) throw std::runtime_error("malformed BinFHE secret key");
  auto p = i->cc.GetParams()->GetLWEParams();
  if (i->sk->GetLength() != p->Getn()) {
    throw std::runtime_error("secret key is for another parameter set");
  }
  return std::make_unique<BinClient>(std::move(i));
}

rust::Vec<uint8_t> bin_export_secret(const BinClient& c) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return ser(c.impl->sk);
}

rust::Vec<uint8_t> bin_export_refresh_key(const BinClient& c) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  if (!c.impl->keys) throw std::runtime_error("no bootstrapping keys (a restored client)");
  return ser(c.impl->cc.GetRefreshKey());
}

rust::Vec<uint8_t> bin_export_switching_key(const BinClient& c) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  if (!c.impl->keys) throw std::runtime_error("no bootstrapping keys (a restored client)");
  return ser(c.impl->cc.GetSwitchKey());
}

rust::Vec<uint8_t> bin_encrypt(const BinClient& c, bool bit) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  return ser(c.impl->cc.Encrypt(c.impl->sk, bit ? 1 : 0));
}

bool bin_decrypt(const BinClient& c, rust::Slice<const uint8_t> ciphertext) {
  std::lock_guard<std::mutex> g(openfhe_mutex());
  lbcrypto::LWECiphertext ct;
  try {
    std::string s(reinterpret_cast<const char*>(ciphertext.data()), ciphertext.size());
    std::istringstream in(s);
    lbcrypto::Serial::Deserialize(ct, in, lbcrypto::SerType::BINARY);
  } catch (const std::exception& e) {
    throw std::runtime_error(std::string("malformed BinFHE ciphertext: ") + e.what());
  }
  if (!ct) throw std::runtime_error("malformed BinFHE ciphertext");
  auto p = c.impl->cc.GetParams()->GetLWEParams();
  if (ct->GetLength() != p->Getn() || ct->GetModulus() != p->Getq()) {
    throw std::runtime_error("ciphertext is for another parameter set");
  }
  lbcrypto::LWEPlaintext m = 0;
  c.impl->cc.Decrypt(c.impl->sk, ct, &m);
  return m != 0;
}

}  // namespace encompute_openfhe_client
