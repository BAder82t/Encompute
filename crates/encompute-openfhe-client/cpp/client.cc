#include "client.h"

#include <sstream>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "common.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

namespace encompute_openfhe_client {

using encompute_openfhe::openfhe_mutex;
using lbcrypto::DCRTPoly;
using Guard = std::lock_guard<std::mutex>;
using CC = lbcrypto::CryptoContextImpl<DCRTPoly>;

struct ClientImpl {
  lbcrypto::CryptoContext<DCRTPoly> cc;
  lbcrypto::PublicKey<DCRTPoly> pk;
  lbcrypto::PrivateKey<DCRTPoly> sk;
  std::string tag;
  bool owns_eval_keys = false;
  bool has_rotations = false;
  uint32_t slots = 0;
};

Client::Client(std::unique_ptr<ClientImpl> impl) : impl(std::move(impl)) {}
Client::~Client() {
  Guard lock(openfhe_mutex());
  if (impl && impl->owns_eval_keys) encompute_openfhe::release_key_tag(impl->tag);
  impl.reset();
}

namespace {
rust::Vec<uint8_t> bytes_of(const std::string& s) {
  rust::Vec<uint8_t> out;
  out.reserve(s.size());
  for (char c : s) out.push_back(static_cast<uint8_t>(c));
  return out;
}

std::string str_of(rust::Slice<const uint8_t> b) {
  return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

template <typename T>
std::string serialize(const T& obj) {
  std::ostringstream s;
  lbcrypto::Serial::Serialize(obj, s, lbcrypto::SerType::BINARY);
  return s.str();
}

void put_len(std::string& out, uint64_t v, int width) {
  for (int i = 0; i < width; ++i) out.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
}
}  // namespace

std::unique_ptr<Client> generate(uint32_t ring_dim, uint32_t mult_depth,
                                 uint32_t scale_bits, uint32_t first_mod_bits,
                                 uint32_t num_large_digits, uint32_t slots,
                                 rust::Slice<const int32_t> rotations) {
  Guard lock(openfhe_mutex());
  auto impl = std::make_unique<ClientImpl>();
  impl->cc = encompute_openfhe::make_context(ring_dim, mult_depth, scale_bits,
                                             first_mod_bits, num_large_digits, slots);
  auto kp = impl->cc->KeyGen();
  impl->cc->EvalMultKeyGen(kp.secretKey);
  std::vector<int32_t> rot(rotations.begin(), rotations.end());
  if (!rot.empty()) impl->cc->EvalRotateKeyGen(kp.secretKey, rot);
  impl->has_rotations = !rot.empty();
  impl->pk = kp.publicKey;
  impl->sk = kp.secretKey;
  impl->tag = kp.secretKey->GetKeyTag();
  impl->slots = slots;
  impl->owns_eval_keys = true;
  encompute_openfhe::retain_key_tag(impl->tag);
  return std::make_unique<Client>(std::move(impl));
}

std::unique_ptr<Client> restore(uint32_t ring_dim, uint32_t mult_depth,
                                uint32_t scale_bits, uint32_t first_mod_bits,
                                uint32_t num_large_digits, uint32_t slots,
                                rust::Slice<const uint8_t> secret) {
  Guard lock(openfhe_mutex());
  auto impl = std::make_unique<ClientImpl>();
  impl->cc = encompute_openfhe::make_context(ring_dim, mult_depth, scale_bits,
                                             first_mod_bits, num_large_digits, slots);
  // Framing: u64 length + secret key, u64 length + public key.
  std::string all = str_of(secret);
  auto read = [&](size_t& at) {
    if (at + 8 > all.size()) throw std::runtime_error("secret key file is truncated");
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i) n |= static_cast<uint64_t>(static_cast<uint8_t>(all[at + i])) << (8 * i);
    at += 8;
    if (n > all.size() - at) throw std::runtime_error("secret key file is truncated");
    std::string s = all.substr(at, n);
    at += n;
    return s;
  };
  size_t at = 0;
  std::istringstream sks(read(at)), pks(read(at));
  if (at != all.size()) throw std::runtime_error("trailing bytes after the key pair");
  lbcrypto::Serial::Deserialize(impl->sk, sks, lbcrypto::SerType::BINARY);
  lbcrypto::Serial::Deserialize(impl->pk, pks, lbcrypto::SerType::BINARY);
  if (!impl->sk || !impl->pk) throw std::runtime_error("key pair could not be deserialized");
  if (impl->sk->GetCryptoContext() != impl->cc || impl->pk->GetCryptoContext() != impl->cc)
    throw std::runtime_error("key pair belongs to another parameter set");
  impl->tag = impl->sk->GetKeyTag();
  impl->slots = slots;
  return std::make_unique<Client>(std::move(impl));
}

rust::Vec<uint8_t> export_evaluation_keys(const Client& c) {
  Guard lock(openfhe_mutex());
  if (!c.impl->owns_eval_keys)
    throw std::runtime_error("a restored client has no evaluation keys; use the exported eval.keys");
  std::ostringstream mult, rot;
  CC::SerializeEvalMultKey(mult, lbcrypto::SerType::BINARY, c.impl->tag);
  if (c.impl->has_rotations)
    CC::SerializeEvalAutomorphismKey(rot, lbcrypto::SerType::BINARY, c.impl->tag);
  // Framing read by the evaluator shim: u32 tag length, tag, u64 length +
  // relinearization keys, u64 length + rotation keys.
  std::string out;
  put_len(out, c.impl->tag.size(), 4);
  out += c.impl->tag;
  std::string m = mult.str(), r = rot.str();
  put_len(out, m.size(), 8);
  out += m;
  put_len(out, r.size(), 8);
  out += r;
  return bytes_of(out);
}

rust::Vec<uint8_t> export_secret_key(const Client& c) {
  Guard lock(openfhe_mutex());
  std::string sk = serialize(c.impl->sk), pk = serialize(c.impl->pk);
  std::string out;
  put_len(out, sk.size(), 8);
  out += sk;
  put_len(out, pk.size(), 8);
  out += pk;
  return bytes_of(out);
}

rust::Vec<uint8_t> encrypt(const Client& c, rust::Slice<const double> values) {
  Guard lock(openfhe_mutex());
  std::vector<double> v(values.begin(), values.end());
  auto pt = c.impl->cc->MakeCKKSPackedPlaintext(v, 1, 0, nullptr, c.impl->slots);
  return bytes_of(serialize(c.impl->cc->Encrypt(c.impl->pk, pt)));
}

rust::Vec<double> decrypt(const Client& c, rust::Slice<const uint8_t> ciphertext) {
  Guard lock(openfhe_mutex());
  std::istringstream s(str_of(ciphertext));
  lbcrypto::Ciphertext<DCRTPoly> ct;
  lbcrypto::Serial::Deserialize(ct, s, lbcrypto::SerType::BINARY);
  if (!ct) throw std::runtime_error("ciphertext could not be deserialized");
  if (ct->GetCryptoContext() != c.impl->cc)
    throw std::runtime_error("ciphertext belongs to another parameter set");
  if (ct->GetKeyTag() != c.impl->tag)
    throw std::runtime_error("ciphertext was encrypted under another key");
  lbcrypto::Plaintext pt;
  c.impl->cc->Decrypt(c.impl->sk, ct, &pt);
  pt->SetLength(c.impl->slots);
  rust::Vec<double> out;
  for (double x : pt->GetRealPackedValue()) out.push_back(x);
  return out;
}

}  // namespace encompute_openfhe_client
