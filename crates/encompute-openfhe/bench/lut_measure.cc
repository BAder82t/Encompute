// Measurement only: OpenFHE BinFHE functional bootstrapping (LUTs) against
// the production Boolean gate. Not part of any Encompute build; run it with
// scripts/lut-measure.sh. Results: docs/benchmarks.md, "Functional
// bootstrapping (LUTs)".
//
// Usage: lut_measure [gate|lut4|lut8|lut16|sign]... (default: all)

#include <omp.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <streambuf>
#include <string>
#include <thread>
#include <vector>

#include "binfhecontext-ser.h"
#include "binfhecontext.h"

using namespace lbcrypto;
using Clock = std::chrono::steady_clock;

static constexpr int kRuns = 10;     // single-thread samples (median)
static constexpr int kThreads = 8;   // concurrent workers, one OpenMP thread each
static constexpr int kPerThread = 3; // operations per worker

static double ms(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

static double median(std::vector<double> v) {
  std::sort(v.begin(), v.end());
  size_t n = v.size();
  return n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
}

// Counts serialized bytes without holding them (the keys reach gigabytes).
struct CountBuf : std::streambuf {
  size_t n = 0;
  int_type overflow(int_type c) override {
    ++n;
    return c;
  }
  std::streamsize xsputn(const char*, std::streamsize k) override {
    n += k;
    return k;
  }
};

template <typename T>
static double mib(const T& obj) {
  CountBuf b;
  std::ostream out(&b);
  Serial::Serialize(obj, out, SerType::BINARY);
  return b.n / (1024.0 * 1024.0);
}

static void describe(const char* name, BinFHEContext& cc) {
  auto lwe = cc.GetParams()->GetLWEParams();
  auto rgsw = cc.GetParams()->GetRingGSWParams();
  std::printf("[%s] n=%u N=%u q=%s Q=%s qKS=%s baseKS=%u baseG=%u maxP=%s\n", name,
              lwe->Getn(), lwe->GetN(), lwe->Getq().ToString().c_str(),
              lwe->GetQ().ToString().c_str(), lwe->GetqKS().ToString().c_str(),
              lwe->GetBaseKS(), rgsw->GetBaseG(), cc.GetMaxPlaintextSpace().ToString().c_str());
}

static LWEPrivateKey keygen(const char* name, BinFHEContext& cc) {
  omp_set_num_threads(1);
  auto t0 = Clock::now();
  auto sk = cc.KeyGen();
  cc.BTKeyGen(sk);
  double kg = ms(t0);
  std::printf("[%s] keygen (one thread) %.0f ms; refresh key %.1f MiB, switching key %.1f MiB\n",
              name, kg, mib(cc.GetRefreshKey()), mib(cc.GetSwitchKey()));
  return sk;
}

// `op(i)` runs one operation on input i and returns true if the result is
// correct. Prints the single-thread median and the 8-worker time per op.
template <typename Op>
static void time_op(const char* name, int inputs, Op op) {
  omp_set_num_threads(1);
  std::vector<double> t;
  int wrong = 0;
  for (int r = 0; r < kRuns; ++r) {
    auto t0 = Clock::now();
    wrong += !op(r % inputs);
    t.push_back(ms(t0));
  }
  std::vector<int> bad(kThreads, 0);
  auto t0 = Clock::now();
  std::vector<std::thread> ws;
  for (int w = 0; w < kThreads; ++w) {
    ws.emplace_back([&, w] {
      omp_set_num_threads(1);
      for (int k = 0; k < kPerThread; ++k) bad[w] += !op((w * kPerThread + k) % inputs);
    });
  }
  for (auto& th : ws) th.join();
  double wall = ms(t0);
  for (int b : bad) wrong += b;
  std::printf(
      "[%s] one thread: median %.1f ms (min %.1f, max %.1f, %d runs); %d workers: %.1f ms wall "
      "for %d ops = %.1f ms per op; wrong results %d of %d\n",
      name, median(t), *std::min_element(t.begin(), t.end()),
      *std::max_element(t.begin(), t.end()), kRuns, kThreads, wall, kThreads * kPerThread,
      wall / (kThreads * kPerThread), wrong, kRuns + kThreads * kPerThread);
}

static void gate() {
  BinFHEContext cc;
  cc.GenerateBinFHEContext(STD128, GINX);  // production: BINFHE_STD128_GINX_BITS_V1
  describe("gate STD128 GINX", cc);
  auto sk = keygen("gate STD128 GINX", cc);
  std::vector<LWECiphertext> a, b;
  for (int i = 0; i < 4; ++i) {
    a.push_back(cc.Encrypt(sk, i & 1));
    b.push_back(cc.Encrypt(sk, (i >> 1) & 1));
  }
  time_op("gate AND", 4, [&](int i) {
    auto c = cc.EvalBinGate(AND, a[i], b[i]);
    LWEPlaintext m;
    cc.Decrypt(sk, c, &m);
    return m == ((i & 1) & ((i >> 1) & 1));
  });
}

// The carry of a digit sum: 1 if m >= p/2. Not negacyclic and not periodic,
// so OpenFHE evaluates it as an arbitrary function.
static NativeInteger carry(NativeInteger m, NativeInteger p) {
  return m >= (p >> 1) ? NativeInteger(1) : NativeInteger(0);
}

static void lut(uint32_t p) {
  BinFHEContext cc;
  // STD128 with arbitrary-function support: q = N, so p <= N / 256.
  // N = 2048 (OpenFHE's minimum for 128-bit) gives p <= 8; p = 16 needs N = 4096.
  cc.GenerateBinFHEContext(STD128, true, 12, p <= 8 ? 0 : 4096);
  std::string name = "lut p=" + std::to_string(p);
  describe(name.c_str(), cc);
  if (cc.GetMaxPlaintextSpace().ConvertToInt() < p) {
    std::printf("[%s] p exceeds the plaintext space\n", name.c_str());
    return;
  }
  auto sk = keygen(name.c_str(), cc);
  auto table = cc.GenerateLUTviaFunction(carry, p);
  std::vector<LWECiphertext> in;
  for (uint32_t m = 0; m < p; ++m) in.push_back(cc.Encrypt(sk, m, SMALL_DIM, p));
  time_op((name + " EvalFunc").c_str(), p, [&](int i) {
    auto c = cc.EvalFunc(in[i], table);
    LWEPlaintext m;
    cc.Decrypt(sk, c, &m, p);
    return uint64_t(m) == carry(i, p).ConvertToInt();
  });
}

// The sign of a large-modulus LWE value (a comparison of wide integers
// after one linear subtraction), as in OpenFHE's eval-sign example.
static void sign() {
  BinFHEContext cc;
  const uint32_t logQ = 17;
  cc.GenerateBinFHEContext(STD128, false, logQ, 0, GINX, false);
  describe("sign logQ=17", cc);
  auto sk = keygen("sign logQ=17", cc);
  const uint64_t Q = uint64_t(1) << logQ;
  const uint64_t q = cc.GetParams()->GetLWEParams()->Getq().ConvertToInt();
  const uint64_t p = cc.GetMaxPlaintextSpace().ConvertToInt() * (Q / q);
  std::printf("[sign logQ=17] plaintext space %llu\n", (unsigned long long)p);
  std::vector<LWECiphertext> in;
  std::vector<int> want;
  for (int i = 0; i < 8; ++i) {
    in.push_back(cc.Encrypt(sk, p / 2 + i - 3, SMALL_DIM, p, Q));
    want.push_back(i >= 3);
  }
  time_op("sign logQ=17 EvalSign", 8, [&](int i) {
    auto c = cc.EvalSign(in[i]);
    LWEPlaintext m;
    cc.Decrypt(sk, c, &m, 2);
    return m == want[i];
  });
}

int main(int argc, char** argv) {
  std::vector<std::string> what(argv + 1, argv + argc);
  if (what.empty()) what = {"gate", "lut4", "lut8", "lut16", "sign"};
  std::printf("hardware threads %u\n", std::thread::hardware_concurrency());
  for (auto& w : what) {
    if (w == "gate") gate();
    else if (w == "lut4") lut(4);
    else if (w == "lut8") lut(8);
    else if (w == "lut16") lut(16);
    else if (w == "sign") sign();
    else std::printf("unknown measurement %s\n", w.c_str());
    std::fflush(stdout);
  }
  return 0;
}
