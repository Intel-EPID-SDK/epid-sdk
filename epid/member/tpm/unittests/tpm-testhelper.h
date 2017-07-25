/*############################################################################
  # Copyright 2017 Intel Corporation
  #
  # Licensed under the Apache License, Version 2.0 (the "License");
  # you may not use this file except in compliance with the License.
  # You may obtain a copy of the License at
  #
  #     http://www.apache.org/licenses/LICENSE-2.0
  #
  # Unless required by applicable law or agreed to in writing, software
  # distributed under the License is distributed on an "AS IS" BASIS,
  # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  # See the License for the specific language governing permissions and
  # limitations under the License.
  ############################################################################*/
/// Tpm C++ wrapper interface.
/*!
 * \file
 */
#ifndef EPID_MEMBER_TPM_UNITTESTS_TPM_TESTHELPER_H_
#define EPID_MEMBER_TPM_UNITTESTS_TPM_TESTHELPER_H_

#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
extern "C" {
#include "epid/common/bitsupplier.h"
#include "epid/common/types.h"
#include "epid/member/api.h"  // for MemberPrecomp
}

typedef struct TpmCtx TpmCtx;
typedef struct Epid2Params_ Epid2Params_;
typedef struct FiniteField FiniteField;
typedef struct EcGroup EcGroup;

/// Test fixture class for Tpm
class EpidTpmTest : public ::testing::Test {
 public:
  /// test data
  static const GroupPubKey kGroupPublicKey;
  /// test data
  static const PrivKey kMemberPrivateKey;
  /// test data
  static const MemberPrecomp kMemberPrecomp;
  /// signature based revocation list with 5 entries
  static std::vector<uint8_t> kSigRl5EntryData;
  /// a message
  static const std::vector<uint8_t> kMsg0;
  /// a basename
  static const std::vector<uint8_t> kBsn0;

  /// setup called before each TEST_F starts
  virtual void SetUp() {}
  /// teardown called after each TEST_F finishes
  virtual void TearDown() {}
};

/// C++ Wrapper to manage memory for Epid2Params via RAII
class Epid2ParamsObj {
 public:
  /// Create a Epid2Params
  Epid2ParamsObj();

  // This class instances are not meant to be copied.
  // Explicitly delete copy constructor and assignment operator.
  Epid2ParamsObj(const Epid2ParamsObj&) = delete;
  Epid2ParamsObj& operator=(const Epid2ParamsObj&) = delete;

  /// Destroy the Epid2Params
  ~Epid2ParamsObj();
  /// get a pointer to the stored Epid2Params
  Epid2Params_* ctx() const;
  /// cast operator to get the pointer to the stored Epid2Params
  operator Epid2Params_*() const;
  /// const cast operator to get the pointer to the stored Epid2Params
  operator const Epid2Params_*() const;
  /// get a pointer to the prime field Fp
  FiniteField* Fp() const;
  /// get a pointer to elliptic curve group G1
  EcGroup* G1() const;

 private:
  /// The stored parameters
  Epid2Params_* params_;
};

/// C++ Wrapper to manage memory for TpmCtx via RAII
class TpmCtxObj {
 public:
  /// Create a TpmCtx
  TpmCtxObj(BitSupplier rnd_func, void* rnd_param,
            Epid2ParamsObj const& params);

  // This class instances are not meant to be copied.
  // Explicitly delete copy constructor and assignment operator.
  TpmCtxObj(const TpmCtxObj&) = delete;
  TpmCtxObj& operator=(const TpmCtxObj&) = delete;

  /// Destroy the TpmCtx
  ~TpmCtxObj();
  /// get a pointer to the stored TpmCtx
  TpmCtx* ctx() const;
  /// cast operator to get the pointer to the stored TpmCtx
  operator TpmCtx*() const;
  /// const cast operator to get the pointer to the stored TpmCtx
  operator const TpmCtx*() const;

 private:
  /// The stored TpmCtx
  TpmCtx* ctx_;
  Epid2ParamsObj const& params_;
};

#endif  // EPID_MEMBER_TPM_UNITTESTS_TPM_TESTHELPER_H_
