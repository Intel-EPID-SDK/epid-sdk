/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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
/// CheckPrivRlEntry unit tests.
/*! \file */

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

#include "epid/verifier.h"

extern "C" {
#include "rlverify.h"
}

#include "testhelper/errors-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"
#include "verifier-testhelper.h"

namespace {

TEST_F(EpidVerifierTest, CheckPrivRlEntryFailsGivenNullPtr) {
  // check ctx, sig, f for NULL
  auto& pub_key = this->kGrpXKey;
  auto& priv_rl = this->kGrpXPrivRl;
  auto& sig = this->kSigGrpXMember0Sha256Bsn0Msg0;

  VerifierCtxObj verifier(pub_key);
  FpElemStr fp_str = ((PrivRl const*)priv_rl.data())->f[0];
  BasicSignature basic_signature =
      ((EpidNonSplitSignature const*)sig.data())->sigma0;

  EXPECT_EQ(kEpidBadCtxErr,
            EpidCheckPrivRlEntry(nullptr, &basic_signature, &fp_str));
  EXPECT_EQ(kEpidBadSignatureErr,
            EpidCheckPrivRlEntry(verifier, nullptr, &fp_str));
  EXPECT_EQ(kEpidBadRlEntryErr,
            EpidCheckPrivRlEntry(verifier, &basic_signature, nullptr));
}

TEST_F(EpidVerifierTest, CheckPrivRlEntryFailsGivenRevokedPrivKey) {
  // test a revoked priv key
  // check ctx, sig, f for NULL
  auto& pub_key = this->kGrpXKey;
  auto& priv_rl = this->kGrpXPrivRl;
  // signed using revoked key
  auto& sig = this->kSigGrpXRevokedPrivKey000Sha256Bsn0Msg0;

  VerifierCtxObj verifier(pub_key);
  FpElemStr fp_str = ((PrivRl const*)priv_rl.data())->f[0];
  BasicSignature basic_signature =
      ((EpidNonSplitSignature const*)sig.data())->sigma0;

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidCheckPrivRlEntry(verifier, &basic_signature, &fp_str));
}

TEST_F(EpidVerifierTest,
       CheckPrivRlEntryFailsGivenRevokedPrivKeyUsingIkgfData) {
  // test a revoked priv key
  // check ctx, sig, f for NULL
  auto& pub_key = this->kPubKeyIkgfStr;
  auto& priv_rl = this->kPrivRlIkgf;
  // signed using revoked key
  auto& sig = this->kSigRevokedPrivKeySha256Bsn0Msg0Ikgf;

  VerifierCtxObj verifier(pub_key);

  FpElemStr fp_str = ((PrivRl const*)priv_rl.data())->f[2];
  BasicSignature basic_signature =
      ((EpidNonSplitSignature const*)sig.data())->sigma0;

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidCheckPrivRlEntry(verifier, &basic_signature, &fp_str));
}

TEST_F(EpidVerifierTest, CheckPrivRlEntrySucceedsGivenUnRevokedPrivKey) {
  // test a non revoked priv key
  auto& pub_key = this->kGrpXKey;
  auto& priv_rl = this->kGrpXPrivRl;
  // signed using un revoked key
  auto& sig = this->kSigGrpXMember0Sha256Bsn0Msg0;

  VerifierCtxObj verifier(pub_key);
  FpElemStr fp_str = ((PrivRl const*)priv_rl.data())->f[0];
  BasicSignature basic_signature =
      ((EpidNonSplitSignature const*)sig.data())->sigma0;

  EXPECT_EQ(kEpidNoErr,
            EpidCheckPrivRlEntry(verifier, &basic_signature, &fp_str));
}

TEST_F(EpidVerifierTest,
       CheckPrivRlEntrySucceedsGivenUnRevokedPrivKeyUsingIkgfData) {
  // test a non revoked priv key
  auto& pub_key = this->kPubKeyIkgfStr;
  auto& priv_rl = this->kPrivRlIkgf;
  // signed using un revoked key
  auto& sig = this->kSigMember0Sha256Bsn0Msg0Ikgf;

  VerifierCtxObj verifier(pub_key);
  FpElemStr fp_str = ((PrivRl const*)priv_rl.data())->f[0];
  BasicSignature basic_signature =
      ((EpidNonSplitSignature const*)sig.data())->sigma0;

  EXPECT_EQ(kEpidNoErr,
            EpidCheckPrivRlEntry(verifier, &basic_signature, &fp_str));
}

}  // namespace
