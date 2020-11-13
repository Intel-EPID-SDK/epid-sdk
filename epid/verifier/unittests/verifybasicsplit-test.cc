/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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

/*!
 * \file
 * \brief EpidVerifyBasicSplitSig unit tests.
 */

#include <cstring>
#include <vector>

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "epid/verifier.h"
#include "verifybasic.h"
}

#include "testhelper/errors-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"
#include "verifier-testhelper.h"

namespace {

TEST_F(EpidVerifierSplitTest, VerifyBasicSplitSigFailsGivenNullPtr) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;

  EXPECT_EQ(kEpidBadCtxErr, EpidVerifyBasicSplitSig(nullptr, &basic_sig, &nk,
                                                    msg.data(), msg.size()));
  EXPECT_EQ(
      kEpidBadSignatureErr,
      EpidVerifyBasicSplitSig(verifier, nullptr, &nk, msg.data(), msg.size()));
  EXPECT_EQ(
      kEpidBadMessageErr,
      EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk, nullptr, msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigCanVerifyValidSignatureWithSHA256) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 0;
  VerifierCtxObj verifier(pub_key);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigCanVerifyValidSignatureWithSHA384) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 1;
  VerifierCtxObj verifier(pub_key);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha384RandombaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigCanVerifyValidSignatureWithSHA512) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 2;
  VerifierCtxObj verifier(pub_key);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha512RandombaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigCanVerifyValidSignatureWithSHA512256) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 3;
  VerifierCtxObj verifier(pub_key);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha512256RndbaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigDetectsInvalidSignatureGivenMatchingMessage) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const FpElemStr nk = sig->nonce;
  const BasicSignature basic_sig = sig->sigma0;
  auto& msg = this->kTest1;
  BasicSignature corrupted_basic_sig = basic_sig;
  corrupted_basic_sig.B.x.data.data[0]++;
  EXPECT_NE(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &corrupted_basic_sig,
                                                &nk, msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigDetectsInvalidSignatureGivenMessageMismatch) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto msg = this->kTest1;
  msg[0]++;  // change message for signature verification to fail
  EXPECT_EQ(kEpidSigInvalid, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                     msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifyBasicSplitSigCanVerifyWithBasename) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;
  auto& msg = this->kTest1;
  auto& basename = this->kBasename1;
  THROW_ON_EPIDERR(
      EpidVerifierSetBasename(verifier, basename.data(), basename.size()));
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifyBasicSplitSigCanVerifyMsgContainingAllPossibleBytes) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 0;
  VerifierCtxObj verifier(pub_key);
  auto const& sig =
      (EpidSplitSignature const*)this
          ->kSplitSigGrpXMember3Sha256kBsn0Data_0_255NoSigRl.data();
  const BasicSignature basic_sig = sig->sigma0;
  const FpElemStr nk = sig->nonce;

  auto& msg = this->kData_0_255;
  auto& basename = this->kBsn0;
  THROW_ON_EPIDERR(
      EpidVerifierSetBasename(verifier, basename.data(), basename.size()));
  EXPECT_EQ(kEpidNoErr, EpidVerifyBasicSplitSig(verifier, &basic_sig, &nk,
                                                msg.data(), msg.size()));
}

}  // namespace
