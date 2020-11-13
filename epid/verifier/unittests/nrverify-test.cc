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

/*!
 * \file
 * \brief NrVerify unit tests.
 */

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

/////////////////////////////////////////////////////////////////////////
// Simple Errors

TEST_F(EpidVerifierTest, NrVerifyFailsGivenNullParameters) {
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  EXPECT_EQ(kEpidBadCtxErr,
            EpidNrVerify(nullptr, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));

  EXPECT_EQ(
      kEpidBadSignatureErr,
      EpidNrVerify(verifier, nullptr, this->kTest0.data(), this->kTest0.size(),
                   &sig_rl->bk[0], &epid_signature->sigma[0], sizeof(NrProof)));

  EXPECT_EQ(kEpidBadMessageErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, nullptr,
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));

  EXPECT_EQ(kEpidBadSigRlEntryErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), nullptr,
                         &epid_signature->sigma[0], sizeof(NrProof)));

  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], nullptr,
                         sizeof(NrProof)));

  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], 0));
}

/////////////////////////////////////////////////////////////////////
// Reject

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithTNotInG1) {
  // * 4.2.2 step 1 - The verifier verifies that G1.inGroup(T) = true.
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  NrProof nr_proof = epid_signature->sigma[0];
  nr_proof.T.x.data.data[0]++;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithTIdentityOfG1) {
  // * 4.2.2 step 2 - The verifier verifies that G1.isIdentity(T) = false.
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  NrProof nr_proof = epid_signature->sigma[0];
  nr_proof.T = this->kG1IdentityStr;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithCNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  NrProof nr_proof = epid_signature->sigma[0];
  nr_proof.c.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithSmuNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  NrProof nr_proof = epid_signature->sigma[0];
  nr_proof.smu.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithSnuNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  NrProof nr_proof = epid_signature->sigma[0];
  nr_proof.snu.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(NrProof)));
}

//   4.2.2 step 4 - The verifier computes nc = (- c) mod p.
// This Step is not testable

//   4.2.2 step 5 - The verifier computes R1 = G1.multiExp(K, smu, B, snu).
// This Step is not testable

//   4.2.2 step 6 - The verifier computes R2 = G1.multiExp(K', smu, B', snu,
//                  T, nc).
// This Step is not testable

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithInvalidCommitment) {
  // * 4.2.2 step 7 - The verifier verifies c = Fp.hash(p || g1 || B || K ||
  //                  B' || K' || T || R1 || R2 || m).
  //                  Refer to Section 7.1 for hash operation over a
  //                  prime field.
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  std::vector<uint8_t> test_msg = this->kTest0;
  test_msg[0]++;
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, test_msg.data(),
                         test_msg.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyRejectsSigWithValidCommitmentDiffHashAlg) {
  // * 4.2.2 step 7 - The verifier verifies c = Fp.hash(p || g1 || B || K ||
  //                  B' || K' || T || R1 || R2 || m).
  //                  Refer to Section 7.1 for hash operation over a
  //                  prime field.
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature_sha384 = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrpXMember0Sha384RandbaseMsg0.data());
  auto epid_signature_sha512 = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrpXMember0Sha512RandbaseMsg0.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(this->kGrpXSigRl.data());
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature_sha384->sigma0,
                         this->kMsg0.data(), this->kMsg0.size(), &sig_rl->bk[0],
                         &epid_signature_sha384->sigma[0], sizeof(NrProof)));
  EXPECT_EQ(kEpidBadNrProofErr,
            EpidNrVerify(verifier, &epid_signature_sha512->sigma0,
                         this->kMsg0.data(), this->kMsg0.size(), &sig_rl->bk[0],
                         &epid_signature_sha512->sigma[0], sizeof(NrProof)));
}

/////////////////////////////////////////////////////////////////////
// Accept
//   4.2.2 step 8 - If all the above verifications succeed, the verifier
//                  outputs true. If any of the above verifications fails,
//                  the verifier aborts and outputs false

TEST_F(EpidVerifierTest, NrVerifyAcceptsSigWithRandomBaseNameSha256) {
  VerifierCtxObj verifier(this->kGrp01Key);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha256RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest,
       NrVerifyAcceptsSigWithRandomBaseNameSha256UsingIkgfData) {
  VerifierCtxObj verifier(this->kPubKeyIkgfStr);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigMember0Sha256RandombaseMsg0Ikgf.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(this->kSigRlIkgf.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kMsg0.data(),
                         this->kMsg0.size(), &sig_rl->bk[2],
                         &epid_signature->sigma[2], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyAcceptsSigWithRandomBaseNameSha384) {
  GroupPubKey pubkey01_sha384 = this->kGrp01Key;
  pubkey01_sha384.gid.data[1] = 1;
  VerifierCtxObj verifier(pubkey01_sha384);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha384RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyAcceptsSigWithRandomBaseNameSha512) {
  GroupPubKey pubkey01_sha512 = this->kGrp01Key;
  pubkey01_sha512.gid.data[1] = 2;
  VerifierCtxObj verifier(pubkey01_sha512);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrp01Member0Sha512RandombaseTest0.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest0.data(),
                         this->kTest0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyAcceptsSigWithRandomBaseNameSha512256) {
  GroupPubKey pubkey01_sha512256 = this->kGrpXKey;
  pubkey01_sha512256.gid.data[1] = 3;
  VerifierCtxObj verifier(pubkey01_sha512256);
  auto epid_signature = reinterpret_cast<EpidNonSplitSignature const*>(
      this->kSigGrpXMember0Sha512256RandombaseMsg0.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(this->kGrpXSigRl.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kMsg0.data(),
                         this->kMsg0.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(NrProof)));
}

TEST_F(EpidVerifierTest, NrVerifyAcceptsMsgContainingAllPossibleBytes) {
  GroupPubKey pub_key = this->kPubKeySigRlVerify;
  // Initialize pubkey.gid to sha512
  pub_key.gid.data[1] = 2;
  VerifierCtxObj verifier(pub_key);
  auto epid_signature =
      (EpidNonSplitSignature*)kSigGrp01Member0Sha512kBsn0Data_0_255.data();
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(this->kGrp01SigRl.data());
  EXPECT_EQ(
      kEpidSigValid,
      EpidNrVerify(verifier, &epid_signature->sigma0, this->kData_0_255.data(),
                   this->kData_0_255.size(), &sig_rl->bk[0],
                   &epid_signature->sigma[0], sizeof(NrProof)));
}

}  // namespace
