/*############################################################################
  # Copyright 2018 Intel Corporation
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
 * \brief Split NrVerify unit tests.
 */

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/src/sig_types.h"
#include "epid/verifier/api.h"
#include "epid/verifier/src/rlverify.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/verifier/unittests/verifier-testhelper.h"

namespace {
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

std::vector<uint8_t> change_sigrl_hashalg(std::vector<uint8_t> const& sigrl,
                                          HashAlg hash_alg) {
  std::vector<uint8_t> sigrl_with_correct_hash(sigrl);
  SigRl* sigrl_ptr = reinterpret_cast<SigRl*>(sigrl_with_correct_hash.data());
  set_gid_hashalg(&sigrl_ptr->gid, hash_alg);
  return sigrl_with_correct_hash;
}

/////////////////////////////////////////////////////////////////////////
// Simple Errors
TEST_F(EpidVerifierSplitTest, SplitNrVerifyFailsGivenNullParameters) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(nullptr, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, nullptr, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, nullptr,
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), nullptr,
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], nullptr,
                         sizeof(SplitNrProof)));

  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], 0));
}

/////////////////////////////////////////////////////////////////////
// Reject

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithTNotInG1) {
  // * 4.2.2 step 1 - The verifier verifies that G1.inGroup(T) = true.
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  SplitNrProof nr_proof = epid_signature->sigma[0];
  nr_proof.T.x.data.data[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithTIdentityOfG1) {
  // * 4.2.2 step 2 - The verifier verifies that G1.isIdentity(T) = false.
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  SplitNrProof nr_proof = epid_signature->sigma[0];
  nr_proof.T = this->kG1IdentityStr;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithCNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  SplitNrProof nr_proof = epid_signature->sigma[0];
  nr_proof.c.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithSmuNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  SplitNrProof nr_proof = epid_signature->sigma[0];
  nr_proof.smu.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithSnuNotInRange) {
  // * 4.2.2 step 3 - The verifier verifies that c, smu, snu in [0, p-1].
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  SplitNrProof nr_proof = epid_signature->sigma[0];
  nr_proof.snu.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0], &nr_proof,
                         sizeof(SplitNrProof)));
}

//   4.2.2 step 4 - The verifier computes nc = (- c) mod p.
// This Step is not testable

//   4.2.2 step 5 - The verifier computes R1 = G1.multiExp(K, smu, B, snu).
// This Step is not testable

//   4.2.2 step 6 - The verifier computes R2 = G1.multiExp(K', smu, B', snu,
//                  T, nc).
// This Step is not testable

TEST_F(EpidVerifierSplitTest, SplitNrVerifyRejectsSigWithInvalidCommitment) {
  // * 4.2.2 step 7 - The verifier verifies c = Fp.hash(p || g1 || B || K ||
  //                  B' || K' || T || R1 || R2 || m).
  //                  Refer to Section 7.1 for hash operation over a
  //                  prime field.
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  std::vector<uint8_t> test_msg = this->kTest1;
  test_msg[0]++;
  EXPECT_EQ(kEpidBadArgErr,
            EpidNrVerify(verifier, &epid_signature->sigma0, test_msg.data(),
                         test_msg.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest,
       SplitNrVerifyRejectsSigWithValidCommitmentDiffHashAlg) {
  // * 4.2.2 step 7 - The verifier verifies c = Fp.hash(p || g1 || B || K ||
  //                  B' || K' || T || R1 || R2 || m).
  //                  Refer to Section 7.1 for hash operation over a
  //                  prime field.
  // result must be kEpidBadArgErr
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature_sha384 = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha384RndBsnTest1WithSigRl.data());
  auto epid_signature_sha512 = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha512RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidNrVerify(verifier, &epid_signature_sha384->sigma0,
                   this->kTest1.data(), this->kTest1.size(), &sig_rl->bk[0],
                   &epid_signature_sha384->sigma[0], sizeof(SplitNrProof)));
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidNrVerify(verifier, &epid_signature_sha512->sigma0,
                   this->kTest1.data(), this->kTest1.size(), &sig_rl->bk[0],
                   &epid_signature_sha512->sigma[0], sizeof(SplitNrProof)));
}

/////////////////////////////////////////////////////////////////////
// Accept
//   4.2.2 step 8 - If all the above verifications succeed, the verifier
//                  outputs true. If any of the above verifications fails,
//                  the verifier aborts and outputs false

TEST_F(EpidVerifierSplitTest, SplitNrVerifyAcceptsSigWithRandomBaseNameSha256) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyAcceptsSigWithRandomBaseNameSha384) {
  GroupPubKey pub_key = this->kGrpXKey;
  std::vector<uint8_t> sigrl_sha384 =
      change_sigrl_hashalg(kSigRl5EntrySha256Data, kSha384);
  set_gid_hashalg(&pub_key.gid, kSha384);
  VerifierCtxObj verifier(pub_key);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha384RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(sigrl_sha384.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest, SplitNrVerifyAcceptsSigWithRandomBaseNameSha512) {
  GroupPubKey pub_key = this->kGrpXKey;
  set_gid_hashalg(&pub_key.gid, kSha512);
  std::vector<uint8_t> sigrl_sha512 =
      change_sigrl_hashalg(kSigRl5EntrySha256Data, kSha512);
  VerifierCtxObj verifier(pub_key);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha512RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(sigrl_sha512.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest,
       SplitNrVerifyAcceptsSigWithRandomBaseNameSha512256) {
  GroupPubKey pub_key = this->kGrpXKey;
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  std::vector<uint8_t> sigrl_sha512_256 =
      change_sigrl_hashalg(kSigRl5EntrySha256Data, kSha512_256);
  VerifierCtxObj verifier(pub_key);
  auto epid_signature = reinterpret_cast<EpidSplitSignature const*>(
      this->kSplitSigGrpXMember3Sha512_256RndBsnTest1WithSigRl.data());
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(sigrl_sha512_256.data());
  EXPECT_EQ(kEpidSigValid,
            EpidNrVerify(verifier, &epid_signature->sigma0, this->kTest1.data(),
                         this->kTest1.size(), &sig_rl->bk[0],
                         &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

TEST_F(EpidVerifierSplitTest,
       SplitNrVerifyAcceptsMsgContainingAllPossibleBytes) {
  GroupPubKey pub_key = this->kGrpXKey;
  VerifierCtxObj verifier(pub_key);
  auto epid_signature =
      (EpidSplitSignature*)this
          ->kSplitSigGrpXMember3Sha256RndBsnData_0_255WithSigRl.data();
  SigRl const* sig_rl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  EXPECT_EQ(
      kEpidSigValid,
      EpidNrVerify(verifier, &epid_signature->sigma0, this->kData_0_255.data(),
                   this->kData_0_255.size(), &sig_rl->bk[0],
                   &epid_signature->sigma[0], sizeof(SplitNrProof)));
}

}  // namespace
