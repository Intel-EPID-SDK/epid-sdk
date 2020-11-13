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
 * \brief EpidVerifySplitSig unit tests.
 */
#include <algorithm>

#include "common/endian_convert.h"
#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"
#include "verifier-testhelper.h"
extern "C" {
#include "verify.h"
}

namespace {
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}
std::vector<uint8_t> kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryFirstRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsigrl_grpx_member3_bsn0_msg0_sha256_first_revoked.inc"
};
std::vector<uint8_t> kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryMiddleRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsigrl_grpx_member3_bsn0_msg0_sha256_middle_revoked.inc"
};
std::vector<uint8_t> kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryLastRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsigrl_grpx_member3_bsn0_msg0_sha256_last_revoked.inc"
};
std::vector<uint8_t> kSplitSigGrpXMember3Sha256Bsn0Msg0FirstRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0_msg0_first_revoked.inc"
};
std::vector<uint8_t> kSplitSigGrpXMember3Sha256Bsn0Msg0MiddleRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0_msg0_middle_revoked.inc"
};
std::vector<uint8_t> kSplitSigGrpXMember3Sha256Bsn0Msg0LastRevoked = {
#include "testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0_msg0_last_revoked.inc"
};

/////////////////////////////////////////////////////////////////////////
// Simple Errors

TEST_F(EpidVerifierSplitTest, VerifySplitFailsGivenNullParameters) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto& msg = this->kTest0;

  EXPECT_EQ(kEpidBadCtxErr,
            EpidVerifySplitSig(nullptr, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, nullptr, sig.size(), msg.data(),
                               msg.size()));
  EXPECT_EQ(kEpidBadMessageErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), nullptr, msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitFailsGivenTooShortSigLen) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto& msg = this->kTest1;

  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               0, msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sizeof(EpidSplitSignature) - sizeof(NrProof) - 1,
                               msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitFailsGivenSigLenTooShortForRlCount) {
  VerifierCtxObj verifier(this->kGrpXKey);
  EpidVerifierSetSigRl(verifier, (SigRl const*)this->kGrp01SigRl.data(),
                       this->kGrp01SigRl.size());
  auto sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto n2 = this->kGrp01SigRlN2;
  sig.resize(sizeof(EpidSplitSignature) +
             (n2 - 2) * sizeof(((EpidSplitSignature*)0)->sigma));
  auto& msg = this->kTest1;

  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitFailsGivenSigLenTooLongForRlCount) {
  VerifierCtxObj verifier(this->kGrpXKey);
  EpidVerifierSetSigRl(verifier, (SigRl const*)this->kGrp01SigRl.data(),
                       this->kGrp01SigRl.size());
  auto sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto n2 = this->kGrp01SigRlN2;
  sig.resize(sizeof(EpidSplitSignature) +
             n2 * sizeof(((EpidSplitSignature*)0)->sigma));
  auto& msg = this->kTest1;

  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

#if (SIZE_MAX <= 0xFFFFFFFF)  // When size_t value is 32 bit or lower
TEST_F(EpidVerifierSplitTest, VerifySplitFailsGivenRlCountTooBig) {
  VerifierCtxObj verifier(this->kGrpXKey);
  EpidVerifierSetSigRl(verifier, (SigRl const*)this->kGrp01SigRl.data(),
                       this->kGrp01SigRl.size());
  auto sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  uint32_t n2 = SIZE_MAX / sizeof(NrProof) + 1;
  uint32_t n2_ = ntohl(n2);
  auto sig_struct = (EpidSplitSignature*)sig.data();
  sig_struct->n2 = *((OctStr32*)&n2_);
  sig.resize(sizeof(EpidSplitSignature) + (n2 - 1) * sizeof(NrProof));
  auto& msg = this->kTest1;
  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}
#endif

/////////////////////////////////////////////////////////////////////
//
//   4.1.2 step 1 - The verifier reads the pre-computed (e12, e22, e2w, eg12).
//                  Refer to Section 3.6 for the computation of these values.
// This Step is not testable

/////////////////////////////////////////////////////////////////////
// Non-Revocation List Reject
//   4.1.2 step 2 - The verifier verifies the basic signature Sigma0 as
//                  follows:

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithBNotInG1) {
  // * 4.1.2 step 2.a - The verifier verifies G1.inGroup(B) = true.
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;
  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.B.x.data.data[31]++;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithBIdentityOfG1) {
  // * 4.1.2 step 2.b - The verifier verifies that G1.isIdentity(B) is false.
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.B = this->kG1IdentityStr;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitRejectsSigWithDiffBaseNameSameHashAlg) {
  // * 4.1.2 step 2.c - If bsn is provided, the verifier verifies
  //                    B = G1.hash(bsn).
  // result must be kEpidSigInvalid
  auto& pub_key = this->kGrpXKey;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBasename1;

  VerifierCtxObj verifier(pub_key);

  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitRejectsSigWithSameBaseNameDiffHashAlg) {
  // * 4.1.2 step 2.c - If bsn is provided, the verifier verifies
  //                    B = G1.hash(bsn).
  // result must be kEpidSigInvalid
  GroupPubKey pub_key = this->kGrpXKey;
  auto& sig = this->kSplitSigGrpXMember3Sha512Basename1Test1NoSigRl;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  set_gid_hashalg(&pub_key.gid, kSha512);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithDifferentHugeBaseName) {
  // * 4.1.2 step 2.c - If bsn is provided, the verifier verifies
  //                    B = G1.hash(bsn).
  // result must be kEpidSigInvalid
  auto& pub_key = this->kGrpXKey;
  auto& sig = this->kSplitSigGrpXMember3Sha256HugeBsnMsg0NoSigRl;
  auto& msg = this->kMsg0;
  std::vector<uint8_t> bsn(1024 * 1024);
  uint8_t c = 0;
  for (size_t i = 0; i < bsn.size(); ++i) {
    // change middle kilobyte
    if (i == 512 * 1024) c++;
    if (i == 513 * 1024) c--;
    bsn[i] = c++;
  }

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithKNotInG1) {
  // * 4.1.2 step 2.d - The verifier verifies G1.inGroup(K) = true.
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.K.x.data.data[31]++;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithTNotInG1) {
  // * 4.1.2 step 2.e - The verifier verifies G1.inGroup(T) = true.
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.T.x.data.data[31]++;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithCNotInRange) {
  // * 4.1.2 step 2.f - The verifier verifies c, sx, sf, sa, sb in [0, p-1].
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.c.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithSxNotInRange) {
  // * 4.1.2 step 2.f - The verifier verifies c, sx, sf, sa, sb in [0, p-1].
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.sx.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithSfNotInRange) {
  // * 4.1.2 step 2.f - The verifier verifies c, sx, sf, sa, sb in [0, p-1].
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.sf.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithSaNotInRange) {
  // * 4.1.2 step 2.f - The verifier verifies c, sx, sf, sa, sb in [0, p-1].
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.sa.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigWithSbNotInRange) {
  // * 4.1.2 step 2.f - The verifier verifies c, sx, sf, sa, sb in [0, p-1].
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;

  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->sigma0.sb.data = this->kParamsStr.p.data;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

//   4.1.2 step 2.g - The verifier computes nc = (-c) mod p.
// This Step is not testable

//   4.1.2 step 2.h - The verifier computes nsx = (-sx) mod p.
// This Step is not testable

//   4.1.2 step 2.i - The verifier computes R1 = G1.multiExp(B, sf, K, nc).
// This Step is not testable

//   4.1.2 step 2.j - The verifier computes t1 = G2.multiExp(g2, nsx, w, nc).
// This Step is not testable

//   4.1.2 step 2.k - The verifier computes R2 = pairing(T, t1).
// This Step is not testable

//   4.1.2 step 2.l - The verifier compute t2 = GT.multiExp(e12, sf, e22, sb,
//                    e2w, sa, eg12, c).
// This Step is not testable

//   4.1.2 step 2.m - The verifier compute R2 = GT.mul(R2, t2).
// This Step is not testable

//   4.1.2 step 2.n - The verifier compute t3 = Fp.hash(p || g1 || g2 || h1
//                    || h2 || w || B || K || T || R1 || R2).
//                    Refer to Section 7.1 for hash operation over a prime
//                    field.
// This Step is not testable

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigDifferingOnlyInMsg) {
  // * 4.1.2 step 2.o - The verifier verifies c = Fp.hash(t3 || m).
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;

  auto msg = this->kTest1;
  msg[0]++;
  EXPECT_EQ(kEpidSigInvalid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigDifferingOnlyInBaseName) {
  // * 4.1.2 step 2.o - The verifier verifies c = Fp.hash(t3 || m).
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);

  // copy sig data to a local buffer
  auto sig_data = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  // simulate change to basename
  sig->sigma0.B.x.data.data[0] += 1;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigDifferingOnlyInGroup) {
  // * 4.1.2 step 2.o - The verifier verifies c = Fp.hash(t3 || m).
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);

  // copy sig data to a local buffer
  auto sig_data = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  // simulate change to h1
  sig->sigma0.T.x.data.data[0] += 1;
  auto msg = this->kMsg0;
  EXPECT_EQ(kEpidSigInvalid, EpidVerifySplitSig(verifier, sig, sig_data.size(),
                                                msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigDifferingOnlyInHashAlg) {
  // * 4.1.2 step 2.o - The verifier verifies c = Fp.hash(t3 || m).
  // result must be kEpidSigInvalid
  VerifierCtxObj verifier(this->kGrpXKey);
  auto& msg = this->kTest1;
  auto& sig = this->kSplitSigGrpXMember3Sha384RandombaseTest1NoSigRl;

  EXPECT_EQ(kEpidSigInvalid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

//   4.1.2 step 2.p - If any of the above verifications fails, the verifier
//                    aborts and outputs 1.
// This Step is an aggregate of the above steps

/////////////////////////////////////////////////////////////////////
// Group Based Revocation List Reject
//   4.1.2 step 3 - If GroupRL is provided

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsFromGroupRlSingleEntry) {
  // * 4.1.2 step 3.a - The verifier verifies that gid does not match any entry
  //                    in GroupRL.
  // result must be kEpidSigRevokedInGroupRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;
  auto& grp_rl = this->kGrpRlRevokedGrpXOnlyEntry;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInGroupRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsFromGroupRlFirstEntry) {
  // * 4.1.2 step 3.a - The verifier verifies that gid does not match any entry
  //                    in GroupRL.
  // result must be kEpidSigRevokedInGroupRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;
  auto& grp_rl = this->kGrpRlRevokedGrpXFirstEntry;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInGroupRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsFromGroupRlMiddleEntry) {
  // * 4.1.2 step 3.a - The verifier verifies that gid does not match any entry
  //                    in GroupRL.
  // result must be kEpidSigRevokedInGroupRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;
  auto& grp_rl = this->kGrpRlRevokedGrpXMiddleEntry;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInGroupRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsFromGroupRlLastEntry) {
  // * 4.1.2 step 3.a - The verifier verifies that gid does not match any entry
  //                    in GroupRL.
  // result must be kEpidSigRevokedInGroupRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;
  auto& grp_rl = this->kGrpRlRevokedGrpXLastEntry;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInGroupRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

//   4.1.2 step 3.b - If gid matches an entry in GroupRL, aborts and returns 2.
// This Step is an aggregate of the above steps

/////////////////////////////////////////////////////////////////////
// Private Based Revocation List Reject
//   4.1.2 step 4 - If PrivRL is provided

// * 4.1.2 step 4.a - The verifier verifies that gid in the public key and in
//                    PrivRL match. If mismatch, abort and return
//                    "operation failed".
// Not possible, checked in EpidVerifierSetPrivRl

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromPrivRlSingleEntry) {
  // * 4.1.2 step 4.b - For i = 0, ?, n1-1,
  //                    the verifier computes t4 =G1.exp(B, f[i])
  //                    and verifies that G1.isEqual(t4, K) = false.
  //                    A faster private-key revocation check algorithm is
  //                    provided in Section 4.5.
  // result must be kEpidSigRevokedInPrivRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& priv_rl = this->kGrpXPrivRlRevokedPrivKey000OnlyEntry;
  auto& sig = this->kSplitSigGrpXRevokedPrivKey000Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromPrivRlFirstEntry) {
  // * 4.1.2 step 4.b - For i = 0, ?, n1-1,
  //                    the verifier computes t4 =G1.exp(B, f[i])
  //                    and verifies that G1.isEqual(t4, K) = false.
  //                    A faster private-key revocation check algorithm is
  //                    provided in Section 4.5.
  // result must be kEpidSigRevokedInPrivRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  // kGrpXPrivRl has 3 entries, where current private key is first
  auto& priv_rl = this->kGrpXPrivRl;
  auto& sig = this->kSplitSigGrpXRevokedPrivKey000Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromPrivRlMiddleEntry) {
  // * 4.1.2 step 4.b - For i = 0, ?, n1-1,
  //                    the verifier computes t4 =G1.exp(B, f[i])
  //                    and verifies that G1.isEqual(t4, K) = false.
  //                    A faster private-key revocation check algorithm is
  //                    provided in Section 4.5.
  // result must be kEpidSigRevokedInPrivRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  // kGrpXPrivRl has 3 entries, where current private key is first
  auto priv_rl_copy = this->kGrpXPrivRl;
  PrivRl* priv_rl = (PrivRl*)priv_rl_copy.data();
  // swap the first and the second entry of the priv rl
  std::swap(priv_rl->f[0], priv_rl->f[1]);
  auto& sig = this->kSplitSigGrpXRevokedPrivKey000Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl_copy.data(), priv_rl_copy.size()));

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromPrivRlLastEntry) {
  // * 4.1.2 step 4.b - For i = 0, ?, n1-1,
  //                    the verifier computes t4 =G1.exp(B, f[i])
  //                    and verifies that G1.isEqual(t4, K) = false.
  //                    A faster private-key revocation check algorithm is
  //                    provided in Section 4.5.
  // result must be kEpidSigRevokedInPrivRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  // kGrpXPrivRl has 3 entries, where current private key is first
  auto priv_rl_copy = this->kGrpXPrivRl;
  PrivRl* priv_rl = (PrivRl*)priv_rl_copy.data();
  // swap the first and the second entry of the priv rl
  std::swap(priv_rl->f[0], priv_rl->f[1]);
  auto& sig = this->kSplitSigGrpXRevokedPrivKey000Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl_copy.data(), priv_rl_copy.size()));

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigUsingCorruptedPrivRlEntry) {
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;
  auto& priv_rl = this->kGrpXCorruptedPrivRl;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

//   4.1.2 step 4.c - If the above step fails, the verifier aborts and
//                    output 3.
// This Step is an aggregate of the above steps

/////////////////////////////////////////////////////////////////////
// Signature Based Revocation List Reject
//   4.1.2 step 5 - If SigRL is provided

// * 4.1.2 step 5.a - The verifier verifies that gid in the public key and in
//                    SigRL match. If mismatch, abort and return
//                    "operation failed".
// Not possible, checked in EpidVerifierSetSigRl

TEST_F(EpidVerifierSplitTest, VerifySplitFailsOnSigRlverNotMatchSigRlRlver) {
  // * 4.1.2 step 5.b - The verifier verifies that RLver in Sigma and in SigRL
  //                    match. If mismatch, abort and output "operation failed".
  // result must be "operation failed" (not kEpidSig*)
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& sig_rl = this->kGrpXSigRlVersion2;
  auto& sig = this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidVersionMismatchErr,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitFailsOnSigN2NotMatchSigRlN2) {
  // * 4.1.2 step 5.c - The verifier verifies that n2 in Sigma and in SigRL
  //                    match. If mismatch, abort and output "operation failed".
  // result must be "operation failed" (not kEpidSig*)
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto* sig_rl = (SigRl const*)this->kSigRl5EntrySha256Data.data();
  size_t sig_rl_size = this->kSigRl5EntrySha256Data.size();
  auto sig_data = this->kSplitSigGrpXMember3Sha256Bsn0Msg0SingleEntrySigRl;
  EpidSplitSignature* sig = (EpidSplitSignature*)sig_data.data();
  sig->rl_ver = sig_rl->version;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, sig_rl, sig_rl_size));

  EXPECT_EQ(kEpidBadSignatureErr,
            EpidVerifySplitSig(verifier, sig, sig_data.size(), msg.data(),
                               msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromSigRlSingleEntry) {
  // * 4.1.2 step 5.d - For i = 0, ..., n2-1, the verifier verifies
  //                    nrVerify(B, K, B[i], K[i], Sigma[i]) = true. The details
  //                    of nrVerify() will be given in the next subsection.
  // result must be kEpidSigRevokedInSigRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& sig_rl = this->kSplitSigGrpXMember3Sha256Bsn0Msg0OnlyEntry;
  auto& sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0SingleEntrySigRl;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromSigRlFirstEntry) {
  // * 4.1.2 step 5.d - For i = 0, ..., n2-1, the verifier verifies
  //                    nrVerify(B, K, B[i], K[i], Sigma[i]) = true. The details
  //                    of nrVerify() will be given in the next subsection.
  // result must be kEpidSigRevokedInSigRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& sig_rl = kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryFirstRevoked;
  auto& sig = kSplitSigGrpXMember3Sha256Bsn0Msg0FirstRevoked;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromSigRlMiddleEntry) {
  // * 4.1.2 step 5.d - For i = 0, ..., n2-1, the verifier verifies
  //                    nrVerify(B, K, B[i], K[i], Sigma[i]) = true. The details
  //                    of nrVerify() will be given in the next subsection.
  // result must be kEpidSigRevokedInSigRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& sig_rl = kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryMiddleRevoked;
  auto& sig = kSplitSigGrpXMember3Sha256Bsn0Msg0MiddleRevoked;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromSigRlLastEntry) {
  // * 4.1.2 step 5.d - For i = 0, ..., n2-1, the verifier verifies
  //                    nrVerify(B, K, B[i], K[i], Sigma[i]) = true. The details
  //                    of nrVerify() will be given in the next subsection.
  // result must be kEpidSigRevokedInSigRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& sig_rl = kGrpXSigRlMember3Sha256Bsn0Msg0ThreeEntryLastRevoked;
  auto& sig = kSplitSigGrpXMember3Sha256Bsn0Msg0LastRevoked;
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

//   4.1.2 step 5.e - If the above step fails, the verifier aborts and
//                    output 4.
// This Step is an aggregate of the above steps

/////////////////////////////////////////////////////////////////////
// Verifier Based Revocation List Reject
//   4.1.2 step 6 - If VerifierRL is provided

// * 4.1.2 step 6.a - The verifier verifies that gid in the public key and in
//                    VerifierRL match. If mismatch, abort and return
//                    "operation failed".
// Not possible, checked in EpidVerifierSetVerifierRl

// * 4.1.2 step 6.b - The verifier verifies that B in the signature and in
//                    VerifierRL match. If mismatch, go to step 7.
// result must be "operation failed" (not kEpidSig*)
// Not possible, checked in EpidVerifierSetVerifierRl

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromVerifierRlSingleEntry) {
  // * 4.1.2 step 6.c - For i = 0, ..., n4-1, the verifier verifies that
  //                    K != K[i].
  // result must be kEpidSigRevokedInVerifierRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  auto& ver_rl = this->kGrpXBsn0VerRlSingleEntry;
  auto& sig = this->kSplitSigGrpXVerRevokedMember0Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromVerifierRlFirstEntry) {
  // * 4.1.2 step 6.c - For i = 0, ..., n4-1, the verifier verifies that
  //                    K != K[i].
  // result must be kEpidSigRevokedInVerifierRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  // kGrpXBsn0Sha256VerRl has 3 entries, where curent kBsn0 is the first
  auto& ver_rl = this->kGrpXBsn0Sha256VerRl;
  auto& sig = this->kSplitSigGrpXVerRevokedMember0Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromVerifierRlMiddleEntry) {
  // * 4.1.2 step 6.c - For i = 0, ..., n4-1, the verifier verifies that
  //                    K != K[i].
  // result must be kEpidSigRevokedInVerifierRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  // kGrpXBsn0Sha256VerRl has 3 entries, where curent kBsn0 is the first
  auto& ver_rl_copy = this->kGrpXBsn0Sha256VerRl;
  VerifierRl* ver_rl = (VerifierRl*)ver_rl_copy.data();
  // swap the first and the second entry of the priv rl
  std::swap(ver_rl->K[0], ver_rl->K[1]);
  auto& sig = this->kSplitSigGrpXVerRevokedMember0Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl_copy.data(), ver_rl_copy.size()));

  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitRejectsSigFromVerifierRlLastEntry) {
  // * 4.1.2 step 6.c - For i = 0, ..., n4-1, the verifier verifies that
  //                    K != K[i].
  // result must be kEpidSigRevokedInVerifierRl
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  // kGrpXBsn0Sha256VerRl has 3 entries, where curent kBsn0 is the first
  auto& ver_rl_copy = this->kGrpXBsn0Sha256VerRl;
  VerifierRl* ver_rl = (VerifierRl*)ver_rl_copy.data();
  // swap the first and the second entry of the priv rl
  std::swap(ver_rl->K[0], ver_rl->K[1]);
  auto& sig = this->kSplitSigGrpXVerRevokedMember0Sha256Bsn0Msg0NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl_copy.data(), ver_rl_copy.size()));

  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

//   4.1.2 step 6.d - If the above step fails, the verifier aborts and
//                    output 5
// This Step is an aggregate of the above steps

/////////////////////////////////////////////////////////////////////
// Accept
// 4.1.2 step 7 - If all the above verifications succeed, the verifier
//                outputs 0

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithBaseNameNoRlSha256) {
  auto& pub_key = this->kGrpXKey;
  auto& sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& msg = this->kTest1;
  auto& bsn = this->kBasename1;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithBaseNameAllRlSha256) {
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  auto& sig_rl = this->kSigRl5EntrySha256Data;
  auto& ver_rl = this->kGrpXBsn0Sha256VerRl;
  auto& sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigWithRandomBaseNameNoRlSha256) {
  auto& pub_key = this->kGrpXKey;
  auto& sig = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto& msg = this->kTest1;

  VerifierCtxObj verifier(pub_key);
  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigWithRandomBaseNameAllRlSha256) {
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& grp_rl = this->kGrpRl;
  auto& priv_rl = this->kGrpXPrivRl;
  auto& sig_rl = this->kSigRl5EntrySha256Data;
  auto& sig = this->kSplitSigGrpXMember3Sha256RndBsnTest1WithSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithBaseNameAllRlSha384) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& sig = this->kSplitSigGrpXMember3Sha384Bsn0Msg0;
  auto& grp_rl = this->kGrpRl;

  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  std::vector<uint8_t> ver_rl = kGrpXBsn0Sha384VerRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha384);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid), kSha384);
  set_gid_hashalg(&(reinterpret_cast<VerifierRl*>(ver_rl.data())->gid),
                  kSha384);
  set_gid_hashalg(&pub_key.gid, kSha384);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigWithRandomBaseNameAllRlSha384) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& sig = this->kSplitSigGrpXMember3Sha384RndBsnTest1WithSigRl;
  auto& grp_rl = this->kGrpRl;

  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha384);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid), kSha384);
  set_gid_hashalg(&pub_key.gid, kSha384);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithBaseNameAllRlSha512) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kData_0_255;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& sig = this->kSplitSigGrpXMember3Sha512kBsn0Data_0_255;
  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  std::vector<uint8_t> ver_rl = kGrpXBsn0Sha512VerRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha512);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid), kSha512);
  set_gid_hashalg(&(reinterpret_cast<VerifierRl*>(ver_rl.data())->gid),
                  kSha512);
  set_gid_hashalg(&pub_key.gid, kSha512);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithHugeBaseNameNoRlSha512) {
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 0;
  auto& msg = this->kMsg0;
  auto& sig = this->kSplitSigGrpXMember3Sha512HugeBsnMsg0NoSigRl;
  std::vector<uint8_t> bsn(1024 * 1024);
  uint8_t c = 0;
  for (int i = 0; i < 1024 * 1024; ++i) {
    bsn[i] = c++;
  }
  set_gid_hashalg(&pub_key.gid, kSha512);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigWithRandomBaseNameAllRlSha512) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& grp_rl = this->kGrpRl;
  auto& sig = this->kSplitSigGrpXMember3Sha512RndBsnTest1WithSigRl;
  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  std::vector<uint8_t> ver_rl = kGrpXBsn0Sha512VerRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha512);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid), kSha512);
  set_gid_hashalg(&pub_key.gid, kSha512);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest, VerifySplitAcceptsSigWithBaseNameAllRlSha512256) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& grp_rl = this->kGrpRl;
  auto& sig = this->kSplitSigGrpXMember3Sha512256Bsn0Msg0;

  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  std::vector<uint8_t> ver_rl = kGrpXBsn0Sha512256VerRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha512_256);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid),
                  kSha512_256);
  set_gid_hashalg(&(reinterpret_cast<VerifierRl*>(ver_rl.data())->gid),
                  kSha512_256);
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl const*)ver_rl.data(), ver_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigWithRandomBaseNameAllRlSha512256) {
  GroupPubKey pub_key = this->kGrpXKey;
  auto& msg = this->kTest1;
  auto& grp_rl = this->kGrpRl;
  auto& sig = this->kSplitSigGrpXMember3Sha512_256RndBsnTest1WithSigRl;
  std::vector<uint8_t> sig_rl = kSigRl5EntrySha256Data;
  std::vector<uint8_t> priv_rl = kGrpXPrivRl;
  set_gid_hashalg(&(reinterpret_cast<SigRl*>(sig_rl.data())->gid), kSha512_256);
  set_gid_hashalg(&(reinterpret_cast<PrivRl*>(priv_rl.data())->gid),
                  kSha512_256);
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetGroupRl(
      verifier, (GroupRl const*)grp_rl.data(), grp_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetPrivRl(
      verifier, (PrivRl const*)priv_rl.data(), priv_rl.size()));
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(verifier, (SigRl const*)sig_rl.data(),
                                        sig_rl.size()));

  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

TEST_F(EpidVerifierSplitTest,
       VerifySplitAcceptsSigGivenMsgContainingAllPossibleBytes) {
  auto& pub_key = this->kGrpXKey;
  auto& msg = this->kData_0_255;
  auto& bsn = this->kBsn0;
  auto& sig = this->kSplitSigGrpXMember3Sha256kBsn0Data_0_255NoSigRl;

  VerifierCtxObj verifier(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigValid,
            EpidVerifySplitSig(verifier, (EpidSplitSignature const*)sig.data(),
                               sig.size(), msg.data(), msg.size()));
}

}  // namespace
