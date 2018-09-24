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
 * \brief Split EpidBlacklistSig unit tests.
 */

#include <cstring>
#include <vector>

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/src/endian_convert.h"
#include "epid/verifier/api.h"
#include "epid/verifier/src/context.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/verifier/unittests/verifier-testhelper.h"
bool operator==(VerifierPrecomp const& lhs, VerifierPrecomp const& rhs);
bool operator==(G1ElemStr const& lhs, G1ElemStr const& rhs);
bool operator==(OctStr32 const& lhs, OctStr32 const& rhs);
namespace {
//////////////////////////////////////////////////////////////////////////
// EpidBlacklistSig
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsGivenNullPointer) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidBlacklistSig(nullptr, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadArgErr, EpidBlacklistSig(verifier, nullptr, sig.size(),
                                             msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             nullptr, 1));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsGivenInvalidSignatureLength) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), 0,
                             msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                             sig.size() - 1, msg.data(), msg.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                             sig.size() + 1, msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsGivenSigFromDiffGroup) {
  VerifierCtxObj verifier(this->kGrp01Key);
  auto sig = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto msg = this->kTest1;
  auto bsn = this->kBasename1;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsGivenSigFromDiffBasename) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBasename1;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsGivenSigWithDiffHashAlg) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha384Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigInvalid,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsOnSigAlreadyInVerRl) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXVerRevokedMember0Sha256Bsn0Msg0NoSigRl;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  auto ver_rl = this->kGrpXBsn0VerRlSingleEntry;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(EpidVerifierSetVerifierRl(
      verifier, (VerifierRl*)ver_rl.data(), ver_rl.size()));
  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsOnSigRevokedInSigRl) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0SingleEntrySigRl;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  auto sig_rl = this->kSplitSigGrpXMember3Sha256Bsn0Msg0OnlyEntry;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(
      EpidVerifierSetSigRl(verifier, (SigRl*)sig_rl.data(), sig_rl.size()));
  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigFailsOnSigRevokedInPrivRl) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXRevokedPrivKey000Sha256Bsn0Msg0NoSigRl;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  auto priv_rl = this->kGrpXPrivRl;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  THROW_ON_EPIDERR(
      EpidVerifierSetPrivRl(verifier, (PrivRl*)priv_rl.data(), priv_rl.size()));
  EXPECT_EQ(kEpidSigRevokedInPrivRl,
            EpidBlacklistSig(verifier, (EpidSignature*)sig.data(), sig.size(),
                             msg.data(), msg.size()));
}
TEST_F(EpidVerifierSplitTest, BlacklistSigWorksForValidSigGivenEmptyBlacklist) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                                         sig.size(), msg.data(), msg.size()));

  std::vector<uint8_t> ver_rl_vec(EpidGetVerifierRlSize(verifier));
  VerifierRl* ver_rl = (VerifierRl*)ver_rl_vec.data();
  size_t ver_rl_size = ver_rl_vec.size();

  THROW_ON_EPIDERR(EpidWriteVerifierRl(verifier, ver_rl, ver_rl_size));

  OctStr32 n4_expected = {0x00, 0x00, 0x00, 0x01};
  OctStr32 rlver_expected = {0x00, 0x00, 0x00, 0x01};
  EXPECT_EQ(n4_expected, ver_rl->n4);
  EXPECT_EQ(rlver_expected, ver_rl->version);
  EXPECT_EQ(((EpidSplitSignature*)sig.data())->sigma0.K,
            ver_rl->K[ntohl(n4_expected) - 1]);
}
TEST_F(EpidVerifierSplitTest,
       MultipleBlacklistFollowedBySerializeIncrementsRlVersionByOne) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256Bsn0Msg0;
  auto msg = this->kMsg0;
  auto bsn = this->kBsn0;
  auto sig2 = this->kSplitSigGrpXMember4Sha256Bsn0Msg0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                                         sig.size(), msg.data(), msg.size()));
  std::vector<uint8_t> ver_rl_vec(EpidGetVerifierRlSize(verifier));
  VerifierRl* ver_rl = (VerifierRl*)ver_rl_vec.data();
  size_t ver_rl_size = ver_rl_vec.size();
  THROW_ON_EPIDERR(EpidWriteVerifierRl(verifier, ver_rl, ver_rl_size));
  OctStr32 n4_expected = {0x00, 0x00, 0x00, 0x01};
  OctStr32 rlver_expected = {0x00, 0x00, 0x00, 0x01};
  EXPECT_EQ(n4_expected, ver_rl->n4);
  EXPECT_EQ(rlver_expected, ver_rl->version);
  EXPECT_EQ(((EpidSplitSignature*)sig.data())->sigma0.K,
            ver_rl->K[ntohl(n4_expected) - 1]);
  EXPECT_EQ(kEpidNoErr, EpidBlacklistSig(verifier, (EpidSignature*)sig2.data(),
                                         sig2.size(), msg.data(), msg.size()));
  std::vector<uint8_t> ver_rl_vec2(EpidGetVerifierRlSize(verifier));
  VerifierRl* ver_rl2 = (VerifierRl*)ver_rl_vec2.data();
  size_t ver_rl_size2 = ver_rl_vec2.size();

  THROW_ON_EPIDERR(EpidWriteVerifierRl(verifier, ver_rl2, ver_rl_size2));

  n4_expected.data[sizeof(n4_expected) - 1] = 0x02;
  EXPECT_EQ(n4_expected, ver_rl2->n4);
  EXPECT_EQ(rlver_expected, ver_rl2->version);
  EXPECT_EQ(((EpidSplitSignature*)sig2.data())->sigma0.K,
            ver_rl2->K[ntohl(n4_expected) - 1]);
}
TEST_F(EpidVerifierSplitTest,
       BlacklistSigWorksForMsgContainingAllPossibleBytes) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256kBsn0Data_0_255NoSigRl;
  auto msg = this->kData_0_255;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                                         sig.size(), msg.data(), msg.size()));

  std::vector<uint8_t> ver_rl_vec(EpidGetVerifierRlSize(verifier));
  VerifierRl* ver_rl = (VerifierRl*)ver_rl_vec.data();
  size_t ver_rl_size = ver_rl_vec.size();

  THROW_ON_EPIDERR(EpidWriteVerifierRl(verifier, ver_rl, ver_rl_size));

  OctStr32 n4_expected = {0x00, 0x00, 0x00, 0x01};
  OctStr32 rlver_expected = {0x00, 0x00, 0x00, 0x01};
  EXPECT_EQ(n4_expected, ver_rl->n4);
  EXPECT_EQ(rlver_expected, ver_rl->version);
  EXPECT_EQ(((EpidSplitSignature*)sig.data())->sigma0.K,
            ver_rl->K[ntohl(n4_expected) - 1]);
}
TEST_F(EpidVerifierSplitTest,
       VerifyReturnsSigRevokedInVerifierRlAfterBlacklistSig) {
  VerifierCtxObj verifier(this->kGrpXKey);
  auto sig = this->kSplitSigGrpXMember3Sha256kBsn0Data_0_255NoSigRl;
  auto msg = this->kData_0_255;
  auto bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidVerifierSetBasename(verifier, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidBlacklistSig(verifier, (EpidSignature*)sig.data(),
                                         sig.size(), msg.data(), msg.size()));
  EXPECT_EQ(kEpidSigRevokedInVerifierRl,
            EpidVerify(verifier, (EpidSignature const*)sig.data(), sig.size(),
                       msg.data(), msg.size()));
}
}  // namespace
