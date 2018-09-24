/*############################################################################
  # Copyright 2016-2018 Intel Corporation
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
/// SignBasic unit tests.
/*! \file */

#include <cstring>
#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/member/api.h"
#include "epid/member/split/src/signbasic.h"
#include "epid/verifier/api.h"
#include "epid/verifier/src/verifybasic.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

bool operator==(BigNumStr const& lhs, BigNumStr const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}
namespace {

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

/////////////////////////////////////////////////////////////////////////
// Simple error cases
TEST_F(EpidSplitMemberTest, SignBasicFailsGivenNullParameters) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  FpElemStr nonce = {0};
  BasicSignature basic_sig;
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(nullptr, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), nullptr, nullptr, &nonce));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, nullptr, msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr,
                               bsn.size(), &basic_sig, nullptr, &nonce));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, nullptr));
}
TEST_F(EpidSplitMemberTest,
       SignBasicFailsGivenNullBasenameAndNullRandomBasename) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  FpElemStr nonce = {0};
  BasicSignature basic_sig;
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, nullptr, &nonce));
}

TEST_F(EpidSplitMemberTest,
       SignBasicFailsForBasenameWithoutRegisteredBasenames) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  BasicSignature basic_sig;
  FpElemStr nonce = {0};
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce));
}
TEST_F(EpidSplitMemberTest, SignBasicFailsForUnregisteredBasename) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn0 = this->kBsn0;
  auto& bsn1 = this->kBsn1;
  FpElemStr nonce = {0};
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn0.data(), bsn0.size()));
  BasicSignature basic_sig;
  EXPECT_EQ(kEpidBadArgErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn1.data(),
                               bsn1.size(), &basic_sig, nullptr, &nonce));
}
/////////////////////////////////////////////////////////////////////////
// Anonymity
TEST_F(EpidSplitMemberTest, BasicSignaturesOfSameMessageAreDifferent) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  BasicSignature basic_sig1 = {0};
  BasicSignature basic_sig2 = {0};
  BigNumStr rnd_bsn = {0};
  FpElemStr nonce = {0};
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig1, &rnd_bsn, &nonce));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig2, &rnd_bsn, &nonce));
  EXPECT_NE(0, memcmp(&basic_sig1, &basic_sig2, sizeof(BasicSignature)));
}
TEST_F(EpidSplitMemberTest,
       BasicSignaturesOfSameMessageWithSameBasenameAreDifferent) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  BasicSignature basic_sig1;
  BasicSignature basic_sig2;
  FpElemStr nonce = {0};
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig1, nullptr, &nonce));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig2, nullptr, &nonce));
  EXPECT_NE(0, memcmp(&basic_sig1, &basic_sig2, sizeof(BasicSignature)));
}
/////////////////////////////////////////////////////////////////////////
// Variable basename
TEST_F(EpidSplitMemberTest,
       PROTECTED_SignBasicSucceedsAllPossibleBytesForCredential_EPS0) {
  Prng my_prng;
  MemberCtxObj member(
      this->kEps0GroupPublicKey,
      *(MembershipCredential const*)&this->kEps0MemberPrivateKey,
      &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kData_0_255;
  FpElemStr nonce = {0};
  // 0 - 123
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), 124));
  BasicSignature basic_sig;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(), 124,
                               &basic_sig, nullptr, &nonce));
  VerifierCtxObj ctx1(this->kEps0GroupPublicKey);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(ctx1, bsn.data(), 124));
  EXPECT_EQ(kEpidSigValid, EpidVerifyBasicSplitSig(ctx1, &basic_sig, &nonce,
                                                   msg.data(), msg.size()));

  // 124 - 247
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data() + 124, 124));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data() + 124,
                               124, &basic_sig, nullptr, &nonce));
  VerifierCtxObj ctx2(this->kEps0GroupPublicKey);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(ctx2, bsn.data() + 124, 124));
  EXPECT_EQ(kEpidSigValid, EpidVerifyBasicSplitSig(ctx2, &basic_sig, &nonce,
                                                   msg.data(), msg.size()));

  // 248 - 255
  THROW_ON_EPIDERR(
      EpidRegisterBasename(member, bsn.data() + 124 * 2, 256 - 124 * 2));
  EXPECT_EQ(kEpidNoErr, EpidSplitSignBasic(member, msg.data(), msg.size(),
                                           bsn.data() + 124 * 2, 256 - 124 * 2,
                                           &basic_sig, nullptr, &nonce));
  VerifierCtxObj ctx3(this->kEps0GroupPublicKey);
  THROW_ON_EPIDERR(
      EpidVerifierSetBasename(ctx3, bsn.data() + 124 * 2, 256 - 124 * 2));
  EXPECT_EQ(kEpidSigValid, EpidVerifyBasicSplitSig(ctx3, &basic_sig, &nonce,
                                                   msg.data(), msg.size()));
}
/////////////////////////////////////////////////////////////////////////
// Variable hash alg
/////////////////////////////////////////////////////////////////////////
TEST_F(EpidSplitMemberTest, SignBasicConsumesPrecomputedSignatures) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 3));
  auto& msg = this->kMsg0;
  BasicSignature basic_sig;
  auto& bsn = this->kBsn0;
  FpElemStr nonce = {0};
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  // use 1 precomputed signature
  ASSERT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce));
  EXPECT_EQ((size_t)2, EpidGetNumPreSigs(member));
}

TEST_F(EpidSplitMemberTest,
       PROTECTED_SignBasicSucceedsUsingRndBasePrecompSigWithCredential_EPS0) {
  Prng my_prng;
  MemberCtxObj member(
      this->kEps0GroupPublicKey,
      *(MembershipCredential const*)&this->kEps0MemberPrivateKey,
      &Prng::Generate, &my_prng);

  THROW_ON_EPIDERR(EpidAddPreSigs(member, 1));

  auto& msg = this->kMsg0;

  BasicSignature basic_sig;
  BigNumStr rnd_bsn = {0};
  FpElemStr nonce = {0};

  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce));

  VerifierCtxObj ctx(this->kEps0GroupPublicKey);
  EXPECT_EQ(kEpidSigValid, EpidVerifyBasicSplitSig(ctx, &basic_sig, &nonce,
                                                   msg.data(), msg.size()));
}

/////////////////////////////////////////////////////////////////////////
// Variable messages
TEST_F(EpidSplitMemberTest,
       PROTECTED_SignBasicSucceedsMsgAllPossibleBytesForCredential_EPS0) {
  Prng my_prng;
  MemberCtxObj member(
      this->kEps0GroupPublicKey,
      *(MembershipCredential const*)&this->kEps0MemberPrivateKey,
      &Prng::Generate, &my_prng);
  auto& msg = this->kData_0_255;
  auto& bsn = this->kBsn0;
  BasicSignature basic_sig;
  FpElemStr nonce = {0};
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce));
  VerifierCtxObj ctx(this->kEps0GroupPublicKey);
  THROW_ON_EPIDERR(EpidVerifierSetBasename(ctx, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidSigValid, EpidVerifyBasicSplitSig(ctx, &basic_sig, &nonce,
                                                   msg.data(), msg.size()));
}
}  // namespace
