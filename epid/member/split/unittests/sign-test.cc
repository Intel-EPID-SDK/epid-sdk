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
/// Sign unit tests.
/*! \file */
#include <vector>

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/member/api.h"
#include "epid/member/split/src/context.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"
namespace {

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

/////////////////////////////////////////////////////////////////////////
// Simple error cases

TEST_F(EpidSplitMemberTest, SignFailsGivenNullParameters) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  std::vector<uint8_t> sig(EpidGetSigSize(&srl));
  THROW_ON_EPIDERR(
      EpidMemberSetSigRl(member, &srl, sizeof(srl) - sizeof(srl.bk)));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(nullptr, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig.data(), sig.size()));
  EXPECT_EQ(kEpidBadArgErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                     bsn.size(), nullptr, sig.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(member, nullptr, msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig.data(), sig.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, bsn.size(),
                     (EpidSignature*)sig.data(), sig.size()));
}

TEST_F(EpidSplitMemberTest, SignFailsGivenWrongSigLen) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  THROW_ON_EPIDERR(
      EpidMemberSetSigRl(member, &srl, sizeof(srl) - sizeof(srl.bk)));

  // signature buffer one byte less than needed
  std::vector<uint8_t> sig_small(EpidGetSigSize(&srl) - 1);
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig_small.data(), sig_small.size()));

  // signature buffer is one byte - a less than allowed for EpidSignature
  std::vector<uint8_t> sig_one(1);
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig_one.data(), sig_one.size()));
}

TEST_F(EpidSplitMemberTest, SignFailsGivenUnregisteredBasename) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  auto& bsn1 = this->kBsn1;
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  std::vector<uint8_t> sig(EpidGetSigSize(&srl));
  THROW_ON_EPIDERR(
      EpidMemberSetSigRl(member, &srl, sizeof(srl) - sizeof(srl.bk)));
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidSign(member, msg.data(), msg.size(), bsn1.data(), bsn1.size(),
                     (EpidSignature*)sig.data(), sig.size()));
}
TEST_F(EpidSplitMemberTest, SignsFailsIfNotProvisioned) {
  Prng my_prng;
  MemberCtxObj member(&Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  EXPECT_EQ(kEpidOutOfSequenceError,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
}

/////////////////////////////////////////////////////////////////////////
// Anonymity

TEST_F(EpidSplitMemberTest, SignaturesOfSameMessageAreDifferent) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig1(EpidGetSigSize(nullptr));
  std::vector<uint8_t> sig2(EpidGetSigSize(nullptr));
  // without signature based revocation list
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), nullptr, 0,
                                 (EpidSignature*)sig1.data(), sig1.size()));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), nullptr, 0,
                                 (EpidSignature*)sig2.data(), sig2.size()));
  EXPECT_TRUE(sig1.size() == sig2.size() &&
              0 != memcmp(sig1.data(), sig2.data(), sig1.size()));
  // with signature based revocation list
  uint8_t sig_rl_data_n2_one[] = {
      // gid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xee,
      // version
      0x00, 0x00, 0x00, 0x00,
      // n2
      0x0, 0x00, 0x00, 0x01,
      // one bk
      0x9c, 0xa5, 0xe5, 0xae, 0x5f, 0xae, 0x51, 0x59, 0x33, 0x35, 0x27, 0xd,
      0x8, 0xb1, 0xbe, 0x5d, 0x69, 0x50, 0x84, 0xc5, 0xfe, 0xe2, 0x87, 0xea,
      0x2e, 0xef, 0xfa, 0xee, 0x67, 0xf2, 0xd8, 0x28, 0x56, 0x43, 0xc6, 0x94,
      0x67, 0xa6, 0x72, 0xf6, 0x41, 0x15, 0x4, 0x58, 0x42, 0x16, 0x88, 0x57,
      0x9d, 0xc7, 0x71, 0xd1, 0xc, 0x84, 0x13, 0xa, 0x90, 0x23, 0x18, 0x8, 0xad,
      0x7d, 0xfe, 0xf5, 0xc8, 0xae, 0xfc, 0x51, 0x40, 0xa7, 0xd1, 0x28, 0xc2,
      0x89, 0xb2, 0x6b, 0x4e, 0xb4, 0xc1, 0x55, 0x87, 0x98, 0xbd, 0x72, 0xf9,
      0xcf, 0xd, 0x40, 0x15, 0xee, 0x32, 0xc, 0xf3, 0x56, 0xc5, 0xc, 0x61, 0x9d,
      0x4f, 0x7a, 0xb5, 0x2b, 0x16, 0xa9, 0xa3, 0x97, 0x38, 0xe2, 0xdd, 0x3a,
      0x33, 0xad, 0xf6, 0x7b, 0x68, 0x8b, 0x68, 0xcf, 0xa3, 0xd3, 0x98, 0x37,
      0xce, 0xec, 0xd1, 0xa8, 0xc, 0x8b};
  SigRl* srl1 = reinterpret_cast<SigRl*>(sig_rl_data_n2_one);
  size_t srl1_size = sizeof(sig_rl_data_n2_one);
  std::vector<uint8_t> sig3(EpidGetSigSize(srl1));
  std::vector<uint8_t> sig4(EpidGetSigSize(srl1));
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl1, srl1_size));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), nullptr, 0,
                                 (EpidSignature*)sig3.data(), sig3.size()));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), nullptr, 0,
                                 (EpidSignature*)sig4.data(), sig4.size()));
  EXPECT_TRUE(sig3.size() == sig4.size() &&
              0 != memcmp(sig3.data(), sig4.data(), sig3.size()));
}
TEST_F(EpidSplitMemberTest,
       SignaturesOfSameMessageWithSameBasenameAreDifferent) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  std::vector<uint8_t> sig1(EpidGetSigSize(nullptr));
  std::vector<uint8_t> sig2(EpidGetSigSize(nullptr));
  // without signature based revocation list
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig1.data(), sig1.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig2.data(), sig2.size()));
  EXPECT_TRUE(sig1.size() == sig2.size() &&
              0 != memcmp(sig1.data(), sig2.data(), sig1.size()));

  // with signature based revocation list
  uint8_t sig_rl_data_n2_one[] = {
      // gid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xee,
      // version
      0x00, 0x00, 0x00, 0x00,
      // n2
      0x0, 0x00, 0x00, 0x01,
      // one bk
      0x9c, 0xa5, 0xe5, 0xae, 0x5f, 0xae, 0x51, 0x59, 0x33, 0x35, 0x27, 0xd,
      0x8, 0xb1, 0xbe, 0x5d, 0x69, 0x50, 0x84, 0xc5, 0xfe, 0xe2, 0x87, 0xea,
      0x2e, 0xef, 0xfa, 0xee, 0x67, 0xf2, 0xd8, 0x28, 0x56, 0x43, 0xc6, 0x94,
      0x67, 0xa6, 0x72, 0xf6, 0x41, 0x15, 0x4, 0x58, 0x42, 0x16, 0x88, 0x57,
      0x9d, 0xc7, 0x71, 0xd1, 0xc, 0x84, 0x13, 0xa, 0x90, 0x23, 0x18, 0x8, 0xad,
      0x7d, 0xfe, 0xf5, 0xc8, 0xae, 0xfc, 0x51, 0x40, 0xa7, 0xd1, 0x28, 0xc2,
      0x89, 0xb2, 0x6b, 0x4e, 0xb4, 0xc1, 0x55, 0x87, 0x98, 0xbd, 0x72, 0xf9,
      0xcf, 0xd, 0x40, 0x15, 0xee, 0x32, 0xc, 0xf3, 0x56, 0xc5, 0xc, 0x61, 0x9d,
      0x4f, 0x7a, 0xb5, 0x2b, 0x16, 0xa9, 0xa3, 0x97, 0x38, 0xe2, 0xdd, 0x3a,
      0x33, 0xad, 0xf6, 0x7b, 0x68, 0x8b, 0x68, 0xcf, 0xa3, 0xd3, 0x98, 0x37,
      0xce, 0xec, 0xd1, 0xa8, 0xc, 0x8b};
  SigRl* srl1 = reinterpret_cast<SigRl*>(sig_rl_data_n2_one);
  size_t srl1_size = sizeof(sig_rl_data_n2_one);
  std::vector<uint8_t> sig3(EpidGetSigSize(srl1));
  std::vector<uint8_t> sig4(EpidGetSigSize(srl1));
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl1, srl1_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig3.data(), sig3.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     (EpidSignature*)sig4.data(), sig4.size()));
  EXPECT_TRUE(sig3.size() == sig4.size() &&
              0 != memcmp(sig3.data(), sig4.data(), sig3.size()));
}

/////////////////////////////////////////////////////////////////////////
// Variable basename

/////////////////////////////////////////////////////////////////////////
// Variable sigRL

/////////////////////////////////////////////////////////////////////////
// Revoked member by sigRL for TPM case

/////////////////////////////////////////////////////////////////////////
// Variable hash alg

/////////////////////////////////////////////////////////////////////////
// Variable precomputed signatures

TEST_F(EpidSplitMemberTest, SignConsumesPrecomputedSignaturesNoSigRl) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 3));
  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ((size_t)2, EpidGetNumPreSigs(member));
}

TEST_F(EpidSplitMemberTest, SignConsumesPrecomputedSignaturesWithSigRl) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 3));
  auto& msg = this->kMsg0;
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(this->kSigRl5EntrySha256Data.data());
  size_t srl_size = this->kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ((size_t)2, EpidGetNumPreSigs(member));
}

/////////////////////////////////////////////////////////////////////////
// Variable messages

}  // namespace
