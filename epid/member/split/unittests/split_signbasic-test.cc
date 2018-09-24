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
/// SignBasic unit tests.
/*! \file */

#include <cstring>
#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"
extern "C" {
#include "epid/common/src/sig_types.h"
#include "epid/member/split/src/signbasic.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/onetimepad.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

bool operator==(BigNumStr const& lhs, BigNumStr const& rhs);
bool operator==(FpElemStr const& lhs, FpElemStr const& rhs);

bool operator==(BasicSignature const& lhs, BasicSignature const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}
namespace {
/// A security parameter. In this version of Intel(R) EPID SDK, slen = 128
#define EPID_SLEN 128

void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

/// a data with bytes [0,255]
const std::vector<uint8_t> kData_0_255 = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
    0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
    0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
    0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
};

/// the message "msg0"
const std::vector<uint8_t> kMsg0 = {'m', 's', 'g', '0'};
/// the basename "bsn0"
const std::vector<uint8_t> kBsn0 = {'b', 's', 'n', '0'};
/// the message "test1"
const std::vector<uint8_t> kTest1Msg = {'t', 'e', 's', 't', '1'};
/// the basename "basename1"
const std::vector<uint8_t> kBasename1 = {'b', 'a', 's', 'e', 'n',
                                         'a', 'm', 'e', '1'};
const MemberPrecomp kMember3Sha256Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha256_01.inc"
};
const MemberPrecomp kMember3Sha512Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha512_01.inc"
};
const MemberPrecomp kMember3Sha384Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha384_01.inc"
};
const MemberPrecomp kMember3Sha512256Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha512_256_01.inc"
};
static const GroupPubKey kGrpXKey = {
#include "epid/common-testhelper/testdata/grp_x/pubkey.inc"
};
static const PrivKey kGrpXMember3Sha256PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha256_01.inc"
};
static const PrivKey kGrpXMember3Sha512PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha512_01.inc"
};
static const PrivKey kGrpXMember3Sha384PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha384_01.inc"
};
static const PrivKey kGrpXMember3Sha512256PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha512_256_01.inc"
};

const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256kData_0_255Msg0NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0255_msg0_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha512Basename1Test1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha512_basename1_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha384Basename1Test1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha384_basename1_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha512256Base1Test1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha512_256_basename1_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1EmptyNoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_empty_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseMlnNoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_million_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Bsn0Data_0_255NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0_msg0255_no_sigrl.inc"
};

const std::vector<uint8_t>
    kSplitSigGrpXMember0Sha512Bsn0Data_0_255NoSigRl_EPS0 = {
        // TODO(anyone): put correct expected_sig
};
const std::vector<uint8_t>
    kSplitSigGrpXMember0Sha512RandombaseMsg0NoSigRl_EPS0 = {
        // TODO(anyone): put correct expected_sig
};
const std::vector<uint8_t> kSplitSigGrpXMember0Sha256Bsn0Msg0NoSigRl_EPS0 = {
    // TODO(anyone): put correct expected_sig
};
const std::vector<uint8_t>
    kSplitSigGrpXMember0Sha512Data_0_255Msg0NoSigRl_EPS0 = {
        // TODO(anyone): put correct expected_sig
};
const std::vector<uint8_t> kSplitSigGrpXMember0Sha512Bsn0Msg0NoSigRl_EPS0 = {
    // TODO(anyone): put correct expected_sig
};

/// data for OneTimePad to be used in BasicSign: without rf and nonce
const std::vector<uint8_t> kOtpDataWithoutRfAndNonce = {
    // entropy of EpidMemberIsKeyValid
    // r in Tpm2Commit =
    // 0x531201cf42e8946136e516c3651a8b04c826283ab43829926e9277902962f15f
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x53, 0x12, 0x01, 0xcf, 0x42, 0xe8, 0x94, 0x61,
    0x36, 0xe5, 0x16, 0xc3, 0x65, 0x1a, 0x8b, 0x04, 0xc8, 0x26, 0x28, 0x3a,
    0xb4, 0x38, 0x29, 0x92, 0x6e, 0x92, 0x77, 0x90, 0x29, 0x62, 0xf1, 0x5f,
    // noncek =
    // 0xe95408071241a77b0871d175c90185241ed61b5a150793015c903154d2636773
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe9, 0x54, 0x08, 0x07, 0x12, 0x41, 0xa7, 0x7b,
    0x08, 0x71, 0xd1, 0x75, 0xc9, 0x01, 0x85, 0x24, 0x1e, 0xd6, 0x1b, 0x5a,
    0x15, 0x07, 0x93, 0x01, 0x5c, 0x90, 0x31, 0x54, 0xd2, 0x63, 0x67, 0x73,
    // entropy for other operations
    // bsn in presig
    0x25, 0xeb, 0x8c, 0x48, 0xff, 0x89, 0xcb, 0x85, 0x4f, 0xc0, 0x90, 0x81,
    0xcc, 0x47, 0xed, 0xfc, 0x86, 0x19, 0xb2, 0x14, 0xfe, 0x65, 0x92, 0xd4,
    0x8b, 0xfc, 0xea, 0x9c, 0x9d, 0x8e, 0x32, 0x44,
    // r in presig =
    // 0xcf8b90f4428aaf7e9b2244d1db16848230655550f2c52b1fc53b3031f8108bd4
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xcf, 0x8b, 0x90, 0xf4, 0x42, 0x8a, 0xaf, 0x7e,
    0x9b, 0x22, 0x44, 0xd1, 0xdb, 0x16, 0x84, 0x82, 0x30, 0x65, 0x55, 0x50,
    0xf2, 0xc5, 0x2b, 0x1f, 0xc5, 0x3b, 0x30, 0x31, 0xf8, 0x10, 0x8b, 0xd4,
    // a = 0xfb883ef100727d4e46e3e906b96e49c68b2abe1f44084cc0ed5c5ece66afa7e9
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfb, 0x88, 0x3e, 0xf1, 0x00, 0x72, 0x7d, 0x4e,
    0x46, 0xe3, 0xe9, 0x06, 0xb9, 0x6e, 0x49, 0xc6, 0x8b, 0x2a, 0xbe, 0x1f,
    0x44, 0x08, 0x4c, 0xc0, 0xed, 0x5c, 0x5e, 0xce, 0x66, 0xaf, 0xa7, 0xe8,
    // rx = 0xa1d62c80fcc1d60819271c86139880fabd27078b5dd9144c2f1dc6182fa24d4c
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa1, 0xd6, 0x2c, 0x80, 0xfc, 0xc1, 0xd6, 0x08,
    0x19, 0x27, 0x1c, 0x86, 0x13, 0x98, 0x80, 0xfa, 0xbd, 0x27, 0x07, 0x8b,
    0x5d, 0xd9, 0x14, 0x4c, 0x2f, 0x1d, 0xc6, 0x18, 0x2f, 0xa2, 0x4d, 0x4b,
    // rb = 0xf6910e4edc90439572c6a46852ec550adec1b1bfd3928996605e9aa6ff97c97c
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf6, 0x91, 0x0e, 0x4e, 0xdc, 0x90, 0x43, 0x95,
    0x72, 0xc6, 0xa4, 0x68, 0x52, 0xec, 0x55, 0x0a, 0xde, 0xc1, 0xb1, 0xbf,
    0xd3, 0x92, 0x89, 0x96, 0x60, 0x5e, 0x9a, 0xa6, 0xff, 0x97, 0xc9, 0x7b,
    // ra = 0x1e1e6372e53fb6a92763135b148310703e5649cfb7954d5d623aa4c1654d3147
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x1e, 0x1e, 0x63, 0x72, 0xe5, 0x3f, 0xb6, 0xa9,
    0x27, 0x63, 0x13, 0x5b, 0x14, 0x83, 0x10, 0x70, 0x3e, 0x56, 0x49, 0xcf,
    0xb7, 0x95, 0x4d, 0x5d, 0x62, 0x3a, 0xa4, 0xc1, 0x65, 0x4d, 0x31, 0x46};
/// data for OneTimePad to be used in BasicSign: rf in case bsn is passed
const std::vector<uint8_t> rf = {
    // rf = 0xb8b17a99305d417ee3a4fb67a60a41021a3730c05efac141d5a49b870d721d8b
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb8, 0xb1, 0x7a, 0x99, 0x30, 0x5d, 0x41, 0x7e,
    0xe3, 0xa4, 0xfb, 0x67, 0xa6, 0x0a, 0x41, 0x02, 0x1a, 0x37, 0x30, 0xc0,
    0x5e, 0xfa, 0xc1, 0x41, 0xd5, 0xa4, 0x9b, 0x87, 0x0d, 0x72, 0x1d, 0x8b};
/// data for OneTimePad to be used in BasicSign: noncek of split sign
const std::vector<uint8_t> kNoncek = {
    // noncek =
    // 0x19e236b64f315e832b5ac5b68fe75d4b7c0d5f52d6cd979f76d3e7d959627f2e
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0xe2, 0x36, 0xb6, 0x4f, 0x31, 0x5e, 0x83,
    0x2b, 0x5a, 0xc5, 0xb6, 0x8f, 0xe7, 0x5d, 0x4b, 0x7c, 0x0d, 0x5f, 0x52,
    0xd6, 0xcd, 0x97, 0x9f, 0x76, 0xd3, 0xe7, 0xd9, 0x59, 0x62, 0x7f, 0x2e};

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

// NOTE: Do not run these tests in TPM HW mode because some of the data is
// generated randomly inside TPM and will not match with precomputed data
#ifndef TPM_TSS
TEST_F(EpidMemberSplitSignTest,
       SignBasicDoesNotComputeRandomBasenameGivenBasename) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  BigNumStr rnd_bsn = {0};
  BigNumStr zero = {0};
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_EQ(zero, rnd_bsn);
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
/////////////////////////////////////////////////////////////////////////
// Variable basename
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingRandomBase) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  BigNumStr rnd_bsn = {0};
  BigNumStr zero = {0};
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_NE(0, memcmp(&rnd_bsn, &zero, sizeof(BigNumStr)));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}

TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingBasename) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}

TEST_F(EpidMemberSplitSignTest,
       SignBasicSucceedsUsingRandomBaseWithRegisteredBasenames) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  BigNumStr rnd_bsn = {0};
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest,
       SignBasicSucceedsUsingRandomBaseWithoutRegisteredBasenames) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  // otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  BigNumStr rnd_bsn = {0};
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest,
       SignBasicSucceedsUsingBsnContainingAllPossibleBytes) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  auto& bsn = kData_0_255;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256kData_0_255Msg0NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}

/////////////////////////////////////////////////////////////////////////
// Variable hash alg
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingSha512HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha512PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&mpriv_key.gid, kSha512);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, kMember3Sha512Precomp,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha512Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingSha384HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha384PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha384);
  set_gid_hashalg(&mpriv_key.gid, kSha384);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, kMember3Sha384Precomp,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha384Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingSha256HashAlg) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsUsingSha512256HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha512256PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  set_gid_hashalg(&mpriv_key.gid, kSha512_256);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, kMember3Sha512256Precomp,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha512256Base1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
/////////////////////////////////////////////////////////////////////////
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsWithPrecomputedSignatures) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 1));
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  BigNumStr rnd_bsn = {0};
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}

TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsWithoutPrecomputedSignatures) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  // double the entropy, except those, that are needed for key validation
  otp_data.insert(
      otp_data.end(),
      otp_data.begin() + 2 * (sizeof(BigNumStr) + EPID_SLEN / CHAR_BIT),
      otp_data.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 1));
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  ASSERT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  // test sign without precomputed signatures
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
/////////////////////////////////////////////////////////////////////////
// Variable messages
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsGivenEmptyMessage) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Basename1EmptyNoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), 0, bsn.data(), bsn.size(),
                               &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest, SignBasicSucceedsWithLongMessage) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256RandombaseMlnNoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  BigNumStr rnd_bsn = {0};
  std::vector<uint8_t> msg(1000000);  // allocate message for max size
  for (size_t n = 0; n < msg.size(); n++) {
    msg.at(n) = (uint8_t)n;
  }
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), nullptr, 0,
                               &basic_sig, &rnd_bsn, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
TEST_F(EpidMemberSplitSignTest,
       SignBasicSucceedsWithMsgContainingAllPossibleBytes) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kData_0_255;
  auto& bsn = kBsn0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  FpElemStr nonce_k;
  BasicSignature basic_sig;
  auto const& sig = (EpidSplitSignature const*)
                        kSplitSigGrpXMember3Sha256Bsn0Data_0_255NoSigRl.data();
  const BasicSignature expected_basic_sig = sig->sigma0;
  EXPECT_EQ(kEpidNoErr,
            EpidSplitSignBasic(member, msg.data(), msg.size(), bsn.data(),
                               bsn.size(), &basic_sig, nullptr, &nonce_k));
  EXPECT_EQ(expected_basic_sig, basic_sig);
  EXPECT_EQ(sig->nonce, nonce_k);
}
#endif  // TPM_TSS

}  // namespace
