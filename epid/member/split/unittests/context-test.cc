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
 * \brief Member unit tests.
 */
#include <cstring>
#include <vector>
#include "common/endian_convert.h"
#include "gtest/gtest.h"
#include "member-testhelper.h"
#include "testhelper/epid2params_wrapper-testhelper.h"
#include "testhelper/epid_gtest-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/onetimepad.h"
#include "testhelper/prng-testhelper.h"
#include "tpm2-testhelper.h"

extern "C" {
#include "epid/member/api.h"
#include "epid/member/split/context.h"
#include "epid/member/split/split_grouppubkey.h"
#include "epid/member/split/storage.h"
#include "epid/member/split/tpm2/nv.h"
}
/// compares GroupPubKey values
bool operator==(GroupPubKey const& lhs, GroupPubKey const& rhs);

/// compares MembershipCredential values
bool operator==(MembershipCredential const& lhs,
                MembershipCredential const& rhs);
namespace {
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
    0x5e, 0xfa, 0xc1, 0x41, 0xd5, 0xa4, 0x9b, 0x87, 0x0d, 0x72, 0x1d, 0x8b,
};
// entropy for EpidNrProve
const std::vector<uint8_t> NrProveEntropy = {
    // mu
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x9e, 0x7d, 0x36, 0x67, 0x24, 0x65, 0x9e, 0xf5,
    0x7b, 0x34, 0x2c, 0x42, 0x71, 0x4b, 0xb2, 0x58, 0xcd, 0x3d, 0x94, 0xe9,
    0x35, 0xe7, 0x37, 0x0a, 0x58, 0x32, 0xb6, 0xa5, 0x9d, 0xbf, 0xe4, 0xcb,
    // r in Tpm2Commit in PrivateExp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x90, 0x28, 0x6d, 0x75, 0xd5, 0x44, 0x60, 0x47,
    0xe0, 0x4c, 0xf9, 0x23, 0xd2, 0x51, 0x6c, 0xca, 0xf2, 0xad, 0xd7, 0x50,
    0xd9, 0x59, 0x7d, 0x19, 0x1c, 0x53, 0x93, 0xc3, 0x75, 0x8b, 0x83, 0x6b,
    // noncek in Tpm2Sign in PrivateExp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x82, 0x05, 0x02, 0x51, 0x5d, 0xdf, 0xa9, 0x33,
    0xce, 0x98, 0x8e, 0x95, 0xf0, 0xb5, 0x79, 0x99, 0xfe, 0xf4, 0x95, 0x33,
    0xa9, 0x23, 0x7a, 0x67, 0x60, 0xf6, 0x32, 0x5d, 0xbd, 0xfb, 0x89, 0xfa,
    // rmu
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb4, 0x5f, 0x9c, 0x41, 0x89, 0x3c, 0xe3, 0x30,
    0x54, 0xeb, 0xa2, 0x22, 0x1b, 0x2b, 0xc4, 0xcd, 0x8f, 0x7b, 0xc8, 0xb1,
    0x1b, 0xca, 0x6f, 0x68, 0xd4, 0x9f, 0x27, 0xd9, 0xc1, 0xe5, 0xc7, 0x6d,
    // r in Tpm2Commit
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x5a, 0x1e, 0x86, 0x82, 0x29, 0x90, 0x2d, 0x57,
    0x46, 0x57, 0xa8, 0x0c, 0x73, 0xe7, 0xd4, 0xaa, 0x01, 0x11, 0x11, 0xde,
    0xd6, 0x1a, 0x58, 0x21, 0x62, 0x80, 0x2f, 0x25, 0x68, 0x23, 0xbd, 0x04,
    // noncek
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xac, 0x72, 0x37, 0x44, 0xe6, 0x90, 0x30, 0x5f,
    0x17, 0xf5, 0xf5, 0xf1, 0x9e, 0x81, 0xa9, 0x81, 0x2c, 0x7a, 0xa7, 0x37,
    0x52, 0xf6, 0x0e, 0xd3, 0xaa, 0x6c, 0x9f, 0x46, 0xf7, 0x3b, 0x2d, 0x52};
/// data for OneTimePad to be used in BasicSign: noncek of split sign
const std::vector<uint8_t> kNoncek = {
    // noncek =
    // 0x19e236b64f315e832b5ac5b68fe75d4b7c0d5f52d6cd979f76d3e7d959627f2e
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0xe2, 0x36, 0xb6, 0x4f, 0x31, 0x5e, 0x83,
    0x2b, 0x5a, 0xc5, 0xb6, 0x8f, 0xe7, 0x5d, 0x4b, 0x7c, 0x0d, 0x5f, 0x52,
    0xd6, 0xcd, 0x97, 0x9f, 0x76, 0xd3, 0xe7, 0xd9, 0x59, 0x62, 0x7f, 0x2e,
};
//////////////////////////////////////////////////////////////////////////
// EpidMemberDeinit Tests
TEST_F(EpidSplitMemberTest, DeinitWorksGivenNullMemberCtx) {
  EpidMemberDeinit(nullptr);
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberGetSize Tests
TEST_F(EpidSplitMemberTest, GetSizeFailsGivenNullParams) {
  size_t ctx_size = 0;
  MemberParams params = {0};
  EXPECT_EQ(kEpidBadArgErr, EpidMemberGetSize(&params, nullptr));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberGetSize(nullptr, &ctx_size));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberGetSize(nullptr, nullptr));
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberGetSize Tests
TEST_F(EpidSplitMemberTest, GetSizeWorksGivenValidParams) {
  size_t ctx_size = 0;
  Prng my_prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberGetSize(&params, &ctx_size));
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberInit Tests
TEST_F(EpidSplitMemberTest, InitFailsGivenNullParameters) {
  size_t ctx_size = 0;
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  std::vector<uint8_t> ctx_buf;
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberGetSize(&params, &ctx_size));
  ctx_buf.resize(ctx_size);
  ctx = (MemberCtx*)&ctx_buf[0];

  EXPECT_EQ(kEpidBadArgErr, EpidMemberInit(nullptr, nullptr));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberInit(&params, nullptr));
  EXPECT_EQ(kEpidBadArgErr, EpidMemberInit(nullptr, ctx));
}

TEST_F(EpidSplitMemberTest, InitFailsGivenInvalidParameters) {
  FpElemStr f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  size_t ctx_size = 0;
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  std::vector<uint8_t> ctx_buf;
  SetMemberParams(&Prng::Generate, &my_prng, &f, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberGetSize(&params, &ctx_size));
  ctx_buf.resize(ctx_size);
  ctx = (MemberCtx*)&ctx_buf[0];

  EXPECT_EQ(kEpidBadArgErr, EpidMemberInit(&params, ctx));
}

TEST_F(EpidSplitMemberTest, InitSucceedsGivenValidParameters) {
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  size_t ctx_size = 0;
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  std::vector<uint8_t> ctx_buf;
  SetMemberParams(&Prng::Generate, &my_prng, &f, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberGetSize(&params, &ctx_size));
  ctx_buf.resize(ctx_size);
  ctx = (MemberCtx*)&ctx_buf[0];

  EXPECT_EQ(kEpidNoErr, EpidMemberInit(&params, ctx));
  EpidMemberDeinit(ctx);
}

TEST_F(EpidSplitMemberTest, InitSucceedsGivenValidParametersWithNoF) {
  size_t ctx_size = 0;
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  std::vector<uint8_t> ctx_buf;
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberGetSize(&params, &ctx_size));
  ctx_buf.resize(ctx_size);
  ctx = (MemberCtx*)&ctx_buf[0];

  EXPECT_EQ(kEpidNoErr, EpidMemberInit(&params, ctx));
  EpidMemberDeinit(ctx);
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberDelete Tests
TEST_F(EpidSplitMemberTest, DeleteWorksGivenNullMemberCtx) {
  EpidMemberDelete(nullptr);
  MemberCtx* member_ctx = nullptr;
  EpidMemberDelete(&member_ctx);
}
TEST_F(EpidSplitMemberTest, DeleteNullsMemberCtx) {
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  THROW_ON_EPIDERR(EpidMemberCreate(&params, &ctx));
  EpidMemberDelete(&ctx);
  EXPECT_EQ(nullptr, ctx);
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberCreate Tests
// test that create fails if any mandatory parameters are NULL
TEST_F(EpidSplitMemberTest, CreateFailsGivenNullParameters) {
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  EXPECT_EQ(kEpidBadArgErr, EpidMemberCreate(nullptr, &ctx));

  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidBadArgErr, EpidMemberCreate(&params, nullptr));

  SetMemberParams(nullptr, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidBadArgErr, EpidMemberCreate(&params, nullptr));
}

TEST_F(EpidSplitMemberTest, CreateFailsGivenInvalidParameters) {
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  FpElemStr f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  SetMemberParams(&Prng::Generate, &my_prng, &f, &params);
  EXPECT_EQ(kEpidBadArgErr, EpidMemberCreate(&params, &ctx));
  EpidMemberDelete(&ctx);
}

TEST_F(EpidSplitMemberTest, CreateSucceedsGivenValidParameters) {
  MemberCtx* ctx = nullptr;
  Prng my_prng;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, nullptr, &params);
  EXPECT_EQ(kEpidNoErr, EpidMemberCreate(&params, &ctx));
  EpidMemberDelete(&ctx);
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberStartup
TEST_F(EpidSplitMemberTest, StartupFailsGivenNullParameters) {
  EXPECT_EQ(kEpidBadArgErr, EpidMemberStartup(nullptr));
}

TEST_F(EpidSplitMemberTest, StartupSucceedsGivenValidParameters) {
  Prng prng;
  GroupPubKey pub_key = this->kGrpXKey;
  GroupPubKey split_pub_key_expected = {0};
  PrivKey priv_key = this->kGrpXMember3PrivKeySha256;
  MemberParams params = {0};
  MemberCtx* ctx = nullptr;
  Epid2ParamsObj epid2params;
  SetMemberParams(&Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  ctx = member;
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &pub_key, &priv_key, nullptr));
  MembershipCredential credential_expected = ctx->credential;
  EXPECT_EQ(kEpidNoErr,
            EpidComputeSplitGroupPubKey(epid2params.G1(), &pub_key, kSha256,
                                        &split_pub_key_expected));

  // reset member credential to test if startup reads them from NV memory
  // correctly
  ctx->pub_key = {0};
  ctx->credential = {0};
  EXPECT_EQ(kEpidNoErr, EpidMemberStartup(member));
  EXPECT_EQ(split_pub_key_expected, ctx->pub_key);
  EXPECT_EQ(credential_expected, ctx->credential);
}

//////////////////////////////////////////////////////////////////////////
// EpidMemberSetHashAlg
TEST_F(EpidSplitMemberTest, SetHashAlgFailsGivenNullPtr) {
  EXPECT_EQ(kEpidBadArgErr, EpidMemberSetHashAlg(nullptr, kSha256));
}
TEST_F(EpidSplitMemberTest, SetHashAlgSucceedsForTheSameHashAsInGroupId) {
  Prng my_prng;
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 0x00;  // set sha256
  MemberCtxObj member(pub_key, this->kGrpXMember3PrivKeySha256, &Prng::Generate,
                      &my_prng);
  EXPECT_EQ(kEpidNoErr, EpidMemberSetHashAlg(member, kSha256));
}
TEST_F(EpidSplitMemberTest,
       SetHashAlgFailsIfHashAlgIsDifferentFromOneDerivedFromGid) {
  Prng my_prng;
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] = 0x00;  // set sha256
  MemberCtxObj member(pub_key, this->kGrpXMember3PrivKeySha256, &Prng::Generate,
                      &my_prng);
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha384));
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha512));
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha512_256));
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha3_256));
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha3_384));
  EXPECT_EQ(kEpidOperationNotSupportedErr,
            EpidMemberSetHashAlg(member, kSha3_512));
}
//////////////////////////////////////////////////////////////////////////
// EpidMemberSetSigRl
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenNullPointer) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  EXPECT_EQ(kEpidBadArgErr, EpidMemberSetSigRl(nullptr, &srl, sizeof(SigRl)));
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberSetSigRl(member_ctx, nullptr, sizeof(SigRl)));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenZeroSize) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  EXPECT_EQ(kEpidBadArgErr, EpidMemberSetSigRl(member_ctx, &srl, 0));
}
// Size parameter must be at least big enough for n2 == 0 case
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenTooSmallSize) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidMemberSetSigRl(member_ctx, &srl, (sizeof(srl) - sizeof(srl.bk)) - 1));
  srl.n2 = this->kOctStr32_1;
  EXPECT_EQ(
      kEpidBadArgErr,
      EpidMemberSetSigRl(member_ctx, &srl, (sizeof(srl) - sizeof(srl.bk)) - 1));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenN2TooBigForSize) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  srl.n2 = this->kOctStr32_1;
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberSetSigRl(member_ctx, &srl, sizeof(srl) - sizeof(srl.bk)));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenN2TooSmallForSize) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  EXPECT_EQ(kEpidBadArgErr, EpidMemberSetSigRl(member_ctx, &srl, sizeof(srl)));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenBadGroupId) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  srl.gid = this->kGrpXKey.gid;
  srl.gid.data[0] = ~srl.gid.data[0];
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberSetSigRl(member_ctx, &srl, sizeof(srl) - sizeof(srl.bk)));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenEmptySigRlFromDifferentGroup) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  auto sig_rl_raw = this->kGrpXSigRl;
  SigRl* sig_rl = reinterpret_cast<SigRl*>(sig_rl_raw.data());
  sig_rl->gid.data[0] = 0x01;
  size_t sig_rl_size = this->kGrpXSigRl.size();
  EXPECT_EQ(kEpidBadArgErr,
            EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsGivenOldVersion) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);

  OctStr32 octstr32_0 = {0x00, 0x00, 0x00, 0x00};
  SigRl sigrl_v0 = {0};
  sigrl_v0.gid = this->kGrpXKey.gid;
  sigrl_v0.version = octstr32_0;
  OctStr32 octstr32_1 = {0x00, 0x00, 0x00, 0x01};
  SigRl sigrl_v1 = {0};
  sigrl_v1.version = octstr32_1;
  sigrl_v1.gid = this->kGrpXKey.gid;

  EXPECT_EQ(kEpidNoErr,
            EpidMemberSetSigRl(member_ctx, &sigrl_v1,
                               sizeof(sigrl_v1) - sizeof(sigrl_v1.bk)));
  EXPECT_EQ(kEpidVersionMismatchErr,
            EpidMemberSetSigRl(member_ctx, &sigrl_v0,
                               sizeof(sigrl_v0) - sizeof(sigrl_v0.bk)));
}
TEST_F(EpidSplitMemberTest, SetSigRlPreservesOldRlOnFailure) {
  auto old_sig_rl_raw = this->kGrpXSigRl;
  SigRl* old_sig_rl = reinterpret_cast<SigRl*>(old_sig_rl_raw.data());
  size_t old_sig_rl_size = old_sig_rl_raw.size();
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(old_sig_rl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &OneTimePad::Generate, &my_prng);
  auto sig_rl_raw = this->kGrpXSigRlMember3Sha256Bsn0Msg03EntriesFirstRevoked;
  SigRl* sig_rl = reinterpret_cast<SigRl*>(sig_rl_raw.data());

  // old sigrl contains has lower version
  ++sig_rl->version.data[sizeof(sig_rl->version) - 1];
  old_sig_rl->version.data[sizeof(old_sig_rl->version) - 1] = 0x00;
  size_t sig_rl_size = sig_rl_raw.size();
  EXPECT_EQ(kEpidNoErr, EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
  EXPECT_EQ(kEpidVersionMismatchErr,
            EpidMemberSetSigRl(member_ctx, old_sig_rl, old_sig_rl_size));
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member_ctx, bsn.data(), bsn.size()));
  std::vector<uint8_t> sig_data(EpidGetSigSize(sig_rl));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  // Check that sigrevoked member is still in SigRl
  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidSign(member_ctx, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     sig, sig_len));
}
TEST_F(EpidSplitMemberTest, SetSigRlWorksGivenValidSigRl) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(this->kGrpXSigRl.data());
  size_t sig_rl_size = this->kGrpXSigRl.size();
  EXPECT_EQ(kEpidNoErr, EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
}
TEST_F(EpidSplitMemberTest, SetSigRlWorksGivenEmptySigRl) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  uint8_t sig_rl_data_n2_zero[] = {
      // gid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xee,
      // version
      0x00, 0x00, 0x00, 0x00,
      // n2
      0x0, 0x00, 0x00, 0x00,
      // not bk's
  };
  SigRl* sig_rl = reinterpret_cast<SigRl*>(sig_rl_data_n2_zero);
  size_t sig_rl_size = sizeof(sig_rl_data_n2_zero);
  EXPECT_EQ(kEpidNoErr, EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
}
TEST_F(EpidSplitMemberTest, SetSigRlWorksGivenSigRlWithOneEntry) {
  Prng my_prng;
  MemberCtxObj member_ctx(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                          &Prng::Generate, &my_prng);
  SigRl const* sig_rl = reinterpret_cast<SigRl const*>(
      this->kGrpXSigRlMember3Sha256Bsn0Msg0OnlyEntry.data());
  size_t sig_rl_size = this->kGrpXSigRlMember3Sha256Bsn0Msg0OnlyEntry.size();
  EXPECT_EQ(kEpidNoErr, EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
}
TEST_F(EpidSplitMemberTest, SetSigRlFailsIfNotProvisioned) {
  Prng my_prng;
  MemberCtxObj member_ctx(&Prng::Generate, &my_prng);
  uint8_t sig_rl_data[] = {
      // gid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01,
      // version
      0x00, 0x00, 0x00, 0x00,
      // n2
      0x0, 0x00, 0x00, 0x00,
      // not bk's
  };
  SigRl* sig_rl = reinterpret_cast<SigRl*>(sig_rl_data);
  size_t sig_rl_size = sizeof(sig_rl_data);
  EXPECT_EQ(kEpidOutOfSequenceError,
            EpidMemberSetSigRl(member_ctx, sig_rl, sig_rl_size));
}
//////////////////////////////////////////////////////////////////////////
// EpidRegisterBasename
TEST_F(EpidSplitMemberTest, RegisterBaseNameFailsGivenNullPtr) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> basename = {'_', 'b', 'a', 's', 'e', 'n', 'a', 'm', 'e'};
  EXPECT_EQ(kEpidBadArgErr,
            EpidRegisterBasename(member, nullptr, basename.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidRegisterBasename(nullptr, basename.data(), basename.size()));
}
TEST_F(EpidSplitMemberTest, RegisterBaseNameFailsGivenDuplicateBaseName) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> basename = {'d', 'b', 'a', 's', 'e', 'n', 'a', 'm', 'e'};
  EXPECT_EQ(kEpidNoErr,
            EpidRegisterBasename(member, basename.data(), basename.size()));
  EXPECT_EQ(kEpidDuplicateErr,
            EpidRegisterBasename(member, basename.data(), basename.size()));
}
TEST_F(EpidSplitMemberTest, RegisterBaseNameFailsGivenInvalidBaseName) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> basename = {};
  std::vector<uint8_t> basename2 = {'b', 's', 'n'};
  EXPECT_EQ(kEpidBadArgErr,
            EpidRegisterBasename(member, basename.data(), basename.size()));
  EXPECT_EQ(kEpidBadArgErr, EpidRegisterBasename(member, basename2.data(), 0));
}
TEST_F(EpidSplitMemberTest, RegisterBaseNameSucceedsGivenUniqueBaseName) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> basename = {'b', 's', 'n', '0', '1'};
  EXPECT_EQ(kEpidNoErr,
            EpidRegisterBasename(member, basename.data(), basename.size()));
}
TEST_F(EpidSplitMemberTest,
       RegisterBaseNameSucceedsGivenMultipleUniqueBaseNames) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> basename1 = {'b', 's', 'n', '0', '1'};
  std::vector<uint8_t> basename2 = {'b', 's', 'n', '0', '2'};
  std::vector<uint8_t> basename3 = {'b', 's', 'n', '0', '3'};
  EXPECT_EQ(kEpidNoErr,
            EpidRegisterBasename(member, basename1.data(), basename1.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidRegisterBasename(member, basename2.data(), basename2.size()));
  EXPECT_EQ(kEpidNoErr,
            EpidRegisterBasename(member, basename3.data(), basename3.size()));
  // Verify that basenames registered successfully
  EXPECT_EQ(kEpidDuplicateErr,
            EpidRegisterBasename(member, basename1.data(), basename1.size()));
  EXPECT_EQ(kEpidDuplicateErr,
            EpidRegisterBasename(member, basename2.data(), basename2.size()));
  EXPECT_EQ(kEpidDuplicateErr,
            EpidRegisterBasename(member, basename3.data(), basename3.size()));
}
TEST_F(EpidSplitMemberTest,
       RegisterBaseNameSucceedsGivenBsnContainingAllPossibleBytes) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  EXPECT_EQ(kEpidNoErr, EpidRegisterBasename(member, this->kData_0_255.data(),
                                             this->kData_0_255.size()));
}
//////////////////////////////////////////////////////////////////////////
// EpidClearRegisteredBasenames
TEST_F(EpidSplitMemberTest, EpidClearRegisteredBasenamesFailsGivenNullPtr) {
  EXPECT_EQ(kEpidBadArgErr, EpidClearRegisteredBasenames(nullptr));
}
TEST_F(EpidSplitMemberTest, EpidClearRegisteredBasenamesClearsBasenames) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  THROW_ON_EPIDERR(
      EpidRegisterBasename(member, this->kBsn0.data(), this->kBsn0.size()));
  EXPECT_EQ(kEpidNoErr, EpidClearRegisteredBasenames(member));
  // check, that after clearing EpidRegisterBasename works correctly
  THROW_ON_EPIDERR(
      EpidRegisterBasename(member, this->kBsn0.data(), this->kBsn0.size()));
}
TEST_F(EpidSplitMemberTest, EpidClearRegisteredBasenamesClearsAllBasenames) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  for (int i = 0; i < 3; ++i) {
    THROW_ON_EPIDERR(EpidRegisterBasename(member, &i, sizeof(i)));
  }
  EXPECT_EQ(kEpidNoErr, EpidClearRegisteredBasenames(member));
  for (int i = 0; i < 3; ++i) {
    THROW_ON_EPIDERR(EpidRegisterBasename(member, &i, sizeof(i)));
  }
}
TEST_F(EpidSplitMemberTest,
       EpidClearRegisteredBasenamesCausesSignWithBasenameAfterItToFail) {
  Prng my_prng;
  MemberCtxObj member(this->kGrpXKey, this->kGrpXMember3PrivKeySha256,
                      this->kMemberPrecomp, &Prng::Generate, &my_prng);
  auto& msg = this->kMsg0;
  auto& bsn = this->kBsn0;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  THROW_ON_EPIDERR(EpidSign(member, msg.data(), msg.size(), bsn.data(),
                            bsn.size(), sig, sig_len));
  THROW_ON_EPIDERR(EpidClearRegisteredBasenames(member));
  ASSERT_EQ(kEpidBasenameNotRegisteredErr,
            EpidSign(member, msg.data(), msg.size(), bsn.data(), bsn.size(),
                     sig, sig_len));
}
#ifdef TPM_TSS
//////////////////////////////////////////////////////////////////////////
// MemberCanLoadMembershipCredentialFromTpm
TEST_F(EpidSplitMemberTest,
       MemberCanLoadPreviouslyProvisionedMembershipCredentialFromTpm) {
  // Not clear that this test is valid or in the right place.
  Prng prng;
  Epid2ParamsObj epid2params;

  GroupPubKey pub_key_expected = this->kGrpXKey;
  GroupPubKey pub_key;
  GroupPubKey split_pub_key_expected;
  FpElemStr f = this->kGrpXMember3PrivKeySha256.f;
  MembershipCredential credential_expected = {
      this->kGrpXMember3PrivKeySha256.gid, this->kGrpXMember3PrivKeySha256.A,
      this->kGrpXMember3PrivKeySha256.x};
  MembershipCredential credential;
  // Tpm2CtxObj calls Tpm2CreateContext() and sets
  // is_context_already_created=true. To call this function in
  // EpidMemberInit() successfully Tpm2DeleteContext() must be called.
  // Putting creation of Tpm2CtxObj object in a block solves it
  {
    // write credentials
    Tpm2CtxObj tpm(&Prng::Generate, &prng, nullptr, epid2params);
    THROW_ON_EPIDERR(EpidNvWriteMembershipCredential(tpm, &pub_key_expected,
                                                     &credential_expected));

    // read credentials to confirm that credential has been really inserted
    EXPECT_EQ(kEpidNoErr,
              EpidNvReadMembershipCredential(tpm, &pub_key, &credential));
    EXPECT_EQ(pub_key_expected, pub_key);
    EXPECT_EQ(credential_expected, credential);
  }

  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr, EpidMemberStartup(member));
  EXPECT_EQ(kEpidNoErr,
            EpidComputeSplitGroupPubKey(epid2params.G1(), &pub_key, kSha256,
                                        &split_pub_key_expected));

  EXPECT_EQ(split_pub_key_expected, ((MemberCtx*)member)->pub_key);
  EXPECT_EQ(credential_expected, ((MemberCtx*)member)->credential);
}
#endif
}  // namespace
