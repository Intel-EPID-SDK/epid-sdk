/*############################################################################
  # Copyright 2018-2020 Intel Corporation
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
 * \brief Join Request simulator related unit tests.
 */

#include <cstring>
#include <memory>
#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"
#include "testhelper/onetimepad.h"

extern "C" {
#include "epid/member/api.h"
}

#include "epid/member/tiny/context.h"
#include "member-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"

/// compares FpElemStr values
bool operator==(FpElemStr const& lhs, FpElemStr const& rhs);

namespace {
// local constant for Join Request tests. This can be hoisted later if needed
// avoids cpplint warning about multiple includes.

const std::vector<uint8_t> joinreq_sha256_grp_x = {
#include "testhelper/testdata/grp_x/member3/joinreq_grpx_member3_sha256_01.inc"
};

const std::vector<uint8_t> joinreq_sha384_grp_x = {
#include "testhelper/testdata/grp_x/member3/joinreq_grpx_member3_sha384_01.inc"
};

const std::vector<uint8_t> joinreq_sha512_grp_x = {
#include "testhelper/testdata/grp_x/member3/joinreq_grpx_member3_sha512_01.inc"
};

const std::vector<uint8_t> joinreq_sha512256_grp_x = {
#include "testhelper/testdata/grp_x/member3/joinreq_grpx_member3_sha512_256_01.inc"
};

const FpElemStr f = {0x48, 0x40, 0xb5, 0x6c, 0x6d, 0x47, 0x09, 0x0b,
                     0x05, 0xd6, 0x43, 0x56, 0xe0, 0x7c, 0xc6, 0x8e,
                     0xa1, 0x65, 0x67, 0xfd, 0xa7, 0x07, 0x87, 0x9b,
                     0x36, 0x2d, 0x41, 0x35, 0x63, 0x61, 0x31, 0xc7};

const IssuerNonce ni = {0xd3, 0x6d, 0xb5, 0xe0, 0x7f, 0x4c, 0xfd, 0x35,
                        0x4e, 0xac, 0x7b, 0x17, 0x68, 0x3d, 0x51, 0x91,
                        0x41, 0x89, 0x3c, 0x5e, 0x39, 0x5f, 0xd1, 0xed,
                        0x63, 0x22, 0x6b, 0x27, 0x9a, 0x5d, 0x48, 0xf1};

void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesKnownJoinRequestUsingSha256Digest) {
  OneTimePad prng;
  prng.InitUint8(this->kOtpData);  // reinitialize prng with test data
  MemberParams params = {0};
  GroupPubKey pub_key = kGrpXKey;
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  std::vector<uint8_t> expected_join_request_buffer = joinreq_sha256_grp_x;
  SetMemberParams(OneTimePad::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  set_gid_hashalg(&pub_key.gid, kSha256);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(expected_join_request_buffer, join_request);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesKnownJoinRequestUsingSha384Digest) {
  MemberParams params = {0};
  GroupPubKey pub_key = kGrpXKey;
  OneTimePad prng;
  prng.InitUint8(this->kOtpData);  // reinitialize prng with test data
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  std::vector<uint8_t> expected_join_request_buffer = joinreq_sha384_grp_x;

  SetMemberParams(OneTimePad::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  set_gid_hashalg(&pub_key.gid, kSha384);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(expected_join_request_buffer, join_request);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesKnownJoinRequestUsingSha512Digest) {
  MemberParams params = {0};
  GroupPubKey pub_key = kGrpXKey;
  OneTimePad prng;
  prng.InitUint8(this->kOtpData);  // reinitialize prng with test data
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  std::vector<uint8_t> expected_join_request_buffer = joinreq_sha512_grp_x;

  SetMemberParams(OneTimePad::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  set_gid_hashalg(&pub_key.gid, kSha512);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(expected_join_request_buffer, join_request);
}

TEST_F(EpidMemberTest,
       CreateJoinRequestGeneratesKnownJoinRequestUsingSha512256Digest) {
  MemberParams params = {0};
  GroupPubKey pub_key = kGrpXKey;
  OneTimePad prng;
  prng.InitUint8(this->kOtpData);  // reinitialize prng with test data
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  std::vector<uint8_t> expected_join_request_buffer = joinreq_sha512256_grp_x;

  SetMemberParams(OneTimePad::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(expected_join_request_buffer, join_request);
}
}  // namespace
