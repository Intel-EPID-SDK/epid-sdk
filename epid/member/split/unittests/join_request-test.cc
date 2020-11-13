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
 * \brief Join Request related unit tests.
 */

#include <cstring>
#include <memory>
#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "common/endian_convert.h"
#include "common/epid2params.h"
#include "common/hashsize.h"
#include "epid/member/api.h"
#include "epid/types.h"
#include "epid/verifier.h"
#include "ippmath/ecgroup.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"
}

#include "epid/member/split/context.h"
#include "member-testhelper.h"
#include "testhelper/ecgroup_wrapper-testhelper.h"
#include "testhelper/ecpoint_wrapper-testhelper.h"
#include "testhelper/epid_params-testhelper.h"
#include "testhelper/errors-testhelper.h"
#include "testhelper/ffelement_wrapper-testhelper.h"
#include "testhelper/finite_field_wrapper-testhelper.h"
#include "testhelper/mem_params-testhelper.h"
#include "testhelper/prng-testhelper.h"
#include "testhelper/verifier_wrapper-testhelper.h"

/// compares FpElemStr values
bool operator==(FpElemStr const& lhs, FpElemStr const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}

namespace {
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

typedef union sha_digest {
  uint8_t sha512_digest[EPID_SHA512_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha384_digest[EPID_SHA384_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha256_digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t digest[1];  ///< Pointer to digest
} sha_digest;

#pragma pack(1)
typedef struct JoinCommitValues {
  FpElemStr noncek;  //!< random number (256-bit)
  sha_digest digest;
} JoinCommitValues;
#pragma pack()

// local constant for Join Request tests. This can be hoisted later if needed
// avoids cpplint warning about multiple includes.
const GroupPubKey kPubKey = {
#include "testhelper/testdata/grp01/gpubkey.inc"
};

const PrivKey kGrpXMember3Sha256PrivKey = {
#include "testhelper/testdata/grp_x/member3/mprivkey_sha256_01.inc"
};

const MemberPrecomp kGrpXMember3Sha256Precomp = {
#include "testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha256_01.inc"
};

const FpElemStr kFEps1 = {
    0x2e, 0xd6, 0xca, 0xcb, 0xa8, 0x79, 0x07, 0x85, 0xc1, 0x25, 0x02,
    0xcc, 0x61, 0x7f, 0x47, 0xcc, 0x74, 0xf3, 0x8a, 0xe0, 0x75, 0x05,
    0xa5, 0xd6, 0xcb, 0xdb, 0x82, 0x56, 0xe8, 0xb4, 0x2b, 0x5b,
};
/// Validates join request.
void ValidateJoinRequest(void const* request, size_t request_size,
                         HashAlg hash_alg, GroupPubKey const& grp_public_key,
                         FpElemStr const& f, IssuerNonce const& ni) {
  Epid2Params params_values = {
#include "common/epid2params_ate.inc"
  };
  struct {
    G1ElemStr F;  /// an element in G1
    FpElemStr c;  /// an integer between [0, p-1]
    FpElemStr s;  /// an integer between [0, p-1]
    FpElemStr k;  /// an integer between [0, p-1]
    OctStr32 i;   /// 32-bit unsigned integer
    FqElemStr y;  /// an integer between [0, q-1]
  } joinreq_values;
  Epid20Params params;
  G1ElemStr empty_point = {0};
  FqElemStr empty_fp = {0};
  G1ElemStr new_h1_str = empty_point;
  uint32_t iteration;

  // h1'= Efq.hash(i||h1)
  EcPointObj new_h1(&params.G1, empty_point);
  ASSERT_EQ(sizeof(joinreq_values), request_size);
  if (0 != memcpy_S(&joinreq_values, sizeof(joinreq_values), request,
                    request_size)) {
    THROW_ON_EPIDERR(kEpidBadArgErr);
  }
  THROW_ON_EPIDERR(EcHash(params.G1.get(), &grp_public_key.h1,
                          sizeof(grp_public_key.h1), hash_alg, new_h1.get(),
                          &iteration));
  ASSERT_EQ(ntohl(joinreq_values.i.data), iteration);
  THROW_ON_EPIDERR(WriteEcPoint(params.G1.get(), new_h1.getc(), &new_h1_str,
                                sizeof(new_h1_str)));

  // h1'^f ?= F
  EcPointObj F_expected(&params.G1, new_h1_str);
  THROW_ON_EPIDERR(
      EcExp(params.G1.get(), F_expected, (BigNumStr*)&f, F_expected));
  ASSERT_EQ(*(G1ElemStr*)(F_expected.data().data()), joinreq_values.F);

  // H(p|g1|g2|h1'|h2|w|F|R|ni) ?= c, where R = h1'^s * F^(-c)
  JoinCommitValues commitment_values = {0};
  commitment_values.noncek = joinreq_values.k;
  size_t digest_size = EpidGetHashSize(hash_alg);
  size_t c_req_size = sizeof(joinreq_values.c);
  if (memcpy_S((uint8_t*)&commitment_values.digest + (digest_size - c_req_size),
               c_req_size, &joinreq_values.c, c_req_size)) {
    THROW_ON_EPIDERR(kEpidBadArgErr);
  }
  FfElementObj t(&params.fp, empty_fp);
  FfElementObj nt(&params.fp, empty_fp);
  // t = hash(k||c)
  THROW_ON_EPIDERR(FfHash(params.fp.get(), &commitment_values,
                          digest_size + sizeof(commitment_values.noncek),
                          hash_alg, t));
  // -t
  THROW_ON_EPIDERR(FfNeg(params.fp.get(), t, nt));
  EcPointObj a(&params.G1, new_h1_str);
  EcPointObj b(&params.G1, joinreq_values.F);
  // h1'^s
  THROW_ON_EPIDERR(EcExp(params.G1.get(), a, (BigNumStr*)&joinreq_values.s, a));
  // h1'^(-t*f)
  THROW_ON_EPIDERR(EcExp(params.G1.get(), b, (BigNumStr*)nt.data().data(), b));
  // h1'^(s-t*f) = h1'^r = R
  THROW_ON_EPIDERR(EcMul(params.G1.get(), a, b, a));

#pragma pack(1)
  struct {
    BigNumStr p;     // Intel(R) EPID 2.0 parameter p
    G1ElemStr g1;    // Intel(R) EPID 2.0 parameter g1
    G2ElemStr g2;    // Intel(R) EPID 2.0 parameter g2
    G1ElemStr h1;    // Group public key value h1
    G1ElemStr h2;    // Group public key value h2
    G2ElemStr w;     // Group public key value w
    G1ElemStr F;     // Variable F computed in algorithm
    G1ElemStr R;     // Variable R computed in algorithm
    IssuerNonce NI;  // Issuer Nonce
  } commitment = {params_values.p,
                  params_values.g1,
                  params_values.g2,
                  new_h1_str,
                  grp_public_key.h2,
                  grp_public_key.w,
                  joinreq_values.F,
                  *(G1ElemStr*)(a.data().data()),
                  ni};
#pragma pack()

  FfElementObj c(&params.fp, empty_fp);
  THROW_ON_EPIDERR(
      FfHash(params.fp.get(), &commitment, sizeof(commitment), hash_alg, c));
  ASSERT_EQ(*(FpElemStr*)(c.data().data()), joinreq_values.c);
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestFailsGivenNullParameters) {
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni;
  MemberParams params;
  Prng prng;
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj ctx(&params);
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(nullptr, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(ctx, nullptr, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(ctx, &pub_key, nullptr, join_request.data(),
                                  join_request.size()));
  EXPECT_EQ(kEpidBadArgErr, EpidCreateJoinRequest(ctx, &pub_key, &ni, nullptr,
                                                  join_request.size()));
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestRejectsRequestOfInsufficentSize) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoMemErr,
            EpidCreateJoinRequest(member, &pub_key, &ni,
                                  (JoinRequest*)join_request.data(), 0));

  EXPECT_EQ(kEpidNoMemErr,
            EpidCreateJoinRequest(member, &pub_key, &ni,
                                  (JoinRequest*)join_request.data(),
                                  EpidGetJoinRequestSize() - 1));
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestFailsGivenInvalidGroupKey) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  pub_key.h1.x.data.data[15] = 0xff;
  Epid20Params epid_params;
  EcPointObj pt(&epid_params.G1);
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  ASSERT_NE(kEpidNoErr, ReadEcPoint(epid_params.G1, (uint8_t*)&pub_key.h1,
                                    sizeof(pub_key.h1), pt));
  EXPECT_EQ(kEpidBadArgErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestFailsGivenInvalidFValue) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  EpidStatus sts;
  SetMemberParams(Prng::Generate, &prng, &f, &params);

  std::unique_ptr<uint8_t[]> member;
  size_t context_size = 0;
  sts = EpidMemberGetSize(&params, &context_size);
  EXPECT_TRUE(kEpidNoErr == sts || kEpidBadArgErr == sts)
      << "Actual value " << sts;

  if (kEpidNoErr == sts) {
    member.reset(new uint8_t[context_size]());
    sts = EpidMemberInit(&params, (MemberCtx*)member.get());
    EXPECT_TRUE(kEpidNoErr == sts || kEpidBadArgErr == sts)
        << "Actual value " << sts;
  }

  if (kEpidNoErr == sts) {
    sts = EpidCreateJoinRequest((MemberCtx*)member.get(), &pub_key, &ni,
                                join_request.data(), join_request.size());
    EXPECT_EQ(kEpidBadArgErr, sts);
  }

  EpidMemberDeinit((MemberCtx*)member.get());
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestWorksGivenValidParameters) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, pub_key, f, ni));
}

TEST_F(EpidSplitMemberTest,
       PROTECTED_CreateJoinRequestUsingWorksGivenValidParameters_EPS1) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, pub_key, kFEps1, ni));
}

TEST_F(EpidSplitMemberTest,
       CreateJoinRequestGeneratesDiffJoinRequestsOnMultipleCalls) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request1(EpidGetJoinRequestSize());
  std::vector<uint8_t> join_request2(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, &f, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request1.data(),
                                  join_request1.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request1.data(), join_request1.size(), kSha256, pub_key, f, ni));
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request2.data(),
                                  join_request2.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request2.data(), join_request2.size(), kSha256, pub_key, f, ni));
  EXPECT_NE(join_request1, join_request2);
}

TEST_F(EpidSplitMemberTest,
       PROTECTED_CreateJoinRequestGenDiffJoinReqOnMultipleCalls_EPS1) {
  Prng prng;
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request1(EpidGetJoinRequestSize());
  std::vector<uint8_t> join_request2(EpidGetJoinRequestSize());
  SetMemberParams(Prng::Generate, &prng, nullptr, &params);
  MemberCtxObj member(&params);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request1.data(),
                                  join_request1.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(join_request1.data(),
                                              join_request1.size(), kSha256,
                                              pub_key, kFEps1, ni));
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request2.data(),
                                  join_request2.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(join_request2.data(),
                                              join_request2.size(), kSha256,
                                              pub_key, kFEps1, ni));
  EXPECT_NE(join_request1, join_request2);
}

TEST_F(EpidSplitMemberTest,
       CreateJoinRequestGeneratesDiffJoinRequestsGivenDiffHashAlgs) {
  MemberParams params = {0};
  GroupPubKey pub_key = kPubKey;
  FpElemStr f = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
  };
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request1(EpidGetJoinRequestSize());
  std::vector<uint8_t> join_request2(EpidGetJoinRequestSize());
  // Ensure that two members created with equal seed and do not
  // interfere each other. Member1 is deleted by the time member2
  // is created.
  {
    Prng prng;
    SetMemberParams(Prng::Generate, &prng, &f, &params);
    MemberCtxObj member1(&params);
    prng.set_seed(0x1234);
    EXPECT_EQ(kEpidNoErr, EpidCreateJoinRequest(member1, &pub_key, &ni,
                                                join_request1.data(),
                                                join_request1.size()));
    EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
        join_request1.data(), join_request1.size(), kSha256, pub_key, f, ni));
  }
  {
    Prng prng;
    SetMemberParams(Prng::Generate, &prng, &f, &params);
    MemberCtxObj member2(&params);
    prng.set_seed(0x1234);
    set_gid_hashalg(&pub_key.gid, kSha384);
    EXPECT_EQ(kEpidNoErr, EpidCreateJoinRequest(member2, &pub_key, &ni,
                                                join_request2.data(),
                                                join_request2.size()));
    EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
        join_request2.data(), join_request2.size(), kSha384, pub_key, f, ni));
  }
  EXPECT_NE(join_request1, join_request2);
}

TEST_F(EpidSplitMemberTest,
       ProvisionedMemberCanCreateJoinRequestForGroupWithDiffHashAlg) {
  Prng my_prng;
  // create and provision member in sha256 group
  GroupPubKey pub_key = this->kGrpXKey;
  PrivKey mpriv_key = this->kGrpXMember3PrivKeySha256;
  MemberParams params = {0};
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  SetMemberParams(&Prng::Generate, &my_prng, &mpriv_key.f, &params);
  MemberCtxObj member(&params);

  // provision into group with sha256
  EXPECT_EQ(kEpidNoErr, EpidProvisionKey(member, &pub_key, &mpriv_key,
                                         &this->kMemberPrecomp));

  // create join request into a group with a different hash alg
  // verify join request
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;  // sha384

  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(join_request.data(),
                                              join_request.size(), kSha384,
                                              pub_key, mpriv_key.f, ni));
}

TEST_F(EpidSplitMemberTest, CanCreateMultipleJoinRequestsWithDiffHashAlgs) {
  Prng my_prng;
  // create member with specific f
  GroupPubKey pub_key = this->kGrpXKey;
  FpElemStr f = this->kGrpXMember3PrivKeySha256.f;
  MemberParams params = {0};
  SetMemberParams(&Prng::Generate, &my_prng, &f, &params);
  MemberCtxObj member(&params);
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  // create join request into a group with sha256 hash alg
  // verify join request
  set_gid_hashalg(&pub_key.gid, kSha256);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha256, pub_key, f, ni));

  // create join request into a group with sha512 hash alg
  // verify join request
  set_gid_hashalg(&pub_key.gid, kSha512);
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));
  EXPECT_NO_FATAL_FAILURE(ValidateJoinRequest(
      join_request.data(), join_request.size(), kSha512, pub_key, f, ni));
}

TEST_F(EpidSplitMemberTest, CreateJoinRequestDoesNotChangeHashAlgorithm) {
  Prng my_prng;
  // create and provision member in sha256 group
  MemberCtxObj member(this->kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kGrpXMember3Sha256Precomp, &Prng::Generate, &my_prng);
  IssuerNonce ni = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03,
      0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
  };
  std::vector<uint8_t> join_request(EpidGetJoinRequestSize());

  // create join request into a group with a different hash alg
  GroupPubKey pub_key = this->kGrpXKey;
  pub_key.gid.data[1] &= 0xf0;
  pub_key.gid.data[1] |= 0x01;  // sha384
  EXPECT_EQ(kEpidNoErr,
            EpidCreateJoinRequest(member, &pub_key, &ni, join_request.data(),
                                  join_request.size()));

  auto& msg = this->kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);

  // sign message
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));

  // verify signature
  VerifierCtxObj ctx(this->kGrpXKey);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}
}  // namespace
