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
/// Split member group public key helper unit tests.
/*! \file */

#include <cstring>
#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/math/ecgroup.h"
#include "epid/member/split/src/split_grouppubkey.h"
}

#include "epid/common-testhelper/epid2params_wrapper-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

/// compares GroupPubKey values
bool operator!=(GroupPubKey const& lhs, GroupPubKey const& rhs) {
  return 0 != memcmp(&lhs, &rhs, sizeof(lhs));
}

namespace {
TEST_F(EpidSplitMemberTest, ComputeSplitGroupPubKeyFailsGivenNullParameters) {
  HashAlg hash_alg = kSha256;
  GroupPubKey pub_key = {0};
  Epid2ParamsObj epid2_params;

  EXPECT_EQ(kEpidBadArgErr,
            EpidComputeSplitGroupPubKey(nullptr, &pub_key, hash_alg, &pub_key));
  EXPECT_EQ(kEpidBadArgErr,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), nullptr, hash_alg,
                                        &pub_key));
  EXPECT_EQ(kEpidBadArgErr,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key, hash_alg,
                                        nullptr));
}

TEST_F(EpidSplitMemberTest,
       ComputeSplitGroupPubKeyFailsGivenUnsupportedHashAlg) {
  GroupPubKey pub_key = {0};
  Epid2ParamsObj epid2_params;

  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key,
                                        kInvalidHashAlg, &pub_key));
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key, kSha3_256,
                                        &pub_key));
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key, kSha3_384,
                                        &pub_key));
  EXPECT_EQ(kEpidHashAlgorithmNotSupported,
            EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key, kSha3_512,
                                        &pub_key));
}

TEST_F(EpidSplitMemberTest,
       ComputeSplitGroupPubKeySucceedsGivenValidParameters) {
  GroupPubKey pub_key = kGrpXKey;
  GroupPubKey updated_pub_key = {0};
  Epid2ParamsObj epid2_params;

  EXPECT_EQ(kEpidNoErr, EpidComputeSplitGroupPubKey(epid2_params.G1(), &pub_key,
                                                    kSha256, &updated_pub_key));
  EXPECT_NE(pub_key, updated_pub_key);
}
}  // namespace
