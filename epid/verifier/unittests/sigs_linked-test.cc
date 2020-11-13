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
 * \brief AreSigsLinkable unit tests.
 */

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "epid/verifier.h"
}

#include "testhelper/verifier_wrapper-testhelper.h"
#include "verifier-testhelper.h"

namespace {

TEST_F(EpidVerifierTest, AreSigsLinkedReturnsFalseGivenNullParameters) {
  auto& sig = this->kSigGrpXMember0Sha256Bsn0Msg0;
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, sizeof(BasicSignature), nullptr,
                                 sizeof(BasicSignature)));
  EXPECT_FALSE(EpidAreSigsLinked(sig.data(), sig.size(), nullptr,
                                 sizeof(BasicSignature)));
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, sizeof(BasicSignature), sig.data(),
                                 sig.size()));
}

TEST_F(EpidVerifierTest, SigsBySameMemberWithRandomBaseAreNotLinkable) {
  auto& sig1 = this->kSigGrpXMember0Sha256RandbaseMsg0;
  auto& sig2 = this->kSigGrpXMember0Sha256RandbaseMsg1;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierTest, SigsBySameMemberWithSameBasenameAreLinkable) {
  auto& sig1 = this->kSigGrpXMember0Sha256Bsn0Msg0;
  auto& sig2 = this->kSigGrpXMember0Sha256Bsn0Msg1;
  EXPECT_TRUE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierTest, SigsBySameMemberWithDifferentBasenameAreNotLinkable) {
  auto& sig1 = this->kSigGrpXMember0Sha256Bsn0Msg0;
  auto& sig2 = this->kSigGrpXMember0Sha256Bsn1Msg0;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierTest, SigsByDifferentMembersWithSameBasenameAreNotLinkable) {
  auto& sig1 = this->kSigGrpXMember0Sha256Bsn0Msg0;
  auto& sig2 = this->kSigGrpXMember1Sha256Bsn0Msg0;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierSplitTest, AreSigsLinkedReturnsFalseIfSignaturesTooSmall) {
  auto& sig1 = this->kSigGrpXMember0Sha256Bsn0Msg0;
  auto& sig2 = this->kSigGrpXMember0Sha256Bsn0Msg1;
  const size_t bad_size = sizeof(BasicSignature) - 1;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), bad_size, sig2.data(), sig2.size()));
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), bad_size));
}

}  // namespace
