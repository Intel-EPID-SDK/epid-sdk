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
// AreSigsLinkable unit tests for split signatures.
/*! \file */

#include "gtest/gtest.h"
#include "testhelper/epid_gtest-testhelper.h"

extern "C" {
#include "epid/verifier.h"
}

#include "testhelper/verifier_wrapper-testhelper.h"
#include "verifier-testhelper.h"

namespace {

TEST_F(EpidVerifierSplitTest, AreSigsLinkedReturnsFalseGivenNullParameters) {
  auto& sig = this->kSigGrpXMember0Sha256Bsn0Msg0;
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, sizeof(BasicSignature), nullptr,
                                 sizeof(BasicSignature)));
  EXPECT_FALSE(EpidAreSigsLinked(sig.data(), sig.size(), nullptr,
                                 sizeof(BasicSignature)));
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, sizeof(BasicSignature), sig.data(),
                                 sig.size()));
}

TEST_F(EpidVerifierSplitTest, SigsBySameMemberWithRandomBaseAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256RndBsn2Data_0_255NoSigRl;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierSplitTest, SigsBySameMemberWithSameBasenameAreLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256Basename1Test2NoSigRl;
  EXPECT_TRUE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierSplitTest,
       SigsBySameMemberWithDifferentBasenameAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierSplitTest,
       SigsByDifferentMembersWithSameBasenameAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember4Sha256Basename1Test1NoSigRl;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), sig2.size()));
}

TEST_F(EpidVerifierSplitTest, AreSigsLinkedReturnsFalseIfSignaturesTooSmall) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256Basename1Test2NoSigRl;
  const size_t bad_size = sizeof(BasicSignature) - 1;
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), bad_size, sig2.data(), sig2.size()));
  EXPECT_FALSE(
      EpidAreSigsLinked(sig1.data(), sig1.size(), sig2.data(), bad_size));
}

}  // namespace
