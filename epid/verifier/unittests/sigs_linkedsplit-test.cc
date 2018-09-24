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
// AreSigsLinkable unit tests for split signatures.
/*! \file */

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/verifier/api.h"
}

#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/verifier/unittests/verifier-testhelper.h"

namespace {

TEST_F(EpidVerifierSplitTest, AreSigsLinkedReturnsFalseGivenNullParameters) {
  auto& sig = this->kSigGrpXMember0Sha256Bsn0Msg0;
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, nullptr));
  EXPECT_FALSE(EpidAreSigsLinked((BasicSignature const*)sig.data(), nullptr));
  EXPECT_FALSE(EpidAreSigsLinked(nullptr, (BasicSignature const*)sig.data()));
}

TEST_F(EpidVerifierSplitTest, SigsBySameMemberWithRandomBaseAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256RndBsn2Data_0_255NoSigRl;
  EXPECT_FALSE(EpidAreSigsLinked((BasicSignature const*)sig1.data(),
                                 (BasicSignature const*)sig2.data()));
}

TEST_F(EpidVerifierSplitTest, SigsBySameMemberWithSameBasenameAreLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256Basename1Test2NoSigRl;
  EXPECT_TRUE(EpidAreSigsLinked((BasicSignature const*)sig1.data(),
                                (BasicSignature const*)sig2.data()));
}

TEST_F(EpidVerifierSplitTest,
       SigsBySameMemberWithDifferentBasenameAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl;
  EXPECT_FALSE(EpidAreSigsLinked((BasicSignature const*)sig1.data(),
                                 (BasicSignature const*)sig2.data()));
}

TEST_F(EpidVerifierSplitTest,
       SigsByDifferentMembersWithSameBasenameAreNotLinkable) {
  auto& sig1 = this->kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl;
  auto& sig2 = this->kSplitSigGrpXMember4Sha256Basename1Test1NoSigRl;
  EXPECT_FALSE(EpidAreSigsLinked((BasicSignature const*)sig1.data(),
                                 (BasicSignature const*)sig2.data()));
}

}  // namespace
