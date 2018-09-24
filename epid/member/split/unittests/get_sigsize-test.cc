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

/*!
 * \file
 * \brief GetSigSize unit tests.
 */

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/src/sig_types.h"
#include "epid/member/api.h"
}

#include "epid/member/split/unittests/member-testhelper.h"

namespace {

TEST_F(EpidSplitMemberTest, GetSigSizeReturnsSizeofBasicSigGivenNullPointer) {
  size_t sig_size_without_sig_rl =
      sizeof(EpidSplitSignature) - sizeof(SplitNrProof);
  EXPECT_EQ(sig_size_without_sig_rl, EpidGetSigSize(nullptr));
}

TEST_F(EpidSplitMemberTest, GetSigSizeReturnsCorrectValueGivenValidSigRl) {
  SigRl srl = {{{0}}, {{0}}, {{0}}, {{{{0}, {0}}, {{0}, {0}}}}};
  OctStr32 octstr32_0 = {0x00, 0x00, 0x00, 0x00};
  OctStr32 octstr32_1 = {0x00, 0x00, 0x00, 0x01};
  OctStr32 octstr32_2 = {0x00, 0x00, 0x00, 0x02};
  OctStr32 octstr32_16 = {0x00, 0x00, 0x00, 0x10};
  OctStr32 octstr32_256 = {0x00, 0x00, 0x01, 0x00};
  OctStr32 octstr32_65536 = {0x00, 0x01, 0x00, 0x00};
  OctStr32 octstr32_4294967295 = {0xff, 0xff, 0xff, 0xff};

  size_t one_entry_size = sizeof(SplitNrProof);
  size_t sig_size_0_entries = sizeof(EpidSplitSignature) - one_entry_size;
  size_t sig_size_1_entry = sig_size_0_entries + one_entry_size;
  size_t sig_size_2_entries = sig_size_0_entries + 2 * one_entry_size;
  size_t sig_size_16_entries = sig_size_0_entries + 16 * one_entry_size;
  size_t sig_size_256_entries = sig_size_0_entries + 256 * one_entry_size;
  size_t sig_size_65536_entries = sig_size_0_entries + 65536 * one_entry_size;
  // no entries
  srl.n2 = octstr32_0;
  EXPECT_EQ(sig_size_0_entries, EpidGetSigSize(&srl));
  // 1 entry
  srl.n2 = octstr32_1;
  EXPECT_EQ(sig_size_1_entry, EpidGetSigSize(&srl));
  // 2 entries
  srl.n2 = octstr32_2;
  EXPECT_EQ(sig_size_2_entries, EpidGetSigSize(&srl));
  // 16 entries
  srl.n2 = octstr32_16;
  EXPECT_EQ(sig_size_16_entries, EpidGetSigSize(&srl));
  // 256 entries
  srl.n2 = octstr32_256;
  EXPECT_EQ(sig_size_256_entries, EpidGetSigSize(&srl));
  // 65536 entries
  srl.n2 = octstr32_65536;
  EXPECT_EQ(sig_size_65536_entries, EpidGetSigSize(&srl));
  // 4294967295 entries
  srl.n2 = octstr32_4294967295;
#if (SIZE_MAX <= 0xFFFFFFFF)  // When size_t value is 32 bit or lower
  EXPECT_EQ(sig_size_0_entries, EpidGetSigSize(&srl));
#else
  size_t sig_size_4294967295_entries =
      sig_size_0_entries + 4294967295 * one_entry_size;
  EXPECT_EQ(sig_size_4294967295_entries, EpidGetSigSize(&srl));
#endif
}

}  // namespace
