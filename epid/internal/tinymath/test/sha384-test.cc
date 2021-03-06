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
/// Unit tests of SHA-384 implementation.
/*! \file */

#include <gtest/gtest.h>

namespace {
#include "tinymath/sha384.h"

TEST(TinySha384Test, WorksGivenNistTestVector1) {
  const uint8_t expected[SHA384_DIGEST_SIZE] = {
      0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69,
      0x9a, 0xc6, 0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
      0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b,
      0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7};
  const char* m = "abc";
  uint8_t digest[SHA384_DIGEST_SIZE];
  sha384_state s;

  tinysha384_init(&s);
  tinysha384_update(&s, (const uint8_t*)m, strlen(m));
  tinysha384_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha384Test, WorksGivenNistTestVector2) {
  const uint8_t expected[SHA384_DIGEST_SIZE] = {
      0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
      0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
      0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
      0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b};
  const char* m = "";
  uint8_t digest[SHA384_DIGEST_SIZE];
  sha384_state s;

  tinysha384_init(&s);
  tinysha384_update(&s, (const uint8_t*)m, strlen(m));
  tinysha384_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha384Test, WorksGivenNistTestVector3) {
  const uint8_t expected[SHA384_DIGEST_SIZE] = {
      0x7b, 0xd0, 0x6a, 0x94, 0xac, 0xba, 0x7b, 0xeb, 0x3c, 0x5a, 0x9b, 0x9e,
      0x87, 0x69, 0xc3, 0xda, 0x66, 0x91, 0xc4, 0x82, 0xd7, 0x8b, 0x1e, 0x5c,
      0x76, 0x19, 0xb3, 0x66, 0x30, 0xeb, 0xa4, 0xe5, 0x96, 0xd1, 0x1c, 0x41,
      0x0a, 0x4c, 0x87, 0x00, 0x6f, 0x47, 0x16, 0xb6, 0xf1, 0x7b, 0xb9, 0xa0};
  uint8_t digest[SHA384_DIGEST_SIZE];
  const uint8_t m[7] = {0x12, 0x18, 0x35, 0xfe, 0x37, 0x00, 0xb7};
  sha384_state s;

  tinysha384_init(&s);
  tinysha384_update(&s, m, 7);
  tinysha384_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha384Test, WorksGivenNistTestVector4) {
  const uint8_t expected[SHA384_DIGEST_SIZE] = {
      0x09, 0x33, 0x0c, 0x33, 0xf7, 0x11, 0x47, 0xe8, 0x3d, 0x19, 0x2f, 0xc7,
      0x82, 0xcd, 0x1b, 0x47, 0x53, 0x11, 0x1b, 0x17, 0x3b, 0x3b, 0x05, 0xd2,
      0x2f, 0xa0, 0x80, 0x86, 0xe3, 0xb0, 0xf7, 0x12, 0xfc, 0xc7, 0xc7, 0x1a,
      0x55, 0x7e, 0x2d, 0xb9, 0x66, 0xc3, 0xe9, 0xfa, 0x91, 0x74, 0x60, 0x39};
  const char* m =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
      "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t digest[SHA384_DIGEST_SIZE];
  sha384_state s;

  tinysha384_init(&s);
  tinysha384_update(&s, (const uint8_t*)m, strlen(m));
  tinysha384_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

}  // namespace
