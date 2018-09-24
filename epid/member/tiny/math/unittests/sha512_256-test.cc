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
/// Unit tests of SHA-512/256 implementation.
/*! \file */

#include <gtest/gtest.h>

namespace {
extern "C" {
#include "epid/member/tiny/math/sha512_256.h"
}

TEST(TinySha512_256Test, WorksGivenNistTestVector1) {
  const uint8_t expected[SHA512_256_DIGEST_SIZE] = {
      0x53, 0x04, 0x8e, 0x26, 0x81, 0x94, 0x1e, 0xf9, 0x9b, 0x2e, 0x29,
      0xb7, 0x6b, 0x4c, 0x7d, 0xab, 0xe4, 0xc2, 0xd0, 0xc6, 0x34, 0xfc,
      0x6d, 0x46, 0xe0, 0xe2, 0xf1, 0x31, 0x07, 0xe7, 0xaf, 0x23};
  const char* m = "abc";
  uint8_t digest[SHA512_256_DIGEST_SIZE];
  sha512_256_state s;

  tinysha512_256_init(&s);
  tinysha512_256_update(&s, (const uint8_t*)m, strlen(m));
  tinysha512_256_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha512_256Test, WorksGivenNistTestVector2) {
  const uint8_t expected[SHA512_256_DIGEST_SIZE] = {
      0xc6, 0x72, 0xb8, 0xd1, 0xef, 0x56, 0xed, 0x28, 0xab, 0x87, 0xc3,
      0x62, 0x2c, 0x51, 0x14, 0x06, 0x9b, 0xdd, 0x3a, 0xd7, 0xb8, 0xf9,
      0x73, 0x74, 0x98, 0xd0, 0xc0, 0x1e, 0xce, 0xf0, 0x96, 0x7a};
  const char* m = "";
  uint8_t digest[SHA512_256_DIGEST_SIZE];
  sha512_256_state s;

  tinysha512_256_init(&s);
  tinysha512_256_update(&s, (const uint8_t*)m, strlen(m));
  tinysha512_256_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha512_256Test, WorksGivenNistTestVector3) {
  const uint8_t expected[SHA512_256_DIGEST_SIZE] = {
      0x1a, 0x86, 0xb4, 0xd3, 0x4c, 0xd1, 0x04, 0xc1, 0x3b, 0x5b, 0x8d,
      0x41, 0x97, 0x84, 0xce, 0x4c, 0x6d, 0x35, 0x59, 0x4f, 0x2a, 0x93,
      0x00, 0xe8, 0x14, 0x68, 0xf4, 0xdc, 0x06, 0x34, 0x83, 0x2a};
  const uint8_t m[7] = {0x5b, 0x48, 0xb8, 0xb0, 0x1a, 0x59, 0xd5};
  uint8_t digest[SHA512_256_DIGEST_SIZE];
  sha512_256_state s;

  tinysha512_256_init(&s);
  tinysha512_256_update(&s, m, 7);
  tinysha512_256_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

TEST(TinySha512_256Test, WorksGivenNistTestVector4) {
  const uint8_t expected[SHA512_256_DIGEST_SIZE] = {
      0x39, 0x28, 0xe1, 0x84, 0xfb, 0x86, 0x90, 0xf8, 0x40, 0xda, 0x39,
      0x88, 0x12, 0x1d, 0x31, 0xbe, 0x65, 0xcb, 0x9d, 0x3e, 0xf8, 0x3e,
      0xe6, 0x14, 0x6f, 0xea, 0xc8, 0x61, 0xe1, 0x9b, 0x56, 0x3a};
  const char* m =
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnop"
      "jklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
  uint8_t digest[SHA512_256_DIGEST_SIZE];
  sha512_256_state s;

  tinysha512_256_init(&s);
  tinysha512_256_update(&s, (const uint8_t*)m, strlen(m));
  tinysha512_256_final(digest, &s);
  EXPECT_TRUE(0 == memcmp(expected, digest, sizeof(digest)))
      << digest << std::endl
      << expected;
}

}  // namespace
