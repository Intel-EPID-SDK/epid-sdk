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
/// Group Id parsing unit tests.
/*! \file */

#include "epid/common-testhelper/epid_gtest-testhelper.h"
#include "gtest/gtest.h"
extern "C" {
#include "epid/common/src/gid_parser.h"
}

namespace {
TEST(EpidGidParser, FailsGivenNullParameters) {
  HashAlg hash_alg = kInvalidHashAlg;
  GroupId gid = {0};

  EXPECT_EQ(kEpidBadArgErr, EpidParseHashAlg(&gid, nullptr));
  EXPECT_EQ(kEpidBadArgErr, EpidParseHashAlg(nullptr, &hash_alg));
  EXPECT_EQ(kEpidBadArgErr, EpidParseHashAlg(nullptr, nullptr));
}

TEST(EpidGidParser, RejectsUnsupportedSchema) {
  HashAlg hash_alg = kInvalidHashAlg;

  const GroupId unsupported_gid = {0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00};

  EXPECT_EQ(kEpidSchemaNotSupportedErr,
            EpidParseHashAlg(&unsupported_gid, &hash_alg));
}

TEST(EpidGidParser, ParsesSha256Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha256gid = {0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha256;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha256gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}

TEST(EpidGidParser, ParsesSha384Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha384gid = {0x00, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha384;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha384gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}
TEST(EpidGidParser, ParsesSha512Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha512gid = {0x00, 0xf2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha512;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha512gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}
TEST(EpidGidParser, ParsesSha512_256Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha512_256gid = {0x00, 0xf3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha512_256;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha512_256gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}
TEST(EpidGidParser, ParsesSha3_256Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha3_256gid = {0x00, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha3_256;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha3_256gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}
TEST(EpidGidParser, ParsesSha3_384Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha3_384gid = {0x00, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha3_384;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha3_384gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}
TEST(EpidGidParser, ParsesSha3_512Gid) {
  HashAlg actual_hash_alg = kInvalidHashAlg;
  GroupId sha3_512gid = {0x00, 0xf6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  HashAlg expected_hash_alg = kSha3_512;

  EXPECT_EQ(kEpidNoErr, EpidParseHashAlg(&sha3_512gid, &actual_hash_alg));
  EXPECT_EQ(expected_hash_alg, actual_hash_alg);
}

}  // namespace
