/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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
/// Group Id manipulation unit tests.
/*! \file */
#include <cstring>
#include "epid/types.h"
#include "gtest/gtest.h"

#include "epid/gidmanip.h"

inline bool operator==(GroupId const& lhs, GroupId const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}

inline bool operator==(OctStr32 const& lhs, OctStr32 const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}
namespace {

extern const GroupId kGidToParse;
extern const GroupId kGidWithUnsupportedSchema;
extern const GroupId kGidSchema0x0;
extern const GroupId kGidSchema0x2;
extern const GroupId kGidUsage0xFD;
extern const GroupId kGidSha384;
extern const GroupId kGidIssuer0x123;
extern const GroupId kGidVendor0x12345;
extern const GroupId kGidProduct0x1234;
extern const GroupId kGidCore0xDEADBEEF;
extern const OctStr32 kGid32_DEADBEEF;
////////////////////////////////////////////////////////////////////////////////
TEST(Gid32ToGid, ConvertsValidGid32) {
  EpidStatus sts = kEpidErr;
  const OctStr32 gid32 = kGid32_DEADBEEF;
  GroupId gid = {0};
  const GroupId expected_gid = kGidCore0xDEADBEEF;

  sts = EpidGid32ToGid(&gid32, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(Gid32ToGid, RejectsNullGid32) {
  EpidStatus sts = kEpidErr;
  GroupId gid = {0};

  sts = EpidGid32ToGid(nullptr, &gid);
  EXPECT_EQ(kEpidBadArgErr, sts);
}

TEST(Gid32ToGid, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const OctStr32 gid32 = kGid32_DEADBEEF;

  sts = EpidGid32ToGid(&gid32, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

////////////////////////////////////////////////////////////////////////////////
TEST(GidToGid32, ConvertsValidGid) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidCore0xDEADBEEF;
  OctStr32 gid32 = {0};

  const OctStr32 expected_gid32 = kGid32_DEADBEEF;
  sts = EpidGidToGid32(&gid, &gid32);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid32, gid32);
}

TEST(GidToGid32, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  OctStr32 gid32 = {0};

  sts = EpidGidToGid32(nullptr, &gid32);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GidToGid32, RejectsNullGid32) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidCore0xDEADBEEF;

  sts = EpidGidToGid32(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}

TEST(GidToGid32, RejectsNonconvertibleGid) {
  EpidStatus sts = kEpidErr;
  const GroupId non_convertable_gid = kGidToParse;

  OctStr32 gid32 = {0};

  sts = EpidGidToGid32(&non_convertable_gid, &gid32);
  EXPECT_EQ(kEpidOperationNotSupportedErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetSchemaVersion, SetsSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint8_t schema_version = 0x00;
  GroupId gid = kGidToParse;

  const GroupId expected_gid = kGidSchema0x0;
  sts = EpidSetSchemaVersion(schema_version, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);

  // can set an unsupported schema version
  const uint8_t schema_version2 = 0x02;
  gid = kGidToParse;
  const GroupId expected_gid_v2 = kGidSchema0x2;
  sts = EpidSetSchemaVersion(schema_version2, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid_v2, gid);
}

TEST(SetSchemaVersion, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const uint8_t schema_version = 0x00;

  sts = EpidSetSchemaVersion(schema_version, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

////////////////////////////////////////////////////////////////////////////////
TEST(GetSchemaVersion, GetsSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidToParse;
  uint8_t schema_version = 0xFF;
  const uint8_t expected_schema_version = 0x00;

  sts = EpidGetSchemaVersion(&gid, &schema_version);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_schema_version, schema_version);

  // can get an unsupported schema version
  const GroupId gid2 = kGidWithUnsupportedSchema;
  schema_version = 0xFF;
  const uint8_t expected_schema_version_gid2 = 0x02;

  sts = EpidGetSchemaVersion(&gid2, &schema_version);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_schema_version_gid2, schema_version);
}

TEST(GetSchemaVersion, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint8_t schema_version = 0xFF;

  sts = EpidGetSchemaVersion(nullptr, &schema_version);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetSchemaVersion, RejectsNullSchemaVersion) {
  EpidStatus sts = kEpidErr;
  GroupId gid = kGidToParse;

  sts = EpidGetSchemaVersion(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetGlobalUsageId, SetsGlobalUsageId) {
  EpidStatus sts = kEpidErr;
  const uint8_t global_usage_id = 0xFD;
  GroupId gid = {0};
  GroupId expected_gid = kGidUsage0xFD;
  sts = EpidSetGlobalUsageId(global_usage_id, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(SetGlobalUsageId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const uint8_t global_usage_id = 0xFD;

  sts = EpidSetGlobalUsageId(global_usage_id, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetGlobalUsageId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint8_t global_usage_id = 0xFD;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetGlobalUsageId(global_usage_id, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

////////////////////////////////////////////////////////////////////////////////
TEST(GetGlobalUsageId, GetsGlobalUsageId) {
  EpidStatus sts = kEpidErr;
  uint8_t global_usage_id = 0;
  const GroupId gid = kGidToParse;
  const uint8_t expected_global_usage_id = 0xFD;

  sts = EpidGetGlobalUsageId(&gid, &global_usage_id);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_global_usage_id, global_usage_id);
}

TEST(GetGlobalUsageId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  uint8_t global_usage_id = 0;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidGetGlobalUsageId(&gid_with_unsupported_schema, &global_usage_id);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetGlobalUsageId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint8_t global_usage_id = 0;

  sts = EpidGetGlobalUsageId(nullptr, &global_usage_id);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetGlobalUsageId, RejectsNullUsageId) {
  EpidStatus sts = kEpidErr;
  GroupId gid = kGidToParse;

  sts = EpidGetGlobalUsageId(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetHashAlg, SetsHashAlgorithm) {
  EpidStatus sts = kEpidErr;
  HashAlg hash_alg = kSha384;
  GroupId gid = {0};
  GroupId expected_gid_384 = kGidSha384;
  sts = EpidSetHashAlg(hash_alg, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid_384, gid);
}

TEST(SetHashAlg, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  HashAlg hash_alg = kSha384;

  sts = EpidSetHashAlg(hash_alg, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetHashAlg, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  HashAlg hash_alg = kSha384;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetHashAlg(hash_alg, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(GetHashAlg, GetsHashAlgorithm) {
  EpidStatus sts = kEpidErr;
  // check get sha384
  HashAlg hash_alg = kInvalidHashAlg;
  GroupId gid_384 = kGidToParse;
  const HashAlg expected_hash_alg = kSha384;

  sts = EpidGetHashAlg(&gid_384, &hash_alg);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_hash_alg, hash_alg);
}

TEST(GetHashAlg, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  HashAlg hash_alg = kInvalidHashAlg;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidGetHashAlg(&gid_with_unsupported_schema, &hash_alg);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetHashAlg, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  HashAlg hash_alg = kInvalidHashAlg;

  sts = EpidGetHashAlg(nullptr, &hash_alg);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetHashAlg, RejectsNullHashAlgorithm) {
  EpidStatus sts = kEpidErr;
  GroupId gid_384 = kGidToParse;

  sts = EpidGetHashAlg(&gid_384, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetIssuerId, SetsIssuerId) {
  EpidStatus sts = kEpidErr;
  const uint16_t issuer_id = 0x123;
  GroupId gid = {0};
  GroupId expected_gid = kGidIssuer0x123;

  sts = EpidSetIssuerId(issuer_id, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(SetIssuerId, RejectsInvalidIssuerId) {
  EpidStatus sts = kEpidErr;
  const uint16_t invalid_issuer_id = 0x1000;
  GroupId gid = {0};

  sts = EpidSetIssuerId(invalid_issuer_id, &gid);
  EXPECT_EQ(kEpidBadArgErr, sts);
}

TEST(SetIssuerId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const uint16_t issuer_id = 0x123;

  sts = EpidSetIssuerId(issuer_id, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetIssuerId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint16_t issuer_id = 0x123;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetIssuerId(issuer_id, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(GetIssuerId, GetsIssuerId) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidToParse;
  uint16_t issuer_id = 0;
  const uint16_t expected_issuer_id = 0x123;

  sts = EpidGetIssuerId(&gid, &issuer_id);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_issuer_id, issuer_id);
}

TEST(GetIssuerId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;
  uint16_t issuer_id = 0;

  sts = EpidGetIssuerId(&gid_with_unsupported_schema, &issuer_id);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetIssuerId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint16_t issuer_id = 0;

  sts = EpidGetIssuerId(nullptr, &issuer_id);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetIssuerId, RejectsNullIssuerId) {
  EpidStatus sts = kEpidErr;
  GroupId gid = kGidToParse;

  sts = EpidGetIssuerId(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetVendorId, SetsVendorId) {
  EpidStatus sts = kEpidErr;
  const uint32_t vendor_id = 0x012345;
  GroupId gid = {0};
  const GroupId expected_gid = kGidVendor0x12345;

  sts = EpidSetVendorId(vendor_id, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(SetVendorId, RejectsInvalidVendorId) {
  EpidStatus sts = kEpidErr;
  const uint32_t vendor_id = 0x100000;
  GroupId gid = {0};

  sts = EpidSetVendorId(vendor_id, &gid);
  EXPECT_EQ(kEpidBadArgErr, sts);
}

TEST(SetVendorId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint32_t vendor_id = 0x012345;

  sts = EpidSetVendorId(vendor_id, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetVendorId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint32_t vendor_id = 0x012345;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetVendorId(vendor_id, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(GetVendorId, GetsVendorId) {
  EpidStatus sts = kEpidErr;
  uint32_t vendor_id = 0;
  const GroupId gid = kGidToParse;
  const uint32_t expected_vendor_id = 0x012345;

  sts = EpidGetVendorId(&gid, &vendor_id);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_vendor_id, vendor_id);
}

TEST(GetVendorId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  uint32_t vendor_id = 0;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidGetVendorId(&gid_with_unsupported_schema, &vendor_id);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetVendorId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint32_t vendor_id = 0;

  sts = EpidGetVendorId(nullptr, &vendor_id);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetVendorId, RejectsNullVendorId) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidToParse;

  sts = EpidGetVendorId(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(SetProductId, SetsProductId) {
  EpidStatus sts = kEpidErr;
  const uint16_t product_id = 0x1234;
  GroupId gid = {0};
  GroupId expected_gid = kGidProduct0x1234;

  sts = EpidSetProductId(product_id, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(SetProductId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const uint16_t product_id = 0x1234;

  sts = EpidSetProductId(product_id, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetProductId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint16_t product_id = 0x1234;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetProductId(product_id, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

////////////////////////////////////////////////////////////////////////////////
TEST(GetProductId, GetsProductId) {
  EpidStatus sts = kEpidErr;
  uint16_t product_id = 0x0000;
  const GroupId gid = kGidToParse;
  uint16_t expected_product_id = 0x1234;

  sts = EpidGetProductId(&gid, &product_id);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_product_id, product_id);
}

TEST(GetProductId, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  uint16_t product_id = 0x0000;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidGetProductId(&gid_with_unsupported_schema, &product_id);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetProductId, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint16_t product_id = 0x0000;

  sts = EpidGetProductId(nullptr, &product_id);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetProductId, RejectsNullProductId) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidToParse;

  sts = EpidGetProductId(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}
////////////////////////////////////////////////////////////////////////////////

TEST(SetGidCore, SetsGidCore) {
  EpidStatus sts = kEpidErr;
  const uint32_t gid_core = 0xDEADBEEF;
  GroupId gid = {0};
  const GroupId expected_gid = kGidCore0xDEADBEEF;

  sts = EpidSetGidCore(gid_core, &gid);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid, gid);
}

TEST(SetGidCore, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  const uint32_t gid_core = 0xDEADBEEF;

  sts = EpidSetGidCore(gid_core, nullptr);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(SetGidCore, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  const uint32_t gid_core = 0xDEADBEEF;
  GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidSetGidCore(gid_core, &gid_with_unsupported_schema);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}
////////////////////////////////////////////////////////////////////////////////
TEST(GetGidCore, GetsGidCore) {
  EpidStatus sts = kEpidErr;
  uint32_t gid_core = 0;
  const GroupId gid = kGidToParse;
  uint32_t expected_gid_core = 0xDEADBEEF;

  sts = EpidGetGidCore(&gid, &gid_core);
  EXPECT_EQ(kEpidNoErr, sts);
  EXPECT_EQ(expected_gid_core, gid_core);
}

TEST(GetGidCore, RejectsGidWithUnsupportedSchemaVersion) {
  EpidStatus sts = kEpidErr;
  uint32_t gid_core = 0;
  const GroupId gid_with_unsupported_schema = kGidWithUnsupportedSchema;

  sts = EpidGetGidCore(&gid_with_unsupported_schema, &gid_core);
  EXPECT_EQ(kEpidSchemaNotSupportedErr, sts);
}

TEST(GetGidCore, RejectsNullGid) {
  EpidStatus sts = kEpidErr;
  uint32_t gid_core = 0;

  sts = EpidGetGidCore(nullptr, &gid_core);
  EXPECT_EQ(kEpidBadGidErr, sts);
}

TEST(GetGidCore, RejectsNullGidCore) {
  EpidStatus sts = kEpidErr;
  const GroupId gid = kGidToParse;

  sts = EpidGetGidCore(&gid, nullptr);
  EXPECT_EQ(kEpidBadArgErr, sts);
}

////////////////////////////////////////////////////////////////////////////////
const GroupId kGidToParse = {
    0x0F, 0xD1, 0x12, 0x31, 0x23, 0x45, 0x12, 0x34,
    0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
};
const GroupId kGidWithUnsupportedSchema = {
    0x2F, 0xD1, 0x12, 0x31, 0x23, 0x45, 0x12, 0x34,
    0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
};
const GroupId kGidSchema0x0 = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidSchema0x2 = {
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidUsage0xFD = {
    0x0F, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidSha384 = {
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidIssuer0x123 = {
    0x00, 0x00, 0x12, 0x30, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidVendor0x12345 = {
    0x00, 0x00, 0x00, 0x01, 0x23, 0x45, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidProduct0x1234 = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const GroupId kGidCore0xDEADBEEF = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
};
const OctStr32 kGid32_DEADBEEF = {0xDE, 0xAD, 0xBE, 0xEF};
}  // namespace
