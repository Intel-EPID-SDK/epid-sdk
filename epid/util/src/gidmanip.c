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
/// Group ID manipulator implementation
/*! \file */

#include "epid/gidmanip.h"
#include "common/endian_convert.h"
#include "common/gid_parser.h"
#include "epid/types.h"
#include "ippmath/memory.h"

EpidStatus ValidateGid(GroupId const* gid) {
  if (!gid) {
    return kEpidBadGidErr;
  }
  if (gid->data[0] & 0xF0) {
    return kEpidSchemaNotSupportedErr;
  }
  return kEpidNoErr;
}

EpidStatus EpidGid32ToGid(OctStr32 const* gid32, GroupId* gid) {
  size_t bytes_to_copy = sizeof(OctStr32);
  if (!gid32) {
    return kEpidBadArgErr;
  }
  if (!gid) {
    return kEpidBadGidErr;
  }
  memset(gid, 0, sizeof(*gid));
  if (0 != memcpy_S(gid->data + sizeof(GroupId) - sizeof(OctStr32),
                    bytes_to_copy, gid32->data, sizeof(OctStr32))) {
    return kEpidBadArgErr;
  }
  return kEpidNoErr;
}

EpidStatus EpidGidToGid32(GroupId const* gid, OctStr32* gid32) {
  size_t bytes_to_copy = sizeof(OctStr32);
  GroupId empty_gid = {0};
  if (!gid32) {
    return kEpidBadArgErr;
  }
  if (!gid) {
    return kEpidBadGidErr;
  }
  if (0 != memcmp(gid->data, &empty_gid, sizeof(GroupId) - sizeof(OctStr32))) {
    return kEpidOperationNotSupportedErr;
  }
  if (0 != memcpy_S(gid32->data, sizeof(OctStr32),
                    gid->data + sizeof(GroupId) - sizeof(OctStr32),
                    bytes_to_copy)) {
    return kEpidBadArgErr;
  }
  return kEpidNoErr;
}
EpidStatus EpidSetSchemaVersion(uint8_t schema_version, GroupId* gid) {
  if (!gid) {
    return kEpidBadGidErr;
  }
  memset(gid->data, 0, sizeof(GroupId));
  gid->data[0] = gid->data[0] | (schema_version << 4);
  return kEpidNoErr;
}
EpidStatus EpidGetSchemaVersion(GroupId const* gid, uint8_t* schema_version) {
  if (!schema_version) {
    return kEpidBadArgErr;
  }
  if (!gid) {
    return kEpidBadGidErr;
  }
  *schema_version = (gid->data[0] >> 4) & 0x0F;
  return kEpidNoErr;
}
EpidStatus EpidSetGlobalUsageId(uint8_t global_usage_id, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  gid->data[0] &= 0xF0;
  gid->data[1] &= 0x0F;
  gid->data[0] |= (global_usage_id >> 4) & 0x0F;
  gid->data[1] |= (global_usage_id << 4) & 0xF0;
  return kEpidNoErr;
}

EpidStatus EpidGetGlobalUsageId(GroupId const* gid, uint8_t* global_usage_id) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!global_usage_id) {
    return kEpidBadArgErr;
  }

  *global_usage_id =
      ((gid->data[1] & 0xF0) >> 4) | ((gid->data[0] & 0x0F) << 4);
  return kEpidNoErr;
}
EpidStatus EpidSetHashAlg(HashAlg hash_alg, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  gid->data[1] &= 0xF0;
  gid->data[1] |= hash_alg;
  return kEpidNoErr;
}
EpidStatus EpidGetHashAlg(GroupId const* gid, HashAlg* hash_alg) {
  EpidStatus sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!hash_alg) {
    return kEpidBadArgErr;
  }
  return EpidParseHashAlg(gid, hash_alg);
}
EpidStatus EpidSetIssuerId(uint16_t issuer_id, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  if (issuer_id > 0xFFF) {
    return kEpidBadArgErr;
  }
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  gid->data[3] &= 0x0F;
  gid->data[2] = (uint8_t)(issuer_id >> 4);
  gid->data[3] |= (issuer_id & 0x0F) << 4;
  return kEpidNoErr;
}
EpidStatus EpidGetIssuerId(GroupId const* gid, uint16_t* issuer_id) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!issuer_id) {
    return kEpidBadArgErr;
  }
  *issuer_id = ((uint16_t)gid->data[2]) << 4;
  *issuer_id |= gid->data[3] >> 4;
  return kEpidNoErr;
}
EpidStatus EpidSetVendorId(uint32_t vendor_id, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  if (vendor_id > 0xFFFFF) {
    return kEpidBadArgErr;
  }
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  gid->data[3] &= 0xF0;
  gid->data[3] |= (vendor_id >> 16) & 0x0F;
  gid->data[4] = (uint8_t)(vendor_id >> 8);
  gid->data[5] = (uint8_t)(vendor_id);
  return kEpidNoErr;
}
EpidStatus EpidGetVendorId(GroupId const* gid, uint32_t* vendor_id) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!vendor_id) {
    return kEpidBadArgErr;
  }
  *vendor_id = ((uint32_t)(gid->data[3] & 0x0F)) << 16;
  *vendor_id |= ((uint32_t)gid->data[4]) << 8;
  *vendor_id |= (uint32_t)gid->data[5];
  return kEpidNoErr;
}
EpidStatus EpidSetProductId(uint16_t product_id, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  gid->data[6] = (uint8_t)(product_id >> 8);
  gid->data[7] = (uint8_t)product_id;
  return kEpidNoErr;
}
EpidStatus EpidGetProductId(GroupId const* gid, uint16_t* product_id) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!product_id) {
    return kEpidBadArgErr;
  }
  *product_id = (((uint16_t)gid->data[6]) << 8);
  *product_id |= (uint16_t)gid->data[7];
  return kEpidNoErr;
}
EpidStatus EpidSetGidCore(uint32_t gid_core, GroupId* gid) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  *((uint32_t*)(gid->data + sizeof(GroupId) - sizeof(uint32_t))) =
      htonl(gid_core);
  return kEpidNoErr;
}
EpidStatus EpidGetGidCore(GroupId const* gid, uint32_t* gid_core) {
  EpidStatus sts = kEpidErr;
  sts = ValidateGid(gid);
  if (kEpidNoErr != sts) {
    return sts;
  }
  if (!gid_core) {
    return kEpidBadArgErr;
  }
  {
    uint32_t const* gid_p =
        (uint32_t*)(gid->data + sizeof(GroupId) - sizeof(uint32_t));
    *gid_core = ntohl(*gid_p);
  }
  return kEpidNoErr;
}
