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
/// Group ID Manipulators.
/*! \file */
#ifndef EPID_UTIL_INCLUDE_EPID_GIDMANIP_H_
#define EPID_UTIL_INCLUDE_EPID_GIDMANIP_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "epid/errors.h"
#include "epid/types.h"

/// Group ID manipulators.
/*!
 \defgroup GidManip gidmanip

 GID manipulators are utility functions for inspecting and manipulating group
 identifiers.

 The behavior of GID manipulators depends on the schema version set in the
 GID. You should make sure the schema version is set before setting other fields
 in the GID.

 To use this module, include the header epid/common/gidmanip.h.

 \ingroup EpidCommon
  @{
*/

/// Convert legacy 32 bit group ID to modern group ID
/*!
 *
 * \param[in] gid32
 * The legacy 32-bit group ID to convert.
 *
 * \param[out] gid
 * The resultant group ID.
 *
 * \retval kEpidBadArgErr legacy 32-bit group ID is null
 * \retval kEpidBadGidErr group ID is null
 */
EpidStatus EpidGid32ToGid(OctStr32 const* gid32, GroupId* gid);
/// Convert modern group ID to legacy 32 bit group ID
/*!
 *
 * \param[in] gid
 * The group ID to convert.
 *
 * \param[out] gid32
 * The resultant legacy 32-bit group ID.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval kEpidBadGidErr group ID is null
 * \retval kEpidOperationNotSupportedErr group ID to convert has fields set
 * that are not supported by legacy 32-bit GID
 */
EpidStatus EpidGidToGid32(GroupId const* gid, OctStr32* gid32);

/// Set schema version in the group ID
/*!
 *
 * \note In addition to setting the schema version this function will clear all
 * other bits in the GID.
 *
 * \param[in] schema_version
 * The schema version.
 *
 * \param[out] gid
 * The group identifier.
 *
 * \retval ::kEpidBadGidErr
 */
EpidStatus EpidSetSchemaVersion(uint8_t schema_version, GroupId* gid);
/// Extract schema version encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] schema_version
 * The schema version.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 */
EpidStatus EpidGetSchemaVersion(GroupId const* gid, uint8_t* schema_version);

/// Set global usage ID in the group ID
/*!
 *
 * \param[in] global_usage_id
 *
 * The globally unique usage ID (e.g. application, security domain), managed by
 * global GID authority.
 *
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetGlobalUsageId(uint8_t global_usage_id, GroupId* gid);
/// Extract global usage ID encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] global_usage_id
 *
 * The globally unique usage ID (e.g. application, security domain), managed by
 * global GID authority.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetGlobalUsageId(GroupId const* gid, uint8_t* global_usage_id);

/// Set hash algorithm ID in the group ID
/*!
 *
 * \param[in] hash_alg
 *
 * The hash algorithm that will be used when signing and verifying with private
 * keys generated against the GID.
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetHashAlg(HashAlg hash_alg, GroupId* gid);
/// Extract hash algorithm ID encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] hash_alg
 * The hash algorithm that is used when signing and verifying with private keys
 * generated against this GID.
 *
 * \retval kEpidBadArgErr hash_alg is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetHashAlg(GroupId const* gid, HashAlg* hash_alg);

/// Set issuer ID in the group ID
/*!
 *
 * \param[in] issuer_id
 * The issuer responsible for generating keys against the GID. For schema
 * version 0 it can have a maximum value of 4095 (0xFFF).
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval kEpidBadArgErr invalid issuer_id
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetIssuerId(uint16_t issuer_id, GroupId* gid);
/// Extract issuer ID encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] issuer_id
 * The issuer responsible for generating keys against this GID.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetIssuerId(GroupId const* gid, uint16_t* issuer_id);

/// Set vendor id in the group ID
/*!
 *
 * \param[in] vendor_id
 * The vendor responsible for keys generated against the GID. For cases where
 * the first 8 bits are not 0xFF, each Vendor ID is scoped by Issuer ID. For
 * schema version 0, it can have a maximum value of 1048575 (0xFFFFF).
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval kEpidBadArgErr invalid vendor_id
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetVendorId(uint32_t vendor_id, GroupId* gid);
/// Extract vendor id encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] vendor_id
 * The vendor responsible for keys generated against the GID. For cases where
 * the first 8 bits are not 0xFF, each Vendor ID is scoped by Issuer ID.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetVendorId(GroupId const* gid, uint32_t* vendor_id);

/// Set product ID in the group ID
/*!
 *
 * \param[in] product_id
 * The product or usage that keys generated against the GID are targeted
 * for. Product IDs are scoped by Vendor ID.
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetProductId(uint16_t product_id, GroupId* gid);
/// Extract product ID encoded in the group ID
/*!
 *
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] product_id
 * The product or usage that keys generated against the GID are targeted
 * for. Product IDs are scoped by Vendor ID.
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetProductId(GroupId const* gid, uint16_t* product_id);

/// Set GID core in the group ID
/*!
 *
 * \param[in] gid_core
 * The unique Group ID for every Issuing CA, Vendor ID, and Product ID
 * combination.
 *
 * \param[in,out] gid
 * The group identifier.
 *
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidSetGidCore(uint32_t gid_core, GroupId* gid);
/// Extract GID core encoded in the group ID
/*!
 *
 * \param[in] gid
 * The group identifier.
 *
 * \param[out] gid_core
 * The unique Group ID for every Issuing CA, Vendor ID, and Product ID
 * combination.
 *
 *
 * \retval kEpidBadArgErr output buffer is null
 * \retval ::kEpidBadGidErr
 * \retval ::kEpidSchemaNotSupportedErr
 */
EpidStatus EpidGetGidCore(GroupId const* gid, uint32_t* gid_core);

/*! @} */

#ifdef __cplusplus
}
#endif

#endif  // EPID_UTIL_INCLUDE_EPID_GIDMANIP_H_
