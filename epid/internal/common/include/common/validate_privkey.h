/*############################################################################
# INTEL CONFIDENTIAL
#
# Copyright 2019 Intel Corporation
#
# This software and the related documents are Intel copyrighted materials,
# and your use of them is governed by the express license under which they
# were provided to you (License). Unless the License provides otherwise,
# you may not use, modify, copy, publish, distribute, disclose or transmit
# this software or the related documents without Intel's prior written
# permission.
#
# This software and the related documents are provided as is, with no express
# or implied warranties, other than those that are expressly stated in
# the License.
############################################################################*/
/// Interfaces for private key validation functions.
/*! \file */
#ifndef EPID_INTERNAL_COMMON_INCLUDE_COMMON_VALIDATE_PRIVKEY_H_
#define EPID_INTERNAL_COMMON_INCLUDE_COMMON_VALIDATE_PRIVKEY_H_

#include <stddef.h>
#include "epid/errors.h"
#include "epid/stdtypes.h"

// Forward declare types
/// \cond
typedef struct PrivKey PrivKey;
typedef struct GroupPubKey GroupPubKey;
/// \endcond

/// Checks if non split private key is in group
/*!
*
* \param[in] priv_key
* The non split private key to validate
*
* \param[in] pub_key
* The public key to validate private key
*
*
* \retval ::kEpidNoErr
* \retval ::kEpidBadPrivKeyErr
* \retval ::kEpidBadGroupPubKeyErr
* \retval ::kEpidKeyNotInGroupErr
*/
EpidStatus EpidValidateNonSplitPrivateKey(PrivKey const* priv_key,
                                          GroupPubKey const* pub_key);

/// Checks if split private key is in group
/*!
*
* \param[in] priv_key
* The split private key to validate
*
* \param[in] pub_key
* The public key to validate private key
*
*
* \retval ::kEpidNoErr
* \retval ::kEpidBadPrivKeyErr
* \retval ::kEpidBadGroupPubKeyErr
* \retval ::kEpidKeyNotInGroupErr
*/
EpidStatus EpidValidateSplitPrivateKey(PrivKey const* priv_key,
                                       GroupPubKey const* pub_key);

/// Checks if private key is in group
/*!
*
* \param[in] priv_key
* The private key to validate
*
* \param[in] pub_key
* The public key to validate private key
*
*
* \retval ::kEpidNoErr
* \retval ::kEpidBadPrivKeyErr
* \retval ::kEpidBadGroupPubKeyErr
* \retval ::kEpidKeyNotInGroupErr
*/
EpidStatus EpidValidatePrivateKey(PrivKey const* priv_key,
                                  GroupPubKey const* pub_key);

#endif  // EPID_INTERNAL_COMMON_INCLUDE_COMMON_VALIDATE_PRIVKEY_H_
