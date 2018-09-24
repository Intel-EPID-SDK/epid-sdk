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
/// Split member group public key helper API
/*! \file */
#ifndef EPID_MEMBER_SPLIT_SRC_SPLIT_GROUPPUBKEY_H_
#define EPID_MEMBER_SPLIT_SRC_SPLIT_GROUPPUBKEY_H_

#include "epid/common/errors.h"
#include "epid/common/types.h"

/// \cond
typedef struct EcGroup EcGroup;
/// \endcond

/// Computes split group public key
/*!
 \param[in] g
 The elliptic curve group.
 \param[in] pub_key
 The group public key: (gid, h1, h2, w).
 \param[in] hash_alg
 The hash algorithm.
 \param[out] split_pub_key
 The split group public key: (gid, h1', h2, w).

 \returns ::EpidStatus
*/
EpidStatus EpidComputeSplitGroupPubKey(EcGroup const* g,
                                       GroupPubKey const* pub_key,
                                       HashAlg hash_alg,
                                       GroupPubKey* split_pub_key);

#endif  // EPID_MEMBER_SPLIT_SRC_SPLIT_GROUPPUBKEY_H_
