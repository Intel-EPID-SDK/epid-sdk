/*############################################################################
  # Copyright 2017-2019 Intel Corporation
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
/// Member private exponentiation API
/*! \file */
#ifndef EPID_MEMBER_SPLIT_SRC_PRIVATEEXP_H_
#define EPID_MEMBER_SPLIT_SRC_PRIVATEEXP_H_

#include "epid/errors.h"

/// \cond
typedef struct EcPoint EcPoint;
typedef struct MemberCtx MemberCtx;
typedef struct Tpm2Key Tpm2Key;
/// \endcond

/// Raises a point in an elliptic curve group G1 to a private key f.
/*!
 \param[in] ctx
 The member context.
 \param[in] a
 The base.
 \param[in] f_handle
 Handle to private key.
 \param[out] r
 The result of exponentiation.

 \returns ::EpidStatus
*/

EpidStatus EpidPrivateExp(MemberCtx* ctx, EcPoint const* a,
                          Tpm2Key const* f_handle, EcPoint* r);

#endif  // EPID_MEMBER_SPLIT_SRC_PRIVATEEXP_H_
