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
/// Internal tiny pre-computed signature APIs
/*! \file */

#ifndef EPID_MEMBER_TINY_SRC_PRESIG_INTERNAL_H_
#define EPID_MEMBER_TINY_SRC_PRESIG_INTERNAL_H_

#include "epid/errors.h"

/// \cond
typedef struct MemberCtx MemberCtx;
typedef struct PreComputedSignatureData PreComputedSignatureData;
/// \endcond

/// Provides a pointer to precomputed signature in members's pool
/*!

  Provides a pre-computed signatures from members's pool if
  available, otherwise provides a newly calculated pre-computed
  signature.

  \warning
  Pre-computed signatures must not be accessed outside of the secure
  boundary.

  \warning
  You must call MemberPopPreSig() immediately after using the pre-
  computed signature provided by this function or you risk exposing
  the member private key.

  \param[in] ctx
  The member context.

  \param[out] presig
  The pre-computed signature removed from members's pool

  \returns ::EpidStatus

  \see MemberPopPreSig
 */
EpidStatus MemberTopPreSig(MemberCtx* ctx, PreComputedSignatureData** presig);

/// Provides a precomputed signature
/*!

  Removes a pre-computed signature from a member context.

  \warning
  Pre-computed signatures must not be accessed outside of the secure
  boundary.

  \param[in,out] ctx
  The member context.

  \returns ::EpidStatus

 */
EpidStatus MemberPopPreSig(MemberCtx* ctx);

#endif  // EPID_MEMBER_TINY_SRC_PRESIG_INTERNAL_H_
