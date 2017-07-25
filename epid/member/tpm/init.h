/*############################################################################
  # Copyright 2017 Intel Corporation
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
/// Non-sensitive member context APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_INIT_H_
#define EPID_MEMBER_TPM_INIT_H_

#include "epid/common/errors.h"

/// \cond
typedef struct TpmCtx TpmCtx;
typedef struct G1ElemStr G1ElemStr;
typedef struct G2ElemStr G2ElemStr;
typedef struct FpElemStr FpElemStr;
typedef struct MemberPrecomp MemberPrecomp;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

/// Initializes Tpm with non-sensitive parameters
/*!

  \note Does not check consistency with the provisioned f value.  Use
  ::TpmIsKeyValid to check that the parameters will result in a valid
  key pair.

  \param[in,out] ctx
  The TPM context.

  \param[in] A_str
  The A value of the member private key.

  \param[in] x_str
  The x value of the member private key.

  \param[in] h1_str
  The h1 value of the group public key.

  \param[in] h2_str
  The h2 value of the group public key.

  \param[in] w_str
  The w value of the group public key.

  \param[in] precomp_str
  The member pre-computed data.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmIsKeyValid
 */
EpidStatus TpmInit(TpmCtx* ctx, G1ElemStr const* A_str, FpElemStr const* x_str,
                   G1ElemStr const* h1_str, G1ElemStr const* h2_str,
                   G2ElemStr const* w_str, MemberPrecomp const* precomp_str);

/*! @} */

#endif  // EPID_MEMBER_TPM_INIT_H_
