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
/// TPM join APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_JOIN_H_
#define EPID_MEMBER_TPM_JOIN_H_

#include "epid/common/errors.h"

/// \cond
typedef struct TpmCtx TpmCtx;
typedef struct G1ElemStr G1ElemStr;
typedef struct FpElemStr FpElemStr;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

/// Performs the first part of the join operation
/*!

  \param[in,out] ctx
  The TPM context.

  \param[out] F_str
  The F value of the join commit.

  \param[out] R_str
  The R value of the join commit.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmJoin
*/
EpidStatus TpmJoinCommit(TpmCtx* ctx, G1ElemStr* F_str, G1ElemStr* R_str);

/// Performs the last part of the join operation
/*!

  \note
  ::TpmJoin must be preceded by a call to ::TpmJoinCommit. Two
  sequential calls to ::TpmJoin will fail with
  ::kEpidOutOfSequenceError.

  \param[in] ctx
  The TPM context.

  \param[in] c_str
  The join commitment hash.

  \param[out] s_str
  The s value of the join request.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmJoinCommit
 */
EpidStatus TpmJoin(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* s_str);

/*! @} */
#endif  // EPID_MEMBER_TPM_JOIN_H_
