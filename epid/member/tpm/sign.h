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
/// TPM signing APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_SIGN_H_
#define EPID_MEMBER_TPM_SIGN_H_

#include "epid/common/errors.h"
#include "epid/common/types.h"

/// \cond
typedef struct TpmCtx TpmCtx;
/// \endcond

/*!
  \addtogroup TpmModule tpm
  \ingroup EpidMemberModule
  @{
*/

#pragma pack(1)
/// Result of Sign Commit
typedef struct SignCommitOutput {
  G1ElemStr B;   ///< B value for signature
  G1ElemStr K;   ///< K value for signature
  G1ElemStr T;   ///< T value for signature
  G1ElemStr R1;  ///< Serialized G1 element
  GtElemStr R2;  ///< Serialized GT element
} SignCommitOutput;
#pragma pack()

/// Performs the first part of the sign operation
/*!

  \param[in,out] ctx
  The TPM context.

  \param[in] B_in_str
  An optional serialized hash of basename. If NULL a random basename
  is used.

  \param[out] commit_out
  The resulting commitment value.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmInit
  \see TpmSign
*/
EpidStatus TpmSignCommit(TpmCtx* ctx, G1ElemStr const* B_in_str,
                         SignCommitOutput* commit_out);

/// Performs the last part of the sign operation
/*!

  \note
  ::TpmSign must be preceded by a call to ::TpmSignCommit. Two
  sequential calls to ::TpmSign will fail with
  ::kEpidOutOfSequenceError.

  \param[in] ctx
  The TPM context.

  \param[in] c_str
  The sign commitment hash.

  \param[out] sx_str
  The ::BasicSignature sx value.

  \param[out] sf_str
  The ::BasicSignature sf value.

  \param[out] sa_str
  The ::BasicSignature sa value.

  \param[out] sb_str
  The ::BasicSignature sb value.


  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmInit
  \see TpmSignCommit
 */
EpidStatus TpmSign(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* sx_str,
                   FpElemStr* sf_str, FpElemStr* sa_str, FpElemStr* sb_str);

/*! @} */
#endif  // EPID_MEMBER_TPM_SIGN_H_
