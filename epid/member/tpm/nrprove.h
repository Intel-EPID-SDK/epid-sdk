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
/// TPM NrProve APIs
/*! \file */

#ifndef EPID_MEMBER_TPM_NRPROVE_H_
#define EPID_MEMBER_TPM_NRPROVE_H_

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
/// Result of NrProve Commit
typedef struct NrProveCommitOutput {
  G1ElemStr T;   ///< T value for NrProof
  G1ElemStr R1;  ///< Serialized G1 element
  G1ElemStr R2;  ///< Serialized G1 element
} NrProveCommitOutput;
#pragma pack()

/// Performs the first part of the NrProve operation
/*!

  \param[in,out] ctx
  The TPM context.

  \param[in] B_str
  The B value from the ::BasicSignature.

  \param[in] K_str
  The K value from the ::BasicSignature.

  \param[in] sigrl_entry
  The signature based revocation list entry corresponding to this
  proof.

  \param[out] commit_out
  The resulting commitment value.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmInit
  \see TpmNrProve
*/
EpidStatus TpmNrProveCommit(TpmCtx* ctx, G1ElemStr const* B_str,
                            G1ElemStr const* K_str,
                            SigRlEntry const* sigrl_entry,
                            NrProveCommitOutput* commit_out);

/// Performs the last part of the NrProve operation
/*!

  \note
  ::TpmNrProve must be preceded by a call to ::TpmNrProveCommit. Two
  sequential calls to ::TpmNrProve will fail with
  ::kEpidOutOfSequenceError.

  \param[in,out] ctx
  The TPM context.

  \param[in] c_str
  The non-revoked proof commitment hash.

  \param[out] smu_str
  The smu value in the non-revoked proof.

  \param[out] snu_str
  The snu value in the non-revoked proof.

  \returns ::EpidStatus

  \see TpmCreate
  \see TpmProvision
  \see TpmInit
  \see TpmNrProveCommit
 */
EpidStatus TpmNrProve(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* smu_str,
                      FpElemStr* snu_str);

/*! @} */
#endif  // EPID_MEMBER_TPM_NRPROVE_H_
