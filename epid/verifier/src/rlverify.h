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
/// BasicSignature verification interfaces.
/*! \file */
#ifndef EPID_VERIFIER_SRC_RLVERIFY_H_
#define EPID_VERIFIER_SRC_RLVERIFY_H_

#include <stddef.h>
#include "epid/common/errors.h"

/// \cond
typedef struct VerifierCtx VerifierCtx;
typedef struct BasicSignature BasicSignature;
typedef struct SigRlEntry SigRlEntry;
typedef struct FpElemStr FpElemStr;
/// \endcond

/// Verifies the non-revoked proof for a single signature based revocation list
/// entry.
/*!
 Used in constrained environments where, due to limited memory, it may not
 be possible to process through a large and potentially unbounded revocation
 list.

 \param[in] ctx
 The verifier context.
 \param[in] sig
 The basic signature.
 \param[in] msg
 The message that was signed.
 \param[in] msg_len
 The size of msg in bytes.
 \param[in] sigrl_entry
 The signature based revocation list entry.
 \param[in] nr_proof
 The non-revoked proof.
 \param[in] nr_proof_len
 The size of non-revoked proof in bytes.

 \returns ::EpidStatus

 \note
 Sig should be verified using EpidVerifyBasicSig() before invocation. Behavior
 is undefined if sig cannot be verified.

 \note
 This function should be used in conjunction with EpidVerifyBasicSig() and
 EpidCheckPrivRlEntry().

 \note
 If the result is not ::kEpidNoErr, the verification should be
 considered to have failed.

 \see EpidVerifierCreate
 \see EpidVerifyBasicSig
 \see EpidCheckPrivRlEntry
 */
EpidStatus EpidNrVerify(VerifierCtx const* ctx, BasicSignature const* sig,
                        void const* msg, size_t msg_len,
                        SigRlEntry const* sigrl_entry, void const* nr_proof,
                        size_t nr_proof_len);

/// Verifies a signature has not been revoked in the private key based
/// revocation list.
/*!
 Used in constrained environments where, due to limited memory, it may not
 be possible to process through a large and potentially unbounded revocation
 list.

 \param[in] ctx
 The verifier context.
 \param[in] sig
 The basic signature.
 \param[in] f
 The private key based revocation list entry.

 \note
 Sig should be verified using EpidVerifyBasicSig() before invocation. Behavior
 is undefined if sig cannot be verified.

 \note
 This function should be used in conjunction with EpidNrVerify() and
 EpidVerifyBasicSig().

 \note
 If the result is not ::kEpidNoErr the verify should be considered to have
 failed.

 \returns ::EpidStatus
 \see EpidVerifierCreate
 \see EpidNrVerify
 \see EpidVerifyBasicSig
 */
EpidStatus EpidCheckPrivRlEntry(VerifierCtx const* ctx,
                                BasicSignature const* sig, FpElemStr const* f);

#endif  // EPID_VERIFIER_SRC_RLVERIFY_H_
