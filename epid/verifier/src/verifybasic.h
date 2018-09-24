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
#ifndef EPID_VERIFIER_SRC_VERIFYBASIC_H_
#define EPID_VERIFIER_SRC_VERIFYBASIC_H_

#include <stddef.h>
#include "epid/common/errors.h"

/// \cond
typedef struct VerifierCtx VerifierCtx;
typedef struct BasicSignature BasicSignature;
typedef struct FpElemStr FpElemStr;
/// \endcond

/// Verifies a member signature without revocation checks.
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

 \returns ::EpidStatus

 \note
 This function should be used in conjunction with EpidNrVerify() and
 EpidCheckPrivRlEntry().

 \note
 If the result is not ::kEpidNoErr the verify should be considered to have
 failed.

 \see EpidVerifierCreate
 \see EpidSign
 */
EpidStatus EpidVerifyBasicSig(VerifierCtx const* ctx, BasicSignature const* sig,
                              void const* msg, size_t msg_len);

/// Verifies a member signature without revocation checks.
/*!
Used in constrained environments where, due to limited memory, it may not
be possible to process through a large and potentially unbounded revocation
list.

\param[in] ctx
The verifier context.
\param[in] sig
The basic signature.
\param[in] nk
Split signature nonce. If NULL verify sig as non-split signature.
\param[in] msg
The message that was signed.
\param[in] msg_len
The size of msg in bytes.

\returns ::EpidStatus

\note
This function should be used in conjunction with split variants of
EpidNrVerify() and EpidCheckPrivRlEntry().

\note
If the result is not ::kEpidNoErr the verify should be considered to have
failed.

\see EpidVerifierCreate
\see EpidSign
*/
EpidStatus EpidVerifyBasicSplitSig(VerifierCtx const* ctx,
                                   BasicSignature const* sig,
                                   FpElemStr const* nk, void const* msg,
                                   size_t msg_len);

#endif  // EPID_VERIFIER_SRC_VERIFYBASIC_H_
