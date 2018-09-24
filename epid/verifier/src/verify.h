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
#ifndef EPID_VERIFIER_SRC_VERIFY_H_
#define EPID_VERIFIER_SRC_VERIFY_H_

#include <stddef.h>
#include "epid/common/errors.h"

/// \cond
typedef struct VerifierCtx VerifierCtx;
typedef struct EpidSplitSignature EpidSplitSignature;
/// \endcond

/// Verifies a split signature and checks revocation status.
/*!
 \param[in] ctx
 The verifier context.
 \param[in] sig
 The split signature.
 \param[in] sig_len
 The size of sig in bytes.
 \param[in] msg
 The message that was signed.
 \param[in] msg_len
 The size of msg in bytes.

 \returns ::EpidStatus

 \retval ::kEpidSigValid
 Signature validated successfully
 \retval ::kEpidSigInvalid
 Signature is invalid
 \retval ::kEpidSigRevokedInGroupRl
 Signature revoked in GroupRl
 \retval ::kEpidSigRevokedInPrivRl
 Signature revoked in PrivRl
 \retval ::kEpidSigRevokedInSigRl
 Signature revoked in SigRl
 \retval ::kEpidSigRevokedInVerifierRl
 Signature revoked in VerifierRl

 \note
 If the result is not ::kEpidNoErr or one of the values listed above the
 verify should be considered to have failed.

 \see EpidVerifierCreate
 \see EpidSign

 \b Example

 \ref UserManual_VerifyingAnIntelEpidSignature
 */
EpidStatus EpidVerifySplitSig(VerifierCtx const* ctx,
                              EpidSplitSignature const* sig, size_t sig_len,
                              void const* msg, size_t msg_len);

#endif  // EPID_VERIFIER_SRC_VERIFY_H_
