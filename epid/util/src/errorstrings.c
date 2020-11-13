/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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
/// Error reporting implementation.
/*! \file */

#include <stddef.h>

#include "epid/errors.h"
#include "epid/stdtypes.h"

/// Record mapping status code to string
struct ErrorTextEntry {
  /// error code
  EpidStatus value;
  /// string associated with error code
  char const* text;
};

/// Mapping of status codes to strings
static const struct ErrorTextEntry kEnumToText[] = {
    {kEpidNoErr, "no error"},
    {kEpidSigInvalid, "invalid signature"},
    {kEpidSigRevokedInGroupRl, "signature revoked in GroupRl"},
    {kEpidSigRevokedInPrivRl, "signature revoked in PrivRl"},
    {kEpidSigRevokedInSigRl, "signature revoked in SigRl"},
    {kEpidSigRevokedInVerifierRl, "signature revoked in VerifierRl"},
    {kEpidErr, "unspecified error"},
    {kEpidNotImpl, "not implemented"},
    {kEpidNoMemErr, "insufficient memory provided"},
    {kEpidMemAllocErr, "could not allocate memory"},
    {kEpidMathErr, "internal math error"},
    {kEpidDivByZeroErr, "attempt to divide by zero"},
    {kEpidUnderflowErr, "underflow"},
    {kEpidHashAlgorithmNotSupported, "unsupported hash algorithm type"},
    {kEpidRandMaxIterErr, "reached max iteration for random number generation"},
    {kEpidDuplicateErr, "argument would add duplicate entry"},
    {kEpidInconsistentBasenameSetErr,
     "the set basename is inconsistent with supplied parameters"},
    {kEpidMathQuadraticNonResidueError, "quadratic non-residue"},
    {kEpidOutOfSequenceError, "operation out of sequence"},
    {kEpidBadJoinRequestErr, "invalid join request"},
    {kEpidSchemaNotSupportedErr, "format is not supported"},
    {kEpidOperationNotSupportedErr, "operation not supported"},
    {kEpidKeyNotInGroupErr, "private key not in group"},
    {kEpidPrecompNotInGroupErr, "input Precomp not in group"},
    {kEpidVersionMismatchErr, "version mismatch error"},
    {kEpidGroupIdMismatchErr, "group id miss match"},
    {kEpidMaxVersionErr, "version already at maximum"},
    {kEpidMaxEntriesErr, "entries already at maximum"},
    {kEpidBitSupplierErr, "request for random bits failed"},
    {kEpidBadCtxErr, "invalid context to function"},
    {kEpidBadGroupPubKeyErr, "invalid GroupPubKey to function"},
    {kEpidBadSignatureErr, "invalid Signature to function"},
    {kEpidBadNrProofErr, "invalid NrProof to function"},
    {kEpidBadPrivRlErr, "invalid PrivRl to function"},
    {kEpidBadSigRlErr, "invalid SigRl to function"},
    {kEpidBadSigRlEntryErr, "invalid SigRlEntry to function"},
    {kEpidBadGroupRlErr, "invalid GroupRl to function"},
    {kEpidBadVerifierRlErr, "invalid VerifierRl to function"},
    {kEpidBadPrecompErr, "invalid Precomp to function"},
    {kEpidBadBasenameErr, "invalid Basename to function"},
    {kEpidBadMessageErr, "invalid Message to function"},
    {kEpidBadRlEntryErr, "invalid RlEntry to function"},
    {kEpidBadIPrivKeyErr, "invalid issuing private key to function"},
    {kEpidBadGidErr, "invalid GroupId to function"},
    {kEpidBadPrivKeyErr, "invalid private key to function"},
    {kEpidBadNonceErr, "invalid nonce to function"},
    {kEpidBadMembershipCredentialErr, "invalid membership credential"},
    {kEpidBadRekeySeedErr, "invalid rekey seed to function"},
    {kEpidUnrelatedKeyPairErr, "unrelated key pair"},
    {kEpidBadConfigErr, "invalid configuration parameters to function"},
    {kEpidBasenameNotRegisteredErr, "basename not registered"},
    {kEpidBadArgErr, "bad arguments"}};

char const* EpidStatusToString(EpidStatus e) {
  size_t i = 0;
  const size_t num_entries = sizeof(kEnumToText) / sizeof(kEnumToText[0]);
  for (i = 0; i < num_entries; i++) {
    if (e == kEnumToText[i].value) {
      return kEnumToText[i].text;
    }
  }
  return "unknown error";
}
