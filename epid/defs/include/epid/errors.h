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
/// Error reporting.
/*! \file */
#ifndef EPID_DEFS_INCLUDE_EPID_ERRORS_H_
#define EPID_DEFS_INCLUDE_EPID_ERRORS_H_

/// Error reporting interface.
/*!
 \defgroup ErrorCodes errors
 This module defines the return status type. It also provides tools for
 interactions with status values, such as converting them to a string.

 \ingroup EpidCommon
  @{
*/

/// Return status for SDK functions.
/*!
  Convention for status values is as follows:
  - Zero indicates "success"
  - Any positive number indicates "success with status"
  - Any negative number indicates "failure"
*/
typedef enum {
  kEpidNoErr = 0,                   //!< no error
  kEpidSigValid = 0,                //!< Signature is valid
  kEpidSigInvalid = 1,              //!< Signature is invalid
  kEpidSigRevokedInGroupRl = 2,     //!< Signature revoked in GroupRl
  kEpidSigRevokedInPrivRl = 3,      //!< Signature revoked in PrivRl
  kEpidSigRevokedInSigRl = 4,       //!< Signature revoked in SigRl
  kEpidSigRevokedInVerifierRl = 5,  //!< Signature revoked in VerifierRl
  kEpidErr = -999,                  //!< unspecified error
  kEpidNotImpl,                     //!< not implemented error
  kEpidNoMemErr,                    //!< not enough memory for the operation
  kEpidMemAllocErr,                 //!< could not allocate memory for operation
  kEpidMathErr,                     //!< internal math error
  kEpidDivByZeroErr,                //!< an attempt to divide by zero
  kEpidUnderflowErr,  //!< a value became less than minimum supported level
  kEpidHashAlgorithmNotSupported,  //!< unsupported hash algorithm type
  kEpidRandMaxIterErr,  //!< reached max iteration for random number generation
  kEpidDuplicateErr,    //!< argument would add duplicate entry
  kEpidInconsistentBasenameSetErr,    //!< set basename conflicts with arguments
  kEpidMathQuadraticNonResidueError,  //!< quadratic Non-Residue Error
  kEpidOutOfSequenceError,     //!< operation was performed out of sequence
  kEpidBadJoinRequestErr,      //!< Join Request is invalid
  kEpidSchemaNotSupportedErr,  //!< format not supported by this version of SDK
  kEpidOperationNotSupportedErr,  //!< operation called is not supported by SDK
  kEpidKeyNotInGroupErr,          //!< private key is not in the group
  kEpidPrecompNotInGroupErr,      //!< input Precomp is not in the group
  kEpidVersionMismatchErr,        //!< version mismatch error,
  kEpidGroupIdMismatchErr,        //!< group id miss match
  kEpidMaxVersionErr,             //!< version already at maximum
  kEpidMaxEntriesErr,             //!< entries already at maximum
  kEpidBitSupplierErr,            //!< request for random bits failed
  kEpidBadCtxErr,                 //!< invalid Context to function
  kEpidBadGroupPubKeyErr,         //!< invalid GroupPubKey to function
  kEpidBadSignatureErr,           //!< invalid Signature to function
  kEpidBadNrProofErr,             //!< invalid NrProof to function
  kEpidBadPrivRlErr,              //!< invalid PrivRl to function
  kEpidBadSigRlErr,               //!< invalid SigRl to function
  kEpidBadSigRlEntryErr,          //!< invalid SigRlEntry to function
  kEpidBadGroupRlErr,             //!< invalid GroupRl to function
  kEpidBadVerifierRlErr,          //!< invalid VerifierRl to function
  kEpidBadPrecompErr,             //!< invalid Precomp to function
  kEpidBadBasenameErr,            //!< invalid Basename to function
  kEpidBadMessageErr,             //!< invalid Message to function
  kEpidBadRlEntryErr,             //!< invalid RLEntry to function
  kEpidBadIPrivKeyErr,            //!< invalid issuing private key to function
  kEpidBadGidErr,                 //!< invalid GroupId to function
  kEpidBadPrivKeyErr,             //!< invalid private key to function
  kEpidBadNonceErr,               //!< invalid nonce to function
  kEpidBadMembershipCredentialErr,  //!< invalid membership credential to func
  kEpidBadRekeySeedErr,             //!< invalid rekey seed to function
  kEpidUnrelatedKeyPairErr,         //!< unrelated key pair
  kEpidBadConfigErr,  //!< invalid configuration parameters to function
  kEpidBasenameNotRegisteredErr,  //!< basename not registered
  // add new badarg errors here
  kEpidBadArgErr,  //!< General purpose bad argument error
} EpidStatus;

/// Checks if status code is a badarg error
#define EPID_IS_BADARG_ERROR(sts) \
  ((sts >= kEpidBadCtxErr && sts <= kEpidBadArgErr) ? 1 : 0)

/// Returns string representation of error code.
/*!
 \param e
 The status value.

 \returns The string describing the status.
*/
char const* EpidStatusToString(EpidStatus e);

/*! @} */
#endif  // EPID_DEFS_INCLUDE_EPID_ERRORS_H_
