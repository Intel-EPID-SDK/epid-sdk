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
/// TPM context structures
/*! \file */

#ifndef EPID_MEMBER_TPM_SRC_TYPES_H_
#define EPID_MEMBER_TPM_SRC_TYPES_H_

#include "epid/common/stdtypes.h"
#include "epid/common/bitsupplier.h"
#include "epid/common/types.h"

/// \cond
typedef struct EcPoint EcPoint;
typedef struct FfElement FfElement;
typedef struct Stack Stack;
typedef struct Epid2Params_ Epid2Params_;
/// \endcond

/// Sensitive Tpm values
typedef struct TpmSecrets {
  Seed const seed;       ///< Provisioned seed for compressed key
  FfElement const* f;    ///< Member private key f value
  Stack* presigs;        ///< Pre-computed signature pool
  void* rnd_param;       ///< Pointer to user context for rnd_func
  FfElement* a;          ///< Sign related random value
  FfElement* b;          ///< Sign related intermediate value
  FfElement* rx;         ///< Sign related random value
  FfElement* rf;         ///< Sign related random value
  FfElement* ra;         ///< Sign related random value
  FfElement* rb;         ///< Sign related random value
  FfElement* mu;         ///< Nr Proof related random value
  FfElement* nu;         ///< Nr Proof related random value
  FfElement* rmu;        ///< Nr Proof related random value
  FfElement* rnu;        ///< Nr Proof related random value
  FfElement* r;          ///< Join related random value
  bool sign_pending;     ///< split sign in progress
  bool nrprove_pending;  ///< split Nr Proof in progress
  bool join_pending;     ///< split Nr Proof in progress
} TpmSecrets;

/// TPM State
typedef struct TpmCtx {
  Epid2Params_ const* epid2_params;  ///< Intel(R) EPID 2.0 params
  TpmSecrets secret;     ///< Tpm information that must be stored securely
  BitSupplier rnd_func;  ///< Pseudo random number generation function
  EcPoint const* h1;     ///< Group public key h1 value
  EcPoint const* h2;     ///< Group group public key h2 value
  EcPoint const* A;      ///< Membership Credential A value
  FfElement const* x;    ///< Membership Credential x value
  EcPoint const* w;      ///< Group group public key w value
  FfElement const* e12;  ///< an element in GT, = pairing (h1, g2)
  FfElement const* e22;  ///< an element in GT, = pairing (h2, g2)
  FfElement const* e2w;  ///< an element in GT, = pairing (h2, w)
  FfElement const* ea2;  ///< an element in GT, = pairing (g1, g2)
} TpmCtx;

/// Pre-computed signature.
/*!
 Serialized form of an intermediate signature that does not depend on
 basename or message. This can be used to time-shift compute time needed to
 sign a message.
 */
#pragma pack(1)
typedef struct PreComputedSignature {
  G1ElemStr B;   ///< an element in G1
  G1ElemStr K;   ///< an element in G1
  G1ElemStr T;   ///< an element in G1
  G1ElemStr R1;  ///< an element in G1
  GtElemStr R2;  ///< an element in G1
  FpElemStr a;   ///< an integer between [0, p-1]
  FpElemStr b;   ///< an integer between [0, p-1]
  FpElemStr rx;  ///< an integer between [0, p-1]
  FpElemStr rf;  ///< an integer between [0, p-1]
  FpElemStr ra;  ///< an integer between [0, p-1]
  FpElemStr rb;  ///< an integer between [0, p-1]
} PreComputedSignature;
#pragma pack()

#endif  // EPID_MEMBER_TPM_SRC_TYPES_H_
