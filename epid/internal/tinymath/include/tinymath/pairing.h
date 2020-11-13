/*############################################################################
  # Copyright 2017-2020 Intel Corporation
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
/// Definition of pairing math
/*! \file */

#ifndef EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_PAIRING_H_
#define EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_PAIRING_H_
#ifdef __cplusplus
extern "C" {
#endif

/// \cond
typedef struct Fq12Elem Fq12Elem;
typedef struct EccPointFq EccPointFq;
typedef struct EccPointFq2 EccPointFq2;
typedef struct PairingState PairingState;
/// \endcond

/// Initializes pairing environment.
/*!
\param[out] state pairing state information.
*/
void PairingInit(PairingState* state);

/// Computes a pairing according to the Optimal Ate pairing computation
/*!
\param[out] d target, an element in GT.
\param[in] P an element in G1.
\param[in] Q an element in G2.
\param[in,out] state pairing state information.
*/
void PairingCompute(Fq12Elem* d, EccPointFq const* P, EccPointFq2 const* Q,
                    PairingState const* state);

#ifdef __cplusplus
}
#endif
#endif  // EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_PAIRING_H_
