/*############################################################################
  # Copyright 2018-2019 Intel Corporation
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
/// Signature types
/*!
 * \file
 * \addtogroup EpidCommon
 * @{
 */
#ifndef EPID_INTERNAL_COMMON_INCLUDE_COMMON_SIG_TYPES_H_
#define EPID_INTERNAL_COMMON_INCLUDE_COMMON_SIG_TYPES_H_

#include "epid/types.h"

/// Type of a signature
typedef enum EpidSigType {
  kSigUnknown,   //< Unknown signature type
  kSigNonSplit,  //< Non-split signature type
  kSigSplit      //< Split signature type
} EpidSigType;

/// Returns a non split signature's revocation list count
/*!

\param[in] sig
Non Split signature

\returns size_t number of nrproofs in a non split signature
*/
size_t EpidGetSignatureRlCount(EpidNonSplitSignature const* sig);

/// Returns a split signature's revocation list count
/*!

\param[in] sig
Split signature

\returns size_t number of nrproofs in a split signature
*/
size_t EpidGetSplitSignatureRlCount(EpidSplitSignature const* sig);

/// Infer type of a signature from its content
/*!

\param[in] sig_data
Split signature or non split signature
\param[in] sig_len
Size of signature

\returns kSigNonSplit if sig_data detected to be non split signature
\returns kSigSplit if sig_data detected to be split signature
\returns kSigUnknown if sig_data not a known signature
*/
EpidSigType EpidDetectSigType(void const* sig_data, size_t sig_len);

/*! @} */
#endif  // EPID_INTERNAL_COMMON_INCLUDE_COMMON_SIG_TYPES_H_
