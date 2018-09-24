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
/// Group ID parsing interface
/*! \file */
#ifndef EPID_COMMON_SRC_GID_PARSER_H_
#define EPID_COMMON_SRC_GID_PARSER_H_

#include "epid/common/errors.h"
#include "epid/common/types.h"

/// Extracts hash algorithm encoded in the Group ID
/*!

  \param[in] gid
  Pointer to buffer containing the group ID to parse.

  \param[out] hash_alg
  The extracted hash algorithm to use.

  \returns ::EpidStatus

  \retval ::kEpidSchemaNotSupportedErr
  The version of the GID is not supported.

*/
EpidStatus EpidParseHashAlg(GroupId const* gid, HashAlg* hash_alg);

#endif  // EPID_COMMON_SRC_GID_PARSER_H_
