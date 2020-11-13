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

/*!
 * \file
 * \brief Member data pre-compute interface.
 */

#ifndef TOOLS_MPRECMP_SRC_MPRECMP_H_
#define TOOLS_MPRECMP_SRC_MPRECMP_H_

#include "epid/errors.h"
#include "epid/file_parser.h"
#include "epid/stdtypes.h"

/// Pre-compute Member data
EpidStatus PrecomputeMemberData(GroupPubKey const* pub_key,
                                unsigned char const* priv_key_ptr,
                                size_t privkey_size,
                                MemberPrecomp* member_precomp);

#endif  // TOOLS_MPRECMP_SRC_MPRECMP_H_
