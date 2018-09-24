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
/// Group ID parsing implementation
/*! \file */

#include "epid/member/tiny/src/gid_parser.h"

#define SCHEMA_VERSION(gid) ((gid->data[0] & 0xf0) >> 4)

EpidStatus EpidTinyParseHashAlg(GroupId const* gid, HashAlg* hash_alg) {
  if (!gid || !hash_alg) {
    return kEpidBadArgErr;
  }
  switch (SCHEMA_VERSION(gid)) {
    case 0:
      switch (gid->data[1] & 0x0f) {
        case 0:
          *hash_alg = kSha256;
          break;
        case 1:
          *hash_alg = kSha384;
          break;
        case 2:
          *hash_alg = kSha512;
          break;
        case 3:
          *hash_alg = kSha512_256;
          break;
        case 4:
          *hash_alg = kSha3_256;
          break;
        case 5:
          *hash_alg = kSha3_384;
          break;
        case 6:
          *hash_alg = kSha3_512;
          break;
        default:
          return kEpidHashAlgorithmNotSupported;
      }
      break;
    default:
      return kEpidSchemaNotSupportedErr;
  }
  return kEpidNoErr;
}
