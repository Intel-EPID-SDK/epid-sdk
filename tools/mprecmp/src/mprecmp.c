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

/*!
 * \file
 * \brief Member data pre-compute implementation.
 */

#include <string.h>

#include "epid/member/api.h"
#include "src/mprecmp.h"

#include "util/envutil.h"

EpidStatus PrecomputeMemberData(GroupPubKey const* pub_key,
                                unsigned char const* priv_key_ptr,
                                size_t privkey_size,
                                MemberPrecomp* member_precomp) {
  EpidStatus sts = kEpidNoErr;
  PrivKey priv_key = {0};
  MembershipCredential member_credential = {0};
  MemberPrecomp precomp_blob = {0};
  do {
    // Process member private key or membership credential
    if (privkey_size == sizeof(PrivKey)) {
      priv_key = *(PrivKey*)priv_key_ptr;
    } else if (privkey_size == sizeof(CompressedPrivKey)) {
      sts = EpidDecompressPrivKey(pub_key, (CompressedPrivKey*)priv_key_ptr,
                                  &priv_key);
      if (kEpidNoErr != sts) {
        log_error("member private key decompression failed");
        break;
      }
    } else if (privkey_size == sizeof(MembershipCredential)) {
      member_credential = *(MembershipCredential*)priv_key_ptr;
    } else {
      sts = kEpidBadArgErr;
      log_error("private key file has invalid format");
      break;
    }  // if (privkey_size == sizeof(PrivKey))

    if (privkey_size != sizeof(MembershipCredential)) {
      member_credential.gid = priv_key.gid;
      member_credential.A = priv_key.A;
      member_credential.x = priv_key.x;
    }

    // Create member precomp blob
    sts = EpidMemberWritePrecomp(pub_key, &member_credential, &precomp_blob);
    if (kEpidNoErr != sts) {
      if (kEpidBadArgErr == sts) {
        // assuming pub_key is valid, the only bad agument is
        // MembershipCredential
        log_error("private key file has invalid format");
      } else {
        log_error("serialization of member precomp blob failed");
      }
      break;
    }
    *member_precomp = precomp_blob;
  } while (0);

  memset(&priv_key, 0, sizeof(PrivKey));
  memset(&member_credential, 0, sizeof(MembershipCredential));
  return sts;
}
