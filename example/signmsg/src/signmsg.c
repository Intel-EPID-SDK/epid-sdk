/*############################################################################
  # Copyright 2016-2017 Intel Corporation
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
/// Message signing implementation.
/*!
 * \file
 *
 * This file has a corresponding walk-through in the SDK documentation.
 *
 * Review the walk-through for correctness after making changes to this
 * file.
 */
#include "src/signmsg.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "epid/common/file_parser.h"
#include "epid/member/api.h"
#include "src/prng.h"
#include "util/convutil.h"

EpidStatus SignMsg(void const* msg, size_t msg_len, void const* basename,
                   size_t basename_len, unsigned char const* signed_sig_rl,
                   size_t signed_sig_rl_size,
                   unsigned char const* signed_pubkey,
                   size_t signed_pubkey_size, unsigned char const* priv_key_ptr,
                   size_t privkey_size, HashAlg hash_alg,
                   MemberPrecomp* member_precomp, EpidSignature** sig,
                   size_t* sig_len, EpidCaCertificate const* cacert) {
  EpidStatus sts = kEpidErr;
  void* prng = NULL;
  MemberCtx* member = NULL;
  SigRl* sig_rl = NULL;

  do {
    GroupPubKey pub_key = {0};
    PrivKey priv_key = {0};
    MembershipCredential member_credential = {0};
    size_t sig_rl_size = 0;
    MemberParams params = {0};
    size_t member_size = 0;

    if (!sig) {
      sts = kEpidBadArgErr;
      break;
    }

    // authenticate and extract group public key
    sts = EpidParseGroupPubKeyFile(signed_pubkey, signed_pubkey_size, cacert,
                                   &pub_key);
    if (kEpidNoErr != sts) {
      break;
    }
    // handle compressed private key or membership credential
    if (privkey_size == sizeof(PrivKey)) {
      priv_key = *(PrivKey*)priv_key_ptr;
    } else if (privkey_size == sizeof(CompressedPrivKey)) {
      sts = EpidDecompressPrivKey(&pub_key, (CompressedPrivKey*)priv_key_ptr,
                                  &priv_key);
      if (kEpidNoErr != sts) {
        break;
      }
    } else if (privkey_size == sizeof(MembershipCredential)) {
      member_credential = *(MembershipCredential*)priv_key_ptr;
    } else {
      sts = kEpidErr;
      break;
    }  // if (privkey_size == sizeof(PrivKey))

    // acquire PRNG
    sts = PrngCreate(&prng);
    if (kEpidNoErr != sts) {
      break;
    }

    SetMemberParams(&PrngGen, prng, NULL, &params);
    // create member
    sts = EpidMemberGetSize(&params, &member_size);
    if (kEpidNoErr != sts) {
      break;
    }
    member = (MemberCtx*)calloc(1, member_size);
    if (!member) {
      sts = kEpidNoMemErr;
      break;
    }
    sts = EpidMemberInit(&params, member);
    if (kEpidNoErr != sts) {
      break;
    }

    sts = EpidMemberSetHashAlg(member, hash_alg);
    if (kEpidNoErr != sts) {
      break;
    }

    if (privkey_size == sizeof(PrivKey) ||
        privkey_size == sizeof(CompressedPrivKey)) {
      sts = EpidProvisionKey(member, &pub_key, &priv_key, member_precomp);
      if (kEpidNoErr != sts) {
        break;
      }
    } else if (privkey_size == sizeof(MembershipCredential)) {
      sts = EpidProvisionCredential(member, &pub_key, &member_credential,
                                    member_precomp);
      if (kEpidNoErr != sts) {
        break;
      }
    }  // if (privkey_size == sizeof(PrivKey))
    // start member
    sts = EpidMemberStartup(member);
    if (kEpidNoErr != sts) {
      break;
    }

    // register any provided basename as allowed
    if (0 != basename_len) {
      sts = EpidRegisterBasename(member, basename, basename_len);
      if (kEpidNoErr != sts) {
        break;
      }
    }

    if (signed_sig_rl) {
      // authenticate and determine space needed for SigRl
      sts = EpidParseSigRlFile(signed_sig_rl, signed_sig_rl_size, cacert, NULL,
                               &sig_rl_size);
      if (kEpidSigInvalid == sts) {
        // authentication failure
        break;
      }
      if (kEpidNoErr != sts) {
        break;
      }
      sig_rl = calloc(1, sig_rl_size);
      if (!sig_rl) {
        sts = kEpidMemAllocErr;
        break;
      }

      // fill the SigRl
      sts = EpidParseSigRlFile(signed_sig_rl, signed_sig_rl_size, cacert,
                               sig_rl, &sig_rl_size);
      if (kEpidSigInvalid == sts) {
        // authentication failure
        break;
      }
      if (kEpidNoErr != sts) {
        break;
      }

      sts = EpidMemberSetSigRl(member, sig_rl, sig_rl_size);
      if (kEpidNoErr != sts) {
        break;
      }
    }  // if (signed_sig_rl)

    // Signature
    // Note: Signature size must be computed after sig_rl is loaded.
    *sig_len = EpidGetSigSize(sig_rl);

    *sig = calloc(1, *sig_len);
    if (!*sig) {
      sts = kEpidMemAllocErr;
      break;
    }

    // sign message
    sts =
        EpidSign(member, msg, msg_len, basename, basename_len, *sig, *sig_len);
    if (kEpidNoErr != sts) {
      break;
    }
    sts = kEpidNoErr;
  } while (0);

  PrngDelete(&prng);
  EpidMemberDeinit(member);
  if (member) free(member);

  if (sig_rl) free(sig_rl);

  return sts;
}
