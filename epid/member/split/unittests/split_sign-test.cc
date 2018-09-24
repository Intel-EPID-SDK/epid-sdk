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
/// Sign with split signature unit tests.
/*! \file */
#include <cstring>
#include <vector>
#include "gtest/gtest.h"

extern "C" {
#include "epid/common/src/endian_convert.h"
#include "epid/common/src/sig_types.h"
#include "epid/member/api.h"
#include "epid/member/split/src/context.h"
#include "epid/verifier/api.h"
}

#include "epid/common-testhelper/errors-testhelper.h"
#include "epid/common-testhelper/onetimepad.h"
#include "epid/common-testhelper/prng-testhelper.h"
#include "epid/common-testhelper/verifier_wrapper-testhelper.h"
#include "epid/member/split/unittests/member-testhelper.h"

bool operator==(EpidSplitSignature const& lhs, EpidSplitSignature const& rhs) {
  return 0 == std::memcmp(&lhs, &rhs, sizeof(lhs));
}

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

namespace {
void set_gid_hashalg(GroupId* id, HashAlg hashalg) {
  id->data[1] = (id->data[1] & 0xf0) | (hashalg & 0x0f);
}

const GroupPubKey kEps0GroupPublicKey_sha256 = {
#include "epid/common-testhelper/testdata/grp_sha256/pubkey.inc"
};

const PrivKey kEps0MemberPrivateKey_sha256 = {
#include "epid/common-testhelper/testdata/grp_sha256/member_eps0/split_credential.inc"

#include "epid/common-testhelper/testdata/grp_sha256/member_eps0/f.inc"
};

const GroupPubKey kEps0GroupPublicKey_sha384 = {
#include "epid/common-testhelper/testdata/grp_sha384/pubkey.inc"
};

const PrivKey kEps0MemberPrivateKey_sha384 = {
#include "epid/common-testhelper/testdata/grp_sha384/member_eps0/split_credential.inc"

#include "epid/common-testhelper/testdata/grp_sha384/member_eps0/f.inc"
};

const GroupPubKey kEps0GroupPublicKey_sha512 = {
#include "epid/common-testhelper/testdata/grp_sha512/pubkey.inc"
};

const PrivKey kEps0MemberPrivateKey_sha512 = {
#include "epid/common-testhelper/testdata/grp_sha512/member_eps0/split_credential.inc"

#include "epid/common-testhelper/testdata/grp_sha512/member_eps0/f.inc"
};

static const std::vector<uint8_t> kSigRl5EntrySha256Data = {
    // gid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7f, 0xff, 0xff, 0xee,
    // version
    0x00, 0x00, 0x00, 0x00,
    // n2
    0x00, 0x00, 0x00, 0x05,
    // bk's
    0x9c, 0xa5, 0xe5, 0xae, 0x5f, 0xae, 0x51, 0x59, 0x33, 0x35, 0x27, 0xd, 0x8,
    0xb1, 0xbe, 0x5d, 0x69, 0x50, 0x84, 0xc5, 0xfe, 0xe2, 0x87, 0xea, 0x2e,
    0xef, 0xfa, 0xee, 0x67, 0xf2, 0xd8, 0x28, 0x56, 0x43, 0xc6, 0x94, 0x67,
    0xa6, 0x72, 0xf6, 0x41, 0x15, 0x4, 0x58, 0x42, 0x16, 0x88, 0x57, 0x9d, 0xc7,
    0x71, 0xd1, 0xc, 0x84, 0x13, 0xa, 0x90, 0x23, 0x18, 0x8, 0xad, 0x7d, 0xfe,
    0xf5, 0xc8, 0xae, 0xfc, 0x51, 0x40, 0xa7, 0xd1, 0x28, 0xc2, 0x89, 0xb2,
    0x6b, 0x4e, 0xb4, 0xc1, 0x55, 0x87, 0x98, 0xbd, 0x72, 0xf9, 0xcf, 0xd, 0x40,
    0x15, 0xee, 0x32, 0xc, 0xf3, 0x56, 0xc5, 0xc, 0x61, 0x9d, 0x4f, 0x7a, 0xb5,
    0x2b, 0x16, 0xa9, 0xa3, 0x97, 0x38, 0xe2, 0xdd, 0x3a, 0x33, 0xad, 0xf6,
    0x7b, 0x68, 0x8b, 0x68, 0xcf, 0xa3, 0xd3, 0x98, 0x37, 0xce, 0xec, 0xd1,
    0xa8, 0xc, 0x8b,

    0x71, 0x8a, 0xb5, 0x1, 0x7f, 0x7c, 0x92, 0x9a, 0xa2, 0xc9, 0x81, 0x10, 0xfe,
    0xbf, 0xc, 0x53, 0xa4, 0x43, 0xaf, 0x31, 0x74, 0x12, 0x25, 0x60, 0x3e, 0xc0,
    0x21, 0xe6, 0x63, 0x9a, 0xd2, 0x67, 0x2d, 0xb5, 0xd5, 0x82, 0xc4, 0x49,
    0x29, 0x51, 0x42, 0x8f, 0xe0, 0xe, 0xd1, 0x73, 0x27, 0xf5, 0x77, 0x16, 0x4,
    0x40, 0x8a, 0x0, 0xe, 0x3a, 0x5d, 0x37, 0x42, 0xd3, 0x8, 0x40, 0xbd, 0x69,
    0xf7, 0x5f, 0x74, 0x21, 0x50, 0xf4, 0xce, 0xfe, 0xd9, 0xdd, 0x97, 0x6c,
    0xa8, 0xa5, 0x60, 0x6b, 0xf8, 0x1b, 0xba, 0x2, 0xb2, 0xca, 0x5, 0x44, 0x9b,
    0xb1, 0x5e, 0x3a, 0xa4, 0x35, 0x7a, 0x51, 0xfa, 0xcf, 0xa4, 0x4, 0xe9, 0xf3,
    0xbf, 0x38, 0xd4, 0x24, 0x9, 0x52, 0xf3, 0x58, 0x3d, 0x9d, 0x4b, 0xb3, 0x37,
    0x4b, 0xec, 0x87, 0xe1, 0x64, 0x60, 0x3c, 0xb6, 0xf7, 0x7b, 0xff, 0x40,
    0x11,

    0x6e, 0x22, 0xaa, 0x10, 0x84, 0x58, 0x8b, 0xff, 0xd8, 0x37, 0x8, 0xa9, 0xe9,
    0xdb, 0xf6, 0x1f, 0x69, 0x10, 0x95, 0x6c, 0xbf, 0xd, 0x11, 0x48, 0x6f, 0x1b,
    0x3c, 0x62, 0x46, 0x13, 0x89, 0x13, 0x5f, 0xa1, 0x3, 0x62, 0xed, 0x62, 0xdf,
    0x3d, 0xbf, 0xcd, 0xb7, 0x41, 0x48, 0x81, 0x3, 0x9f, 0x54, 0xa, 0xe, 0xb3,
    0x35, 0xf9, 0xde, 0x24, 0xba, 0x6d, 0x4c, 0x7f, 0xfc, 0xc1, 0xb4, 0xce,
    0x6d, 0xa1, 0x73, 0x7c, 0xaa, 0xb, 0xad, 0x2, 0xd6, 0x37, 0x85, 0xe, 0xbb,
    0x48, 0x11, 0x38, 0xc4, 0xaa, 0x1b, 0xf, 0xcf, 0xc1, 0x9c, 0x26, 0xcc, 0x95,
    0xc2, 0x5b, 0x49, 0x9, 0x3d, 0xe9, 0x7d, 0xce, 0xc7, 0xa6, 0x4, 0x3e, 0x7c,
    0x9e, 0x28, 0xde, 0x8, 0x11, 0xe, 0x61, 0x3b, 0xc0, 0x9c, 0x6b, 0x58, 0x23,
    0xe6, 0x40, 0x7b, 0xbd, 0xb8, 0x72, 0xf, 0xe0, 0xee, 0xcf, 0xba, 0xb4,

    0xc4, 0xff, 0xaf, 0x48, 0x15, 0xda, 0x60, 0x40, 0xcc, 0xd7, 0xf2, 0x68,
    0xf7, 0xe2, 0x70, 0x12, 0x8d, 0x15, 0xa5, 0xb7, 0xe6, 0x4c, 0x23, 0xea,
    0x4d, 0x8a, 0x51, 0x6, 0x67, 0x3, 0x4c, 0x83, 0x6f, 0x28, 0x67, 0xcf, 0x63,
    0x46, 0x3e, 0x8a, 0x45, 0x9f, 0xed, 0x1a, 0xde, 0xa7, 0xad, 0xb2, 0x2b, 0xf,
    0x8b, 0xab, 0x7c, 0x70, 0xff, 0xc3, 0xa8, 0x6e, 0x8c, 0xaa, 0xb1, 0xf6,
    0x20, 0xe3, 0xb9, 0xf1, 0xc3, 0x3d, 0x5, 0x6a, 0x1e, 0x26, 0x2d, 0xf4, 0xd,
    0xe4, 0x53, 0x63, 0x67, 0x23, 0x48, 0xa8, 0x1, 0xa8, 0xee, 0xe1, 0x5f, 0x64,
    0xe3, 0x2c, 0x71, 0xe2, 0x10, 0x82, 0x0, 0x52, 0xd7, 0x74, 0x87, 0xff, 0x1c,
    0x0, 0x19, 0xe6, 0x4d, 0x15, 0x91, 0x6d, 0xf3, 0x38, 0x3b, 0xee, 0xf3, 0xd5,
    0xd1, 0xc7, 0x6d, 0xd9, 0x8e, 0x55, 0x70, 0x90, 0xb0, 0xb, 0x3c, 0x4a, 0x67,
    0x19,

    0x4f, 0x98, 0x92, 0xf9, 0x18, 0x38, 0xf5, 0xb4, 0xf7, 0x2f, 0xa7, 0x21,
    0x71, 0x52, 0x27, 0xd0, 0x57, 0x4f, 0x9c, 0x30, 0xe, 0xb2, 0x27, 0xce, 0xd7,
    0xb2, 0x9f, 0xc0, 0xf6, 0xc3, 0xb0, 0x7c, 0x40, 0x18, 0x75, 0x4a, 0xde,
    0xb0, 0x9f, 0x46, 0x8a, 0x5a, 0xeb, 0x4f, 0xcb, 0x5e, 0x60, 0xf5, 0xca,
    0xf4, 0x98, 0xaf, 0x62, 0x9b, 0x7e, 0x10, 0xda, 0xba, 0x2f, 0x47, 0x64,
    0xf2, 0xc0, 0x84, 0x19, 0x75, 0xe0, 0xe4, 0xff, 0x20, 0xda, 0x7d, 0xe5, 0xd,
    0xc8, 0xf8, 0xe3, 0x83, 0x61, 0x19, 0x17, 0xf1, 0xa9, 0x1b, 0xff, 0x39,
    0x79, 0x88, 0x1, 0xfb, 0xe7, 0x23, 0xd2, 0xac, 0xe0, 0x49, 0x12, 0x2a, 0x38,
    0xb4, 0x7c, 0xc2, 0x1b, 0x88, 0x5f, 0x68, 0x32, 0x11, 0xd9, 0xfd, 0xdc,
    0x65, 0x2, 0xb3, 0x74, 0x2c, 0x13, 0xf2, 0xd8, 0xf1, 0x45, 0xc5, 0xd1, 0xf4,
    0xa3, 0x38, 0x81, 0x92};
static const std::vector<uint8_t> kMsg0 = {'m', 's', 'g', '0'};
static const std::vector<uint8_t> kBsn0 = {'b', 's', 'n', '0'};
const std::vector<uint8_t> kTest1Msg = {'t', 'e', 's', 't', '1'};
const std::vector<uint8_t> kBasename1 = {'b', 'a', 's', 'e', 'n',
                                         'a', 'm', 'e', '1'};
static const std::vector<uint8_t> kData_0_255 = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
    0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53,
    0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
    0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83,
    0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3,
    0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb,
    0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
    0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
    0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    0xfc, 0xfd, 0xfe, 0xff,
};

const MemberPrecomp kMember3Sha256Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha256_01.inc"
};
const MemberPrecomp kMember3Sha512Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha512_01.inc"
};
const MemberPrecomp kMember3Sha384Precomp = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitprecomp_grpx_member3_sha384_01.inc"
};
static const GroupPubKey kGrpXKey = {
#include "epid/common-testhelper/testdata/grp_x/pubkey.inc"
};
static const PrivKey kGrpXMember3Sha256PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha256_01.inc"
};
static const PrivKey kGrpXMember3Sha512PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha512_01.inc"
};
static const PrivKey kGrpXMember3Sha384PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha384_01.inc"
};
static const PrivKey kGrpXMember3Sha512256PrivKey = {
#include "epid/common-testhelper/testdata/grp_x/member3/mprivkey_sha512_256_01.inc"
};
static const std::vector<uint8_t> kGrpXSigRl = {
#include "epid/common-testhelper/testdata/grp_x/sigrl.inc"
};

/// data for OneTimePad to be used in BasicSign: without rf and nonce
const std::vector<uint8_t> kOtpDataWithoutRfAndNonce = {
    // entropy of EpidMemberIsKeyValid
    // r in Tpm2Commit =
    // 0x531201cf42e8946136e516c3651a8b04c826283ab43829926e9277902962f15f
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x53, 0x12, 0x01, 0xcf, 0x42, 0xe8, 0x94, 0x61,
    0x36, 0xe5, 0x16, 0xc3, 0x65, 0x1a, 0x8b, 0x04, 0xc8, 0x26, 0x28, 0x3a,
    0xb4, 0x38, 0x29, 0x92, 0x6e, 0x92, 0x77, 0x90, 0x29, 0x62, 0xf1, 0x5f,
    // noncek =
    // 0xe95408071241a77b0871d175c90185241ed61b5a150793015c903154d2636773
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xe9, 0x54, 0x08, 0x07, 0x12, 0x41, 0xa7, 0x7b,
    0x08, 0x71, 0xd1, 0x75, 0xc9, 0x01, 0x85, 0x24, 0x1e, 0xd6, 0x1b, 0x5a,
    0x15, 0x07, 0x93, 0x01, 0x5c, 0x90, 0x31, 0x54, 0xd2, 0x63, 0x67, 0x73,
    // entropy for other operations
    // bsn in presig
    0x25, 0xeb, 0x8c, 0x48, 0xff, 0x89, 0xcb, 0x85, 0x4f, 0xc0, 0x90, 0x81,
    0xcc, 0x47, 0xed, 0xfc, 0x86, 0x19, 0xb2, 0x14, 0xfe, 0x65, 0x92, 0xd4,
    0x8b, 0xfc, 0xea, 0x9c, 0x9d, 0x8e, 0x32, 0x44,
    // r in presig =
    // 0xcf8b90f4428aaf7e9b2244d1db16848230655550f2c52b1fc53b3031f8108bd4
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xcf, 0x8b, 0x90, 0xf4, 0x42, 0x8a, 0xaf, 0x7e,
    0x9b, 0x22, 0x44, 0xd1, 0xdb, 0x16, 0x84, 0x82, 0x30, 0x65, 0x55, 0x50,
    0xf2, 0xc5, 0x2b, 0x1f, 0xc5, 0x3b, 0x30, 0x31, 0xf8, 0x10, 0x8b, 0xd4,
    // a = 0xfb883ef100727d4e46e3e906b96e49c68b2abe1f44084cc0ed5c5ece66afa7e9
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xfb, 0x88, 0x3e, 0xf1, 0x00, 0x72, 0x7d, 0x4e,
    0x46, 0xe3, 0xe9, 0x06, 0xb9, 0x6e, 0x49, 0xc6, 0x8b, 0x2a, 0xbe, 0x1f,
    0x44, 0x08, 0x4c, 0xc0, 0xed, 0x5c, 0x5e, 0xce, 0x66, 0xaf, 0xa7, 0xe8,
    // rx = 0xa1d62c80fcc1d60819271c86139880fabd27078b5dd9144c2f1dc6182fa24d4c
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xa1, 0xd6, 0x2c, 0x80, 0xfc, 0xc1, 0xd6, 0x08,
    0x19, 0x27, 0x1c, 0x86, 0x13, 0x98, 0x80, 0xfa, 0xbd, 0x27, 0x07, 0x8b,
    0x5d, 0xd9, 0x14, 0x4c, 0x2f, 0x1d, 0xc6, 0x18, 0x2f, 0xa2, 0x4d, 0x4b,
    // rb = 0xf6910e4edc90439572c6a46852ec550adec1b1bfd3928996605e9aa6ff97c97c
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf6, 0x91, 0x0e, 0x4e, 0xdc, 0x90, 0x43, 0x95,
    0x72, 0xc6, 0xa4, 0x68, 0x52, 0xec, 0x55, 0x0a, 0xde, 0xc1, 0xb1, 0xbf,
    0xd3, 0x92, 0x89, 0x96, 0x60, 0x5e, 0x9a, 0xa6, 0xff, 0x97, 0xc9, 0x7b,
    // ra = 0x1e1e6372e53fb6a92763135b148310703e5649cfb7954d5d623aa4c1654d3147
    // OctStr representation:
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x1e, 0x1e, 0x63, 0x72, 0xe5, 0x3f, 0xb6, 0xa9,
    0x27, 0x63, 0x13, 0x5b, 0x14, 0x83, 0x10, 0x70, 0x3e, 0x56, 0x49, 0xcf,
    0xb7, 0x95, 0x4d, 0x5d, 0x62, 0x3a, 0xa4, 0xc1, 0x65, 0x4d, 0x31, 0x46};
/// data for OneTimePad to be used in BasicSign: rf in case bsn is passed
const std::vector<uint8_t> rf = {
    // rf = 0xb8b17a99305d417ee3a4fb67a60a41021a3730c05efac141d5a49b870d721d8b
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb8, 0xb1, 0x7a, 0x99, 0x30, 0x5d, 0x41, 0x7e,
    0xe3, 0xa4, 0xfb, 0x67, 0xa6, 0x0a, 0x41, 0x02, 0x1a, 0x37, 0x30, 0xc0,
    0x5e, 0xfa, 0xc1, 0x41, 0xd5, 0xa4, 0x9b, 0x87, 0x0d, 0x72, 0x1d, 0x8b,
};
// entropy for EpidNrProve
const std::vector<uint8_t> NrProveEntropy = {
    // mu
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x9e, 0x7d, 0x36, 0x67, 0x24, 0x65, 0x9e, 0xf5,
    0x7b, 0x34, 0x2c, 0x42, 0x71, 0x4b, 0xb2, 0x58, 0xcd, 0x3d, 0x94, 0xe9,
    0x35, 0xe7, 0x37, 0x0a, 0x58, 0x32, 0xb6, 0xa5, 0x9d, 0xbf, 0xe4, 0xcb,
    // r in Tpm2Commit in PrivateExp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x90, 0x28, 0x6d, 0x75, 0xd5, 0x44, 0x60, 0x47,
    0xe0, 0x4c, 0xf9, 0x23, 0xd2, 0x51, 0x6c, 0xca, 0xf2, 0xad, 0xd7, 0x50,
    0xd9, 0x59, 0x7d, 0x19, 0x1c, 0x53, 0x93, 0xc3, 0x75, 0x8b, 0x83, 0x6b,
    // noncek in Tpm2Sign in PrivateExp
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x82, 0x05, 0x02, 0x51, 0x5d, 0xdf, 0xa9, 0x33,
    0xce, 0x98, 0x8e, 0x95, 0xf0, 0xb5, 0x79, 0x99, 0xfe, 0xf4, 0x95, 0x33,
    0xa9, 0x23, 0x7a, 0x67, 0x60, 0xf6, 0x32, 0x5d, 0xbd, 0xfb, 0x89, 0xfa,
    // rmu
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xb4, 0x5f, 0x9c, 0x41, 0x89, 0x3c, 0xe3, 0x30,
    0x54, 0xeb, 0xa2, 0x22, 0x1b, 0x2b, 0xc4, 0xcd, 0x8f, 0x7b, 0xc8, 0xb1,
    0x1b, 0xca, 0x6f, 0x68, 0xd4, 0x9f, 0x27, 0xd9, 0xc1, 0xe5, 0xc7, 0x6d,
    // r in Tpm2Commit
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x5a, 0x1e, 0x86, 0x82, 0x29, 0x90, 0x2d, 0x57,
    0x46, 0x57, 0xa8, 0x0c, 0x73, 0xe7, 0xd4, 0xaa, 0x01, 0x11, 0x11, 0xde,
    0xd6, 0x1a, 0x58, 0x21, 0x62, 0x80, 0x2f, 0x25, 0x68, 0x23, 0xbd, 0x04,
    // noncek
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xac, 0x72, 0x37, 0x44, 0xe6, 0x90, 0x30, 0x5f,
    0x17, 0xf5, 0xf5, 0xf1, 0x9e, 0x81, 0xa9, 0x81, 0x2c, 0x7a, 0xa7, 0x37,
    0x52, 0xf6, 0x0e, 0xd3, 0xaa, 0x6c, 0x9f, 0x46, 0xf7, 0x3b, 0x2d, 0x52};
/// data for OneTimePad to be used in BasicSign: noncek of split sign
const std::vector<uint8_t> kNoncek = {
    // noncek =
    // 0x19e236b64f315e832b5ac5b68fe75d4b7c0d5f52d6cd979f76d3e7d959627f2e
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0xe2, 0x36, 0xb6, 0x4f, 0x31, 0x5e, 0x83,
    0x2b, 0x5a, 0xc5, 0xb6, 0x8f, 0xe7, 0x5d, 0x4b, 0x7c, 0x0d, 0x5f, 0x52,
    0xd6, 0xcd, 0x97, 0x9f, 0x76, 0xd3, 0xe7, 0xd9, 0x59, 0x62, 0x7f, 0x2e,
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseTest1 = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_test1_5_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1Test1WithSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_test1_5_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256MlnTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_million_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256kData_0_255Msg0NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_bsn0255_msg0_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha512RandombaseTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha512_rndbase_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha384RandombaseTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha384_rndbase_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha512256RndbaseTest1NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha512_256_rndbase_test1_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1EmptyNoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_empty_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256Basename1EmptyWithSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_basename1_empty_5_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RndBsnData_0_255NoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_msg0255_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseMlnNoSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_million_no_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256RandombaseMlnWithSigRl = {
#include "epid/common-testhelper/testdata/grp_x/member3/splitsig_sha256_rndbase_million_5_sigrl.inc"
};
const std::vector<uint8_t> kSplitSigGrpXMember3Sha256HugeBsnMsg0WithSigRl = {
#include "epid/common-testhelper/testdata/split/grp_x/member3/splitsig_sha256_hugebsn_msg0_1_sigrl.inc"
};

// NOTE: Do not run these tests in TPM HW mode because some of the data is
// generated randomly inside TPM and will not match with precomputed data
#ifndef TPM_TSS
/////////////////////////////////////////////////////////////////////////
// Variable basename
TEST_F(EpidMemberSplitSignTest, SignsMessageUsingRandomBaseNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingRandomBaseWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256RandombaseTest1.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingBasenameNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256Basename1Test1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                 bsn.size(), sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}
TEST_F(EpidMemberSplitSignTest, SignsMessageUsingBasenameWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256Basename1Test1WithSigRl.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                 bsn.size(), sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsUsingRandomBaseWithRegisteredBasenamesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsUsingRandomBaseWithRegisteredBasenamesWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  auto& bsn = kBasename1;
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256RandombaseTest1.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsUsingRandomBaseWithoutRegisteredBasenamesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsUsingRandomBaseWithoutRegisteredBasenamesWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  memset(sig, 0, sizeof(EpidSplitSignature));
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256RandombaseTest1.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingHugeBasenameNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> bsn(1024 * 1024);  // exactly 1 MB
  uint8_t c = 0;
  for (size_t i = 0; i < bsn.size(); ++i) {
    bsn[i] = c++;
  }
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256MlnTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                 bsn.size(), sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingHugeBasenameWithSigRl) {
  auto sig_rl_data_n2_one = kSigRl5EntrySha256Data;
  SigRl* srl = reinterpret_cast<SigRl*>(sig_rl_data_n2_one.data());
  srl->n2.data[sizeof(srl->n2) - 1] = 0x01;
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  otp_data.insert(otp_data.end(), NrProveEntropy.begin(), NrProveEntropy.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  std::vector<uint8_t> bsn(1024 * 1024);  // exactly 1 MB
  uint8_t c = 0;
  for (size_t i = 0; i < bsn.size(); ++i) {
    bsn[i] = c++;
  }
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  // since we want to work with single SigRl
  size_t srl_size = sig_rl_data_n2_one.size() - 4 * sizeof(srl->bk[0]);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256HugeBsnMsg0WithSigRl.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                 bsn.size(), sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsMsgUsingBsnContainingAllPossibleBytesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  auto& bsn = kData_0_255;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256kData_0_255Msg0NoSigRl.data();
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), msg.size(), bsn.data(),
                                 bsn.size(), sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

/////////////////////////////////////////////////////////////////////////
// Variable sigRL
TEST_F(EpidMemberSplitSignTest, SignsMessageGivenNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  size_t sig_len = EpidGetSigSize(nullptr);
  std::vector<uint8_t> newsig(sig_len);
  EpidSplitSignature* sig = (EpidSplitSignature*)newsig.data();
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageGivenSigRlWithNoEntries) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;

  uint8_t sig_rl_data_n2_zero[] = {
      // gid
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x7f, 0xff, 0xff, 0xee,
      // version
      0x00, 0x00, 0x00, 0x00,
      // n2
      0x0, 0x00, 0x00, 0x00,
      // not bk's
  };
  SigRl const* srl = reinterpret_cast<SigRl const*>(sig_rl_data_n2_zero);
  size_t srl_size = sizeof(sig_rl_data_n2_zero);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}
TEST_F(EpidMemberSplitSignTest, SignsMessageGivenSigRlWithEntries) {
  auto sig_rl_data_n2_one = kSigRl5EntrySha256Data;
  SigRl* srl = reinterpret_cast<SigRl*>(sig_rl_data_n2_one.data());
  srl->n2.data[sizeof(srl->n2) - 1] = 0x01;
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  otp_data.insert(otp_data.end(), NrProveEntropy.begin(), NrProveEntropy.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  // since we want to work with single SigRl
  size_t srl_size = sig_rl_data_n2_one.size() - 4 * sizeof(srl->bk[0]);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig_raw = kSplitSigGrpXMember3Sha256RandombaseTest1;
  auto expected_sig = (EpidSplitSignature*)expected_sig_raw.data();
  expected_sig->n2.data[sizeof(expected_sig->n2) - 1] = 0x01;
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignMessageReportsIfMemberRevoked) {
  // note: a complete sig + nr proof should still be returned!!
  auto srl_raw = kSigRl5EntrySha256Data;
  auto srl = reinterpret_cast<SigRl*>(srl_raw.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  SplitNrProof ExpectedSplitNrProofRevokedGrpXMember3{
      // T
      // G1ElemStr
      {// x
       // FqElemStr
       {{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}},
       // y
       // FqElemStr
       {{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}}},
      // c
      // FpElemStr
      {{{0xbf, 0xe7, 0x05, 0xbd, 0x7f, 0xb7, 0xcf, 0x81, 0xb8, 0x47, 0x6f,
         0xce, 0xf6, 0xe1, 0x17, 0xd0, 0x23, 0x72, 0x72, 0x65, 0x23, 0xef,
         0x00, 0x0a, 0x71, 0x7f, 0x0c, 0x41, 0x1d, 0x16, 0xa1, 0x1a}}},
      // smu
      // FpElemStr
      {{{
          0x76, 0x71, 0xca, 0xec, 0x41, 0x55, 0x16, 0x7f, 0xd7, 0x34, 0xb3,
          0x82, 0x6e, 0x94, 0xaa, 0x93, 0x56, 0xed, 0x46, 0xb3, 0x2a, 0x0f,
          0xfd, 0xe2, 0xa9, 0x65, 0x4d, 0x3a, 0xfd, 0xd1, 0xe8, 0x94,
      }}},
      // snu
      // FpElemStr
      {{{
          0x9c, 0xc7, 0x8c, 0x95, 0x5c, 0x05, 0x57, 0xed, 0x1e, 0x54, 0xf6,
          0xac, 0x32, 0x99, 0xaf, 0xf5, 0x03, 0x4c, 0x26, 0xcb, 0xbb, 0xd3,
          0xf3, 0x40, 0x37, 0x69, 0x64, 0x91, 0x61, 0x4f, 0x50, 0x06,
      }}},
      // k
      // FpElemStr
      {{{0xac, 0x72, 0x37, 0x44, 0xe6, 0x90, 0x30, 0x5f, 0x17, 0xf5, 0xf5,
         0xf1, 0x9e, 0x81, 0xa9, 0x81, 0x2c, 0x7a, 0xa7, 0x37, 0x52, 0xf6,
         0x0e, 0xd3, 0xaa, 0x6c, 0x9f, 0x46, 0xf7, 0x3b, 0x2d, 0x52}}}};
  auto expected_sig_raw = kSplitSigGrpXMember3Sha256RandombaseTest1;
  auto expected_sig = (EpidSplitSignature*)expected_sig_raw.data();
  srl->bk[3].b = expected_sig->sigma0.B;
  srl->bk[3].k = expected_sig->sigma0.K;
  expected_sig->sigma[3] = ExpectedSplitNrProofRevokedGrpXMember3;
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

/////////////////////////////////////////////////////////////////////////
// Variable hash alg
TEST_F(EpidMemberSplitSignTest, SignsMessageUsingSha512HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha512PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha512);
  set_gid_hashalg(&mpriv_key.gid, kSha512);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, kMember3Sha512Precomp,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha512RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingSha384HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha384PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha384);
  set_gid_hashalg(&mpriv_key.gid, kSha384);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, kMember3Sha384Precomp,
                      &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha384RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingSha256HashAlg) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsMessageUsingSha512256HashAlg) {
  GroupPubKey pub_key = kGrpXKey;
  PrivKey mpriv_key = kGrpXMember3Sha512256PrivKey;
  set_gid_hashalg(&pub_key.gid, kSha512_256);
  set_gid_hashalg(&mpriv_key.gid, kSha512_256);
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(pub_key, mpriv_key, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha512256RndbaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}
/////////////////////////////////////////////////////////////////////////
// Variable precomputed signatures
TEST_F(EpidMemberSplitSignTest, SignsMessageWithPrecomputedSignaturesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 1));
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsMessageWithPrecomputedSignaturesWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  THROW_ON_EPIDERR(EpidAddPreSigs(member, 1));
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256RandombaseTest1.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsMessageWithoutPrecomputedSignaturesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseTest1NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest,
       SignsMessageWithoutPrecomputedSignaturesWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kTest1Msg;
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig = (EpidSplitSignature const*)
                          kSplitSigGrpXMember3Sha256RandombaseTest1.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

/////////////////////////////////////////////////////////////////////////
// Variable messages
TEST_F(EpidMemberSplitSignTest, SignsEmptyMessageNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  auto& bsn = kBasename1;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256Basename1EmptyNoSigRl.data();
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), 0, bsn.data(), bsn.size(),
                                 sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsEmptyMessageWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  auto& bsn = kBasename1;
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  auto expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256Basename1EmptyWithSigRl.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  THROW_ON_EPIDERR(EpidRegisterBasename(member, bsn.data(), bsn.size()));
  EXPECT_EQ(kEpidNoErr, EpidSign(member, msg.data(), 0, bsn.data(), bsn.size(),
                                 sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}

TEST_F(EpidMemberSplitSignTest, SignsShortMessageNoSigRl) {
  // check: 1, 13, 128, 256, 512, 1021, 1024 bytes
  // 13 and 1021 are primes
  Prng my_prng;
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &Prng::Generate, &my_prng);
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSignature* sig = reinterpret_cast<EpidSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  VerifierCtxObj ctx(kGrpXKey);
  size_t lengths[] = {1,   13,   128, 256,
                      512, 1021, 1024};  // have desired lengths to loop over
  std::vector<uint8_t> msg(
      lengths[COUNT_OF(lengths) - 1]);  // allocate message for max size
  for (size_t n = 0; n < msg.size(); n++) {
    msg[n] = (uint8_t)n;
  }
  for (auto length : lengths) {
    EXPECT_EQ(kEpidNoErr,
              EpidSign(member, msg.data(), length, nullptr, 0, sig, sig_len))
        << "EpidSign for message_len: " << length << " failed";
    EXPECT_EQ(kEpidSigValid, EpidVerify(ctx, sig, sig_len, msg.data(), length))
        << "EpidVerify for message_len: " << length << " failed";
  }
}

TEST_F(EpidMemberSplitSignTest, SignsLongMessageNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  std::vector<uint8_t> msg(1000000);  // allocate message for max size
  for (size_t n = 0; n < msg.size(); n++) {
    msg.at(n) = (uint8_t)n;
  }
  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseMlnNoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len))
      << "EpidSign for message_len: " << 1000000 << " failed";
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len))
      << "EpidVerify for message_len: " << 1000000 << " failed";
}

TEST_F(EpidMemberSplitSignTest, SignsLongMessageWithSigRl) {
  SigRl const* srl =
      reinterpret_cast<SigRl const*>(kSigRl5EntrySha256Data.data());
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  for (uint32_t i = 0; i < ntohl(srl->n2); ++i) {
    otp_data.insert(otp_data.end(), NrProveEntropy.begin(),
                    NrProveEntropy.end());
  }
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  size_t srl_size = kSigRl5EntrySha256Data.size() * sizeof(uint8_t);
  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  std::vector<uint8_t> msg(1000000);  // allocate message for max size
  for (size_t n = 0; n < msg.size(); n++) {
    msg.at(n) = (uint8_t)n;
  }
  auto expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RandombaseMlnWithSigRl.data();
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len))
      << "EpidSign for message_len: " << 1000000 << " failed";
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len))
      << "EpidVerify for message_len: " << 1000000 << " failed";
}

TEST_F(EpidMemberSplitSignTest, SignsMsgContainingAllPossibleBytesNoSigRl) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(kGrpXKey, kGrpXMember3Sha256PrivKey,
                      kMember3Sha256Precomp, &OneTimePad::Generate, &my_prng);
  auto& msg = kData_0_255;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);

  auto const& expected_sig =
      (EpidSplitSignature const*)
          kSplitSigGrpXMember3Sha256RndBsnData_0_255NoSigRl.data();
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  EXPECT_EQ(0, memcmp(expected_sig, sig, sig_len));
}
#endif  // TPM_TSS

/////////////////////////////////////////////////////////////////////////
// Revoked member by sigRL for TPM case
TEST_F(EpidMemberSplitSignTest,
       PROTECTED_SignMsgByCredentialReportsIfMemberRevoked_EPS0) {
  auto& pub_key = kEps0GroupPublicKey_sha256;
  auto credential = *(MembershipCredential const*)&kEps0MemberPrivateKey_sha256;
  const std::vector<uint8_t> msg = {'t', 'e', 's', 't', '2'};
  OneTimePad my_prng(0);
  MemberCtxObj member(pub_key, credential, &OneTimePad::Generate, &my_prng);
  const std::vector<uint8_t> kEps0SigRlMember0Sha256Rndbase0Msg0FirstEntry = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
      // B
      0x30, 0x89, 0x2e, 0xbf, 0xf4, 0xa1, 0xa2, 0x54, 0x43, 0xc8, 0x82, 0xe3,
      0x33, 0xea, 0xc1, 0x2d, 0x6f, 0xfc, 0x41, 0x0d, 0xb5, 0x6e, 0x6f, 0x81,
      0xfe, 0x22, 0x10, 0x9c, 0xc8, 0x3d, 0xcf, 0x7a, 0xc2, 0xaf, 0x31, 0x3f,
      0xc9, 0x45, 0x0f, 0x5e, 0x15, 0xb0, 0x66, 0xc1, 0x9b, 0x0f, 0xa9, 0x5b,
      0x41, 0x9c, 0x2f, 0x84, 0xe2, 0xc9, 0xf7, 0xf7, 0xfb, 0xe7, 0xfe, 0x51,
      0x96, 0x5b, 0xe8, 0xd8,
      // K
      0x1b, 0xb8, 0x68, 0x4a, 0xb0, 0x87, 0x11, 0x20, 0x81, 0xfc, 0x29, 0xb4,
      0x00, 0xee, 0x94, 0xcd, 0xd4, 0x68, 0x7e, 0x26, 0xd5, 0x90, 0x55, 0x63,
      0x7b, 0x21, 0xdc, 0xcd, 0x2d, 0xaf, 0xe9, 0x4a, 0x40, 0xea, 0x17, 0x12,
      0x2e, 0xff, 0x1f, 0x32, 0xfe, 0x4f, 0xd6, 0x23, 0xe0, 0x44, 0xa5, 0xbf,
      0xa9, 0x00, 0xb4, 0xbf, 0x8f, 0x28, 0xca, 0x53, 0x33, 0x9b, 0x9e, 0x29,
      0x70, 0x39, 0x45, 0x3b,
  };
  auto srl = reinterpret_cast<SigRl const*>(
      kEps0SigRlMember0Sha256Rndbase0Msg0FirstEntry.data());
  size_t srl_size = kEps0SigRlMember0Sha256Rndbase0Msg0FirstEntry.size();

  std::vector<uint8_t> sig_data(EpidGetSigSize(srl));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  THROW_ON_EPIDERR(EpidMemberSetSigRl(member, srl, srl_size));
  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  VerifierCtxObj ctx(pub_key);
  THROW_ON_EPIDERR(EpidVerifierSetSigRl(ctx, srl, srl_size));
  EXPECT_EQ(kEpidSigRevokedInSigRl,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}

/////////////////////////////////////////////////////////////////////////
// Variable hash alg for TPM data
TEST_F(EpidMemberSplitSignTest,
       PROTECTED_SignsMessageByCredentialUsingSha256HashAlg_EPS0) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(
      kEps0GroupPublicKey_sha256,
      *(MembershipCredential const*)&kEps0MemberPrivateKey_sha256,
      &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  VerifierCtxObj ctx(kEps0GroupPublicKey_sha256);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}

TEST_F(EpidMemberSplitSignTest,
       PROTECTED_SignsMessageByCredentialUsingSha384HashAlg_EPS0) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(
      kEps0GroupPublicKey_sha384,
      *(MembershipCredential const*)&kEps0MemberPrivateKey_sha384,
      &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  VerifierCtxObj ctx(kEps0GroupPublicKey_sha384);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}

TEST_F(EpidMemberSplitSignTest,
       PROTECTED_SignsMessageByCredentialUsingSha512HashAlg_EPS0) {
  auto otp_data = kOtpDataWithoutRfAndNonce;
  otp_data.insert(otp_data.end(), rf.begin(), rf.end());
  otp_data.insert(otp_data.end(), kNoncek.begin(), kNoncek.end());
  OneTimePad my_prng(otp_data);
  MemberCtxObj member(
      kEps0GroupPublicKey_sha512,
      *(MembershipCredential const*)&kEps0MemberPrivateKey_sha512,
      &OneTimePad::Generate, &my_prng);
  auto& msg = kMsg0;
  std::vector<uint8_t> sig_data(EpidGetSigSize(nullptr));
  EpidSplitSignature* sig =
      reinterpret_cast<EpidSplitSignature*>(sig_data.data());
  size_t sig_len = sig_data.size() * sizeof(uint8_t);
  EXPECT_EQ(kEpidNoErr,
            EpidSign(member, msg.data(), msg.size(), nullptr, 0, sig, sig_len));
  // verify signature
  VerifierCtxObj ctx(kEps0GroupPublicKey_sha512);
  EXPECT_EQ(kEpidSigValid,
            EpidVerify(ctx, sig, sig_len, msg.data(), msg.size()));
}

}  // namespace
