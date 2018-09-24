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
/// Create join request for group
/*! \file */

#include <argtable3.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif  // defined(_WIN32)
#include "src/entropy.h"
#include "src/prng.h"

#include "epid/common/file_parser.h"
#include "epid/member/api.h"
#include "util/buffutil.h"
#include "util/convutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"

#ifdef TPM_TSS
#include "epid/member/tpm_member.h"
#elif defined TINY
#include "epid/member/tiny_member.h"
#else
#include "epid/member/software_member.h"
#endif

// Defaults
#define PROGRAM_NAME "joinreq"

#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 8

#define REMARK_MSG                                                             \
  "\n"                                                                         \
  "If the --%s option is provided the GROUP argument will be interpreted as\n" \
  "a group certificate, otherwise it will be interpreted as a group public\n"  \
  "key.\n"

#if defined TINY
#define NOTE_MSG                                                               \
  "\n"                                                                         \
  "Note that if you intend to use %s in a production environment you should\n" \
  "use the --%s option to provide a cryptographically secure source of\n"      \
  "randomness. Creating a join request requires at least 48 bytes of random\n" \
  "data.\n"
#elif defined TPM_TSS
#define NOTE_MSG ""
#else
#define NOTE_MSG                                                               \
  "\n"                                                                         \
  "Note that if you intend to use %s in a production environment you should\n" \
  "use the --%s option to provide a cryptographically secure source of\n"      \
  "randomness. Creating a join request requires at least 192 bytes of\n"       \
  "random data.\n"
#endif

#define UNUSED(x) (void)x;

bool IsCaCertAuthorizedByRootCa(void const* data, size_t size) {
  // Implementation of this function is out of scope of the sample.
  // In an actual implementation Issuing CA certificate must be validated
  // with CA Root certificate before using it in parse functions.
  (void)data;
  (void)size;
  return true;
}

EpidStatus MakeJoinRequest(GroupPubKey const* pub_key, IssuerNonce const* ni,
                           FpElemStr const* privatef,
                           MemberJoinRequest* join_request,
                           BitSupplier rnd_func, void* rnd_ctx) {
  EpidStatus sts;
  MemberParams params = {0};
  MemberCtx* member = NULL;

  if (!pub_key || !ni || !join_request) {
    return kEpidBadArgErr;
  }

  do {
    size_t member_size = 0;

    params.f = privatef;
#ifdef TPM_TSS
    UNUSED(rnd_func)
    UNUSED(rnd_ctx)
#else
    params.rnd_func = rnd_func;
    params.rnd_param = rnd_ctx;
#endif
#ifdef TINY
    params.max_sigrl_entries = 5;
    params.max_allowed_basenames = 5;
    params.max_precomp_sig = 1;
#endif

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

    sts = EpidCreateJoinRequest(member, pub_key, ni, join_request);
    if (kEpidNoErr != sts) {
      break;
    }
  } while (0);
  EpidMemberDeinit(member);
  if (member) free(member);

  return sts;
}

///////////////////////////////////////////////////////////////////////////////
/// Loads a Ca Certificate
int LoadCaCert(char const* filename, EpidCaCertificate* cacert) {
  // CA certificate
  if (0 != ReadBufferFromFileLoud(filename, cacert, sizeof(*cacert),
                                  "certificate")) {
    return -1;
  }
  // Security note:
  // Application must confirm that IoT Intel(R) EPID Issuing CA certificate
  // is authorized by IoT Intel(R) EPID Root CA, e.g.,
  // signed by IoT Intel(R) EPID Root CA.
  if (!IsCaCertAuthorizedByRootCa(cacert, sizeof(*cacert))) {
    log_error("CA certificate is not authorized");
    return -1;
  }
  return 0;
}

/// Loads a group public key
int LoadGroupKey(char const* filename, GroupPubKey* pub_key) {
  if (0 != ReadLoud(filename, pub_key, sizeof(*pub_key))) {
    return -1;
  }
  return 0;
}

/// Loads group certificate
/*!
 *  note this allocates a buffer for signed_pubkey that must be freed
 */
int LoadGroupCert(char const* filename, EpidCaCertificate const* cacert,
                  GroupPubKey* pub_key) {
  int result = -1;
  unsigned char* signed_pubkey = NULL;
  do {
    EpidStatus sts;
    size_t signed_pubkey_size = 0;

    // detect fopen failure here so we can do custom error msg
    if (!FileExists(filename)) {
      log_error("cannot open '%s': %s", filename, strerror(errno));
      result = -1;
      break;
    }

    signed_pubkey = NewBufferFromFile(filename, &signed_pubkey_size);
    if (!signed_pubkey) {
      result = -1;
      break;
    }
    // authenticate and extract group public key
    sts = EpidParseGroupPubKeyFile(signed_pubkey, signed_pubkey_size, cacert,
                                   pub_key);
    if (kEpidNoErr != sts) {
      if (kEpidSigInvalid == sts) {
        log_error("group certificate not authorized by certificate authority");
      } else {
        log_error("group certificate has invalid format");
      }
      result = -1;
      break;
    }
    result = 0;
  } while (0);

  if (signed_pubkey) free(signed_pubkey);
  return result;
}

/// Loads issuer nonce
int LoadIssuerNonce(char const* filename, IssuerNonce* nonce) {
  if (0 != ReadBufferFromFileLoud(filename, nonce, sizeof(*nonce), "nonce")) {
    return -1;
  }
  return 0;
}

/// Loads private f
int LoadPrivatef(char const* filename, FpElemStr* privatef) {
  if (0 != ReadBufferFromFileLoud(filename, privatef, sizeof(*privatef),
                                  "private f file")) {
    return -1;
  }
  return 0;
}

/// Configures the bitsupplier
int ConfigureBitsupplier(char const* filename, void** rnd_ctx) {
  if (!rnd_ctx) return -1;

  *rnd_ctx = NewBitSupplier(filename);
  if (!*rnd_ctx) {
    if (!errno) {
      log_error("failed to initialize entropy source");
    }
    return -1;
  }
  return 0;
}
///////////////////////////////////////////////////////////////////////////////

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_FAILURE;

  FpElemStr privatef = {0};
  FpElemStr* privatef_ptr = NULL;

  // entropy
  void* rnd_ctx = NULL;
  BitSupplier rnd_func = NULL;

  struct arg_file* group_file =
      arg_file1(NULL, NULL, "GROUP", "read group public key from file");
  struct arg_file* ni_file =
      arg_file1(NULL, NULL, "NONCE", "read issuer nonce from file");
  struct arg_file* privatef_file =
      arg_file0("f", "privatef", "FILE", "use private key f value from FILE");
  struct arg_file* random_file =
      arg_file0("R", "randfile", "FILE", "use FILE for random number input");

  struct arg_file* cacert_file = arg_file0(
      "c", "cacert", "FILE", "use the issuing CA certificate from FILE to");
  struct arg_rem* cacert_rem = arg_rem(NULL, "  verify the inputs");
  struct arg_lit* help = arg_lit0("h", "help", "display this help and exit");

  struct arg_end* end = arg_end(ARGPARSE_ERROR_MAX);
  void* argtable[ARGTABLE_SIZE];

  int nerrors;
  (void)argv;

  /* initialize the argtable array with ptrs to the arg_xxx structures
   * constructed above */
  argtable[0] = group_file;
  argtable[1] = ni_file;
  argtable[2] = privatef_file;
  argtable[3] = random_file;
  argtable[4] = cacert_file;
  argtable[5] = cacert_rem;
  argtable[6] = help;
  argtable[7] = end;

  // set program name for logging
  set_prog_name(PROGRAM_NAME);

  do {
    EpidStatus sts;
    GroupPubKey pub_key = {0};
    IssuerNonce nonce = {0};
    MemberJoinRequest join_request = {0};
    // size_t member_size = 0;

    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable) != 0 || !group_file || !ni_file ||
        !privatef_file || !random_file || !cacert_file || !cacert_rem ||
        !help || !end) {
      /* NULL entries were detected, some allocations must have failed */
      printf("%s: insufficient memory\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);
    if (help->count > 0) {
      log_fmt("Usage: %s\n", PROGRAM_NAME);
      log_fmt("[OPTION]... GROUP NONCE\n");

      log_fmt("Create a join request and write it to standard output.\n\n");
      log_fmt(
          "Mandatory arguments to long options "
          "are mandatory for short options too.\n");
      arg_print_glossary(stdout, argtable, "  %-25s %s\n");
      log_fmt(REMARK_MSG, cacert_file->hdr.longopts);
      log_fmt(NOTE_MSG, PROGRAM_NAME, random_file->hdr.longopts);
      ret_value = EXIT_SUCCESS;
      break;
    }
    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0) {
      /* Display the error details contained in the arg_end struct.*/
      arg_print_errors(stderr, end, PROGRAM_NAME);
      fprintf(stderr, "Try '%s --help' for more information.\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }

    // Group
    if (cacert_file->count > 0) {
      EpidCaCertificate cacert = {0};
      if (0 != LoadCaCert(cacert_file->filename[0], &cacert)) {
        ret_value = EXIT_FAILURE;
        break;
      }
      if (0 != LoadGroupCert(group_file->filename[0], &cacert, &pub_key)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    } else {
      if (0 != LoadGroupKey(group_file->filename[0], &pub_key)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }
    // Issuer nonce
    if (0 != LoadIssuerNonce(ni_file->filename[0], &nonce)) {
      ret_value = EXIT_FAILURE;
      break;
    }
    // Private f
    if (privatef_file->count > 0) {
      if (0 != LoadPrivatef(privatef_file->filename[0], &privatef)) {
        ret_value = EXIT_FAILURE;
        break;
      }
      privatef_ptr = &privatef;
    }

    // randfile
    if (random_file->count > 0) {
      ret_value = ConfigureBitsupplier(random_file->filename[0], &rnd_ctx);
    } else {
      // warn against production use of pseudo-random number generator
      log_error(NOTE_MSG, PROGRAM_NAME, random_file->hdr.longopts);
      ret_value = ConfigureBitsupplier(NULL, &rnd_ctx);
    }
    if (0 != ret_value) {
      ret_value = EXIT_FAILURE;
      break;
    }

    rnd_func = SupplyBits;

    sts = MakeJoinRequest(&pub_key, &nonce, privatef_ptr, &join_request,
                          rnd_func, rnd_ctx);

    // Report Result
    if (kEpidNoErr != sts) {
      if ((kEpidRandMaxIterErr == sts ||
           NotEnoughBytesOfEntropyProvided(rnd_ctx)) &&
          random_file->count > 0) {
        log_error("not enough bytes in entropy file");
      } else if (kEpidSchemaNotSupportedErr == sts) {
        log_error("gid schema not supported");
      } else {
        log_error("request creation error \"%s\"", EpidStatusToString(sts));
      }
      ret_value = EXIT_FAILURE;
      break;
    }

#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
#endif  // defined(_WIN32)
    fwrite(&join_request, sizeof(join_request), 1, stdout);

    ret_value = EXIT_SUCCESS;
  } while (0);

  if (rnd_ctx) DeleteBitSupplier(&rnd_ctx);

  memset(&privatef, 0, sizeof(privatef));
  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}
