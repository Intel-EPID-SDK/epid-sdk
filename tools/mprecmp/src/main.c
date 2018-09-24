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
 * \brief Member data pre-compute tool main file.
 */

#include <argtable3.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif  // defined(_WIN32)

#include "src/mprecmp.h"
#include "util/buffutil.h"
#include "util/envutil.h"

// Defaults
#define PROGRAM_NAME "mprecmp"
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 6
#define REMARK_MSG                                                             \
  "\n"                                                                         \
  "If the --%s option is provided the GROUP argument will be interpreted as\n" \
  "a group certificate, otherwise it will be interpreted as a group public\n"  \
  "key.\n"

#define UNUSED(a) (void)a;

bool IsCaCertAuthorizedByRootCa(void const* data, size_t size) {
  // Implementation of this function is out of scope of the sample.
  // In an actual implementation Issuing CA certificate must be validated
  // with CA Root certificate before using it in parse functions.
  UNUSED(data)
  UNUSED(size)
  return true;
}

///////////////////////////////////////////////////////////////////////////////
/// Loads a CA Certificate
/*!

  \param[in] filename
  File containing IoT Intel(R) EPID Issuing CA certificate

  \param[out] cacert
  CA certificate to initialize

  \returns status
  Integer representing operation result

  \retval 0
  Successfully initialized CA certificate
 */
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
/*!

  \param[in] filename
  File containing group public key

  \param[out] pub_key
  Group public key to initialize

  \returns status
  Integer representing operation result

  \retval 0
  Successfully initialized group public key
 */
int LoadGroupKey(char const* filename, GroupPubKey* pub_key) {
  if (0 != ReadBufferFromFileLoud(filename, pub_key, sizeof(*pub_key),
                                  "group public key")) {
    return -1;
  }
  return 0;
}

/// Loads a group certificate
/*!

  \param[in] filename
  File containing group certificate

  \param[in] cacert
  IoT Intel(R) EPID Issuing CA certificate that group certificate
  is verified against

  \param[out]
  Group public key to initialize

  \returns status
  Integer representing operation result

  \retval 0
  Successfully initialized group public key
 */
int LoadGroupCert(char const* filename, EpidCaCertificate const* cacert,
                  GroupPubKey* pub_key) {
  int result = -1;
  unsigned char* signed_pubkey = NULL;
  do {
    EpidStatus sts = kEpidNoErr;
    size_t signed_pubkey_size = 0;

    // detect fopen failure here so we can do custom error msg
    if (!FileExists(filename)) {
      log_error("cannot open '%s': %s", filename, strerror(errno));
      result = -1;
      break;
    }

    signed_pubkey = NewBufferFromFileLoud(filename, &signed_pubkey_size,
                                          "group certificate");
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
///////////////////////////////////////////////////////////////////////////////

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_SUCCESS;

  // intermediate return value for Intel(R) EPID functions
  EpidStatus result = kEpidErr;

  // Group public key
  GroupPubKey pub_key = {0};

  // Member private key buffer
  unsigned char* mprivkey = NULL;
  size_t mprivkey_size = 0;

  // Member pre-computed result
  MemberPrecomp member_precmp = {0};

  // Command-line arguments
  // Group public key or certificate file
  struct arg_file* group_pubkey_file =
      arg_file1(NULL, NULL, "GROUP", "read group public key from file");
  // Member private key or Membership Certificate file
  struct arg_file* member_privkey_file =
      arg_file1(NULL, NULL, "MEMBER",
                "read member private key or membership credential from file");
  struct arg_file* cacert_file = arg_file0(
      "c", "cacert", "FILE", "use the issuing CA certificate from FILE to");
  // Split command-line message into 2 lines
  struct arg_rem* cacert_rem = arg_rem(NULL, "verify the inputs");
  struct arg_lit* help = arg_lit0("h", "help", "display this help and exit");

  struct arg_end* end = arg_end(ARGPARSE_ERROR_MAX);
  void* argtable[ARGTABLE_SIZE];
  int nerrors;

  /* initialize the argtable array with ptrs to the arg_xxx structures
   * constructed above */
  argtable[0] = group_pubkey_file;
  argtable[1] = member_privkey_file;
  argtable[2] = cacert_file;
  argtable[3] = cacert_rem;
  argtable[4] = help;
  argtable[5] = end;

  // set program name for logging
  set_prog_name(PROGRAM_NAME);
  do {
    /* verify the argtable[] entries were allocated successfully */
    if (arg_nullcheck(argtable) != 0 || !group_pubkey_file ||
        !member_privkey_file || !cacert_file || !cacert_rem || !help || !end) {
      /* NULL entries were detected, some allocations must have failed */
      printf("%s: insufficient memory\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt("Usage: %s\n", PROGRAM_NAME);
      log_fmt("[OPTION]... GROUP MEMBER\n");
      log_fmt(
          "Pre-compute Member data and write it to standard output.\n"
          "\n"
          "Options:\n");
      arg_print_glossary(stdout, argtable, "  %-25s %s\n");
      log_fmt(REMARK_MSG, cacert_file->hdr.longopts);
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

    // Convert command line args to usable formats
    // Group
    if (cacert_file->count > 0) {
      EpidCaCertificate cacert = {0};
      if (0 != LoadCaCert(cacert_file->filename[0], &cacert)) {
        ret_value = EXIT_FAILURE;
        break;
      }
      if (0 !=
          LoadGroupCert(group_pubkey_file->filename[0], &cacert, &pub_key)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    } else {
      if (0 != LoadGroupKey(group_pubkey_file->filename[0], &pub_key)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Member private key
    mprivkey = NewBufferFromFileLoud(member_privkey_file->filename[0],
                                     &mprivkey_size, "private key file");
    if (!mprivkey) {
      ret_value = EXIT_FAILURE;
      break;
    }
    if (mprivkey_size != sizeof(PrivKey) &&
        mprivkey_size != sizeof(CompressedPrivKey) &&
        mprivkey_size != sizeof(MembershipCredential)) {
      ret_value = EXIT_FAILURE;
      log_error("private key file has invalid format");
      break;
    }

    // Pre-compute
    result =
        PrecomputeMemberData(&pub_key, mprivkey, mprivkey_size, &member_precmp);

    // Report Result
    if (kEpidNoErr != result) {
      log_error("function MemberPrecompute returned %s",
                EpidStatusToString(result));
      ret_value = EXIT_FAILURE;
      break;
    }

#if defined(_WIN32)
    _setmode(_fileno(stdout), _O_BINARY);
#endif  // defined(_WIN32)
    fwrite(&member_precmp, sizeof(member_precmp), 1, stdout);

    // Success
    ret_value = EXIT_SUCCESS;
  } while (0);

  // Free allocated buffers
  if (mprivkey) free(mprivkey);

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}
