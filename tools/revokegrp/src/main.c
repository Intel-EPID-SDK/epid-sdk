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

/*!
 * \file
 *
 * \brief Create group revocation list request
 *
 */

#include <argtable3.h>
#include <stdlib.h>
#include <string.h>
#include "epid/common/file_parser.h"
#include "util/buffutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"

const OctStr16 kEpidFileVersion = {2, 0};

// Defaults
#define PROGRAM_NAME "revokegrp"
#define PUBKEYFILE_DEFAULT "pubkey.bin"
#define REQFILE_DEFAULT "grprlreq.dat"
#define REASON_DEFAULT 0
#define GROUP_PUB_KEY_SIZE \
  (sizeof(EpidFileHeader) + sizeof(GroupPubKey) + sizeof(EcdsaSignature))
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 7

// Defined function to get defined number as string
#define STRINGIZE_(x) #x
#define STRINGIZE(x) STRINGIZE_(x)

#pragma pack(1)
/// Group revocation request entry
typedef struct GrpInfo {
  GroupId gid;     ///< Intel(R) EPID Group ID
  uint8_t reason;  ///< Revocation reason
} GrpInfo;
/// Group Revocation request
typedef struct GrpRlRequest {
  EpidFileHeader header;  ///< Intel(R) EPID File Header
  uint32_t count;         ///< Revoked count (big endian)
  GrpInfo groups[1];      ///< Revoked group count (flexible array)
} GrpRlRequest;
#pragma pack()

/// convert host to network byte order
static uint32_t htonl(uint32_t hostlong) {
  return (((hostlong & 0xFF) << 24) | ((hostlong & 0xFF00) << 8) |
          ((hostlong & 0xFF0000) >> 8) | ((hostlong & 0xFF000000) >> 24));
}
/// convert network to host byte order
static uint32_t ntohl(uint32_t netlong) {
  return (((netlong & 0xFF) << 24) | ((netlong & 0xFF00) << 8) |
          ((netlong & 0xFF0000) >> 8) | ((netlong & 0xFF000000) >> 24));
}

/// Makes a request and appends it to file.
/*!
\param[in] cacert_file
Issuing CA certificate used to sign group public key file.
\param[in] pubkey_file
File containing group public key.
\param[in] req_file
File to write a request.
\param[in] reason
Revokation reason.
\param[in] verbose
If true function would print debug information to stdout.
*/
int MakeRequest(char const* cacert_file, char const* pubkey_file,
                char const* req_file, uint8_t reason, bool verbose);

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_FAILURE;

  // User Settings

  // Verbose flag parameter
  static bool verbose_flag = false;

  struct arg_file* pubkey_file = arg_file0(
      NULL, "gpubkey", "FILE",
      "load group public key from FILE (default: " PUBKEYFILE_DEFAULT ")");
  struct arg_file* cacert_file = arg_file1(
      NULL, "capubkey", "FILE", "load IoT Issuing CA public key from FILE");
  struct arg_int* reason =
      arg_int0(NULL, "reason", "NUM",
               "revocation reason (default: " STRINGIZE(REASON_DEFAULT) ")");
  struct arg_file* req_file = arg_file0(
      NULL, "req", "FILE",
      "append signature revocation request to FILE (default: " REQFILE_DEFAULT
      ")");
  struct arg_lit* help = arg_lit0(NULL, "help", "display this help and exit");
  struct arg_lit* verbose =
      arg_lit0("v", "verbose", "print status messages to stdout");
  struct arg_end* end = arg_end(ARGPARSE_ERROR_MAX);
  void* argtable[ARGTABLE_SIZE];
  int nerrors;

  /* initialize the argtable array with ptrs to the arg_xxx structures
   * constructed above */
  argtable[0] = pubkey_file;
  argtable[1] = cacert_file;
  argtable[2] = reason;
  argtable[3] = req_file;
  argtable[4] = help;
  argtable[5] = verbose;
  argtable[6] = end;

  // set program name for logging
  set_prog_name(PROGRAM_NAME);
  do {
    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable) != 0) {
      /* NULL entries were detected, some allocations must have failed */
      printf("%s: insufficient memory\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }

    /* set any command line default values prior to parsing */
    pubkey_file->filename[0] = PUBKEYFILE_DEFAULT;
    req_file->filename[0] = REQFILE_DEFAULT;
    reason->ival[0] = REASON_DEFAULT;

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt(
          "Usage: %s [OPTION]...\n"
          "Revoke Intel(R) EPID group\n"
          "\n"
          "Options:\n",
          PROGRAM_NAME);
      arg_print_glossary(stdout, argtable, "  %-25s %s\n");
      ret_value = EXIT_SUCCESS;
      break;
    }
    if (verbose->count > 0) {
      verbose_flag = ToggleVerbosity();
    }
    /* If the parser returned any errors then display them and exit */
    if (nerrors > 0) {
      /* Display the error details contained in the arg_end struct.*/
      arg_print_errors(stderr, end, PROGRAM_NAME);
      fprintf(stderr, "Try '%s --help' for more information.\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }
    if (reason->ival[0] < 0 || reason->ival[0] > UCHAR_MAX) {
      log_error(
          "unexpected reason value. Value of the reason must be in a range "
          "from 0 to %d",
          UCHAR_MAX);
      ret_value = EXIT_FAILURE;
      break;
    }
    if (verbose_flag) {
      log_msg("\nOption values:");
      log_msg(" pubkey_file   : %s", pubkey_file->filename[0]);
      log_msg(" cacert_file   : %s", cacert_file->filename[0]);
      log_msg(" reason        : %d", reason->ival[0]);
      log_msg(" req_file      : %s", req_file->filename[0]);
      log_msg("");
    }

    ret_value = MakeRequest(cacert_file->filename[0], pubkey_file->filename[0],
                            req_file->filename[0], (uint8_t)reason->ival[0],
                            verbose_flag);
  } while (0);

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}

int MakeRequest(char const* cacert_file, char const* pubkey_file,
                char const* req_file, uint8_t reason, bool verbose) {
  // Group index and count
  uint32_t grp_index = 0;
  uint32_t grp_count = 0;

  // Buffers and computed values
  // Group public key file
  unsigned char* pubkey_file_data = NULL;
  size_t pubkey_file_size = 0;

  // Group public key buffer
  GroupPubKey pubkey = {0};

  // CA certificate
  EpidCaCertificate cacert = {0};

  // Request buffer
  uint8_t* req_buf = NULL;
  size_t req_size = 0;
  size_t req_file_size = 0;
  GrpRlRequest* request = NULL;
  size_t req_extra_space = sizeof(GroupId) + sizeof(uint8_t);

  int ret_value = EXIT_FAILURE;
  do {
    if (!cacert_file || !pubkey_file || !req_file) {
      log_error("internal error: badarg to MakeRequest()");
      ret_value = EXIT_FAILURE;
      break;
    }

    // convert command line args to usable formats
    // CA certificate
    if (0 != ReadLoud(cacert_file, &cacert, sizeof(cacert))) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // Group public key file
    pubkey_file_data = NewBufferFromFile(pubkey_file, &pubkey_file_size);
    if (!pubkey_file_data) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // Security note:
    // Application must confirm group public key is
    // authorized by the issuer, e.g., signed by the issuer.
    if (GROUP_PUB_KEY_SIZE != pubkey_file_size) {
      log_error("unexpected file size for '%s'. Expected: %d; got: %d",
                pubkey_file, (int)GROUP_PUB_KEY_SIZE, pubkey_file_size);
      ret_value = EXIT_FAILURE;
      break;
    }
    if (kEpidNoErr != EpidParseGroupPubKeyFile(pubkey_file_data,
                                               pubkey_file_size, &cacert,
                                               &pubkey)) {
      log_error("group public key is not authorized");
      ret_value = EXIT_FAILURE;
      break;
    }

    // Report Settings
    if (verbose) {
      log_msg("==============================================");
      log_msg("Input settings:");
      log_msg("");
      log_msg(" [in]  Group ID: ");
      PrintBuffer(&pubkey.gid, sizeof(pubkey.gid));
      log_msg("");
      log_msg(" [in]  Reason: %d", reason);
      log_msg("==============================================");
    }

    // Calculate request size
    req_size = sizeof(EpidFileHeader) + sizeof(uint32_t);

    if (FileExists(req_file)) {
      req_file_size = GetFileSize_S(req_file, SIZE_MAX - req_extra_space);

      if (req_file_size < req_size) {
        log_error("output file smaller then size of empty request");
        ret_value = EXIT_FAILURE;
        break;
      }

      req_size = req_file_size;
    } else {
      log_msg("request file does not exsist, create new");
    }

    req_size += req_extra_space;

    // Allocate request buffer
    req_buf = AllocBuffer(req_size);
    if (!req_buf) {
      ret_value = EXIT_FAILURE;
      break;
    }

    request = (GrpRlRequest*)req_buf;

    // Load existing request file
    if (req_file_size > 0) {
      if (0 != ReadLoud(req_file, req_buf, req_file_size)) {
        ret_value = EXIT_FAILURE;
        break;
      }

      // Check Intel(R) EPID and file versions
      if (0 != memcmp(&request->header.epid_version, &kEpidFileVersion,
                      sizeof(kEpidFileVersion))) {
        ret_value = EXIT_FAILURE;
        break;
      }

      if (0 != memcmp(&request->header.file_type,
                      &kEpidFileTypeCode[kGroupRlRequestFile],
                      sizeof(kEpidFileTypeCode[kGroupRlRequestFile]))) {
        ret_value = EXIT_FAILURE;
        break;
      }

      grp_count = ntohl(request->count);
      // check if revoked count matches the number of group revocation request
      // entries contained in the file
      if (grp_count * sizeof(GrpInfo) !=
          req_file_size - sizeof(EpidFileHeader) - sizeof(uint32_t)) {
        log_error("Incorrect revoked request count in existing file");
        ret_value = EXIT_FAILURE;
        break;
      }
      // Update the reason if the group is in the request
      for (grp_index = 0; grp_index < grp_count; grp_index++) {
        if (0 == memcmp(&request->groups[grp_index].gid, &pubkey.gid,
                        sizeof(pubkey.gid))) {
          request->groups[grp_index].reason = reason;
          req_size = req_file_size;
          break;
        }
      }
    }

    // Append group to the request
    if (grp_index == grp_count) {
      request->header.epid_version = kEpidFileVersion;
      request->header.file_type = kEpidFileTypeCode[kGroupRlRequestFile];
      request->groups[grp_count].gid = pubkey.gid;
      request->groups[grp_count].reason = reason;
      request->count = htonl(++grp_count);
    }

    // Report Settings
    if (verbose) {
      log_msg("==============================================");
      log_msg("Request generated:");
      log_msg("");
      log_msg(" [in]  Request Len: %d", (int)req_size);
      log_msg(" [in]  Request: ");
      PrintBuffer(req_buf, req_size);
      log_msg("==============================================");
    }

    // Store request
    if (0 != WriteLoud(req_buf, req_size, req_file)) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // Success
    ret_value = EXIT_SUCCESS;
  } while (0);

  // Free allocated buffers
  if (pubkey_file_data) free(pubkey_file_data);
  if (req_buf) free(req_buf);

  return ret_value;
}
