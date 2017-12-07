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
 * \brief Create signature based revocation list request
 *
 */

#include <argtable3.h>
#include <stdlib.h>
#include <string.h>
#include "epid/common/file_parser.h"
#include "util/buffutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"

// Defaults
#define PROGRAM_NAME "revokesig"
#define PUBKEYFILE_DEFAULT "pubkey.bin"
#define REQFILE_DEFAULT "sigrlreq.dat"
#define SIG_DEFAULT "sig.dat"
#define GROUP_PUB_KEY_SIZE \
  (sizeof(EpidFileHeader) + sizeof(GroupPubKey) + sizeof(EcdsaSignature))
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 9

#pragma pack(1)
/// Partial signature request, includes components through sig.
typedef struct SigRlRequestTop {
  EpidFileHeader header;  ///< Intel(R) EPID File Header
  GroupId gid;            ///< Intel(R) EPID Group ID
  EpidSignature sig;      ///< Intel(R) EPID Signature
} SigRlRequestTop;

/// Partial signature request, includes components after.
typedef struct SigRlRequestMid {
  uint32_t be_msg_size;  ///< size of message in bytes (big endian)
  uint8_t msg[1];        ///< message used to create signature (flexible array)
} SigRlRequestMid;
#pragma pack()

/// convert host to network byte order
static uint32_t htonl(uint32_t hostlong) {
  return (((hostlong & 0xFF) << 24) | ((hostlong & 0xFF00) << 8) |
          ((hostlong & 0xFF0000) >> 8) | ((hostlong & 0xFF000000) >> 24));
}

/// Fill a single SigRlRequest structure
/*!
\param[in] pubkey
Group public key.
\param[in] sig
Signature to append to request.
\param[in] sig_size
Size of the signature.
\param[in] msg_str
Message used to generate signature to revoke.
\param[in] msg_size
Length of the message.
\param[in out] req_buf
Pointer to request buffer.
\param[in] req_size
Size of request buffer.
\param[in out] req_top
Pointer to top structure of request.
*/
void FillRequest(GroupPubKey const* pubkey, EpidSignature const* sig,
                 size_t sig_size, char const* msg_str, size_t msg_size,
                 uint8_t* req_buf, size_t req_size, SigRlRequestTop* req_top);

/// Makes a request and appends it to file.
/*!
\param[in] cacert_file
Issuing CA certificate used to sign group public key file.
\param[in] sig_file
File containing signature to add to request.
\param[in] pubkey_file
File containing group public key.
\param[in] req_file
File to write a request.
\param[in] msg_str
Message used to generate signature to revoke.
\param[in] msg_size
Length of the message.
\param[in] verbose
If true function would print debug information to stdout.
*/
int MakeRequest(char const* cacert_file, char const* sig_file,
                char const* pubkey_file, char const* req_file,
                char const* msg_str, size_t msg_size, bool verbose);

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_FAILURE;

  // Message string parameter
  static char* msg_str = NULL;
  size_t msg_size = 0;
  char* msg_buf = NULL;  // message loaded from msg_file

  // Verbose flag parameter
  static bool verbose_flag = false;

  struct arg_file* sig_file = arg_file0(
      NULL, "sig", "FILE",
      "load signature to revoke from FILE (default: " SIG_DEFAULT ")");
  struct arg_str* msg =
      arg_str0(NULL, "msg", "MESSAGE",
               "MESSAGE used to generate signature to revoke (default: empty)");
  struct arg_file* msg_file =
      arg_file0(NULL, "msgfile", "FILE",
                "FILE containing message used to generate signature to revoke");
  struct arg_file* pubkey_file = arg_file0(
      NULL, "gpubkey", "FILE",
      "load group public key from FILE (default: " PUBKEYFILE_DEFAULT ")");
  struct arg_file* cacert_file = arg_file1(
      NULL, "capubkey", "FILE", "load IoT Issuing CA public key from FILE");
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
  argtable[0] = sig_file;
  argtable[1] = msg;
  argtable[2] = msg_file;
  argtable[3] = pubkey_file;
  argtable[4] = cacert_file;
  argtable[5] = req_file;
  argtable[6] = help;
  argtable[7] = verbose;
  argtable[8] = end;

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
    sig_file->filename[0] = SIG_DEFAULT;
    pubkey_file->filename[0] = PUBKEYFILE_DEFAULT;
    req_file->filename[0] = REQFILE_DEFAULT;

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt(
          "Usage: %s [OPTION]...\n"
          "Revoke Intel(R) EPID signature\n"
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

    if (msg->count > 0 && msg_file->count > 0) {
      log_error("options --msg and --msgfile cannot be used together");
      ret_value = EXIT_FAILURE;
      break;
    } else if (msg->count > 0) {
      msg_str = (char*)msg->sval[0];
      msg_size = strlen(msg_str);
    } else if (msg_file->count > 0) {
      msg_buf = NewBufferFromFile(msg_file->filename[0], &msg_size);
      if (!msg_buf) {
        ret_value = EXIT_FAILURE;
        break;
      }
      msg_str = msg_buf;
    } else {
      msg_size = 0;
    }

    if (verbose_flag) {
      log_msg("\nOption values:");
      log_msg(" sig_file      : %s", sig_file->filename[0]);
      log_msg(" msg_str       : %s", msg_str);
      log_msg(" pubkey_file   : %s", pubkey_file->filename[0]);
      log_msg(" cacert_file   : %s", cacert_file->filename[0]);
      log_msg(" req_file      : %s", req_file->filename[0]);
      log_msg("");
    }

    ret_value = MakeRequest(cacert_file->filename[0], sig_file->filename[0],
                            pubkey_file->filename[0], req_file->filename[0],
                            msg_str, msg_size, verbose_flag);
  } while (0);

  if (msg_buf) {
    free(msg_buf);
    msg_buf = NULL;
  }

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}

/// Fill a single SigRlRequest structure
/*!

  | Field                           | Size          |
  |:--------------------------------|--------------:|
  | Intel(R) EPID Version (0x0200)  |       2 bytes |
  | File Type (0x000B)              |       2 bytes |
  | Group ID Number                 |      16 bytes |
  | Basic Signature                 |      52 bytes |
  | SigRL Version                   |       4 bytes |
  | Number of Non-Revoked Proofs    |       4 bytes |
  | nNRP * Non-Revoked Proofs       |    160 * nNRP |
  | Message Size in Bytes (msgSize) |       4 bytes |
  | Message                         | msgSize bytes |

 */
void FillRequest(GroupPubKey const* pubkey, EpidSignature const* sig,
                 size_t sig_size, char const* msg_str, size_t msg_size,
                 uint8_t* req_buf, size_t req_size, SigRlRequestTop* req_top) {
  const OctStr16 kEpidFileVersion = {2, 0};
  size_t i = 0;
  size_t req_mid_size = sizeof(((SigRlRequestMid*)0)->be_msg_size) + msg_size;
  SigRlRequestMid* req_mid =
      (SigRlRequestMid*)(req_buf + req_size - req_mid_size);

  if (!pubkey || !sig || !req_buf || !req_top || (!msg_str && 0 != msg_size)) {
    log_error("internal error: badarg to FillRequest()");
    return;
  }

  req_top->header.epid_version = kEpidFileVersion;
  req_top->header.file_type = kEpidFileTypeCode[kSigRlRequestFile];
  req_top->gid = pubkey->gid;
  // copy signature
  for (i = 0; i < sig_size; i++) {
    ((uint8_t*)&req_top->sig)[i] = ((uint8_t*)sig)[i];
  }
  req_mid->be_msg_size = htonl((uint32_t)msg_size);
  // copy msg
  for (i = 0; i < msg_size; i++) {
    req_mid->msg[i] = msg_str[i];
  }
}

int MakeRequest(char const* cacert_file, char const* sig_file,
                char const* pubkey_file, char const* req_file,
                char const* msg_str, size_t msg_size, bool verbose) {
  // Buffers and computed values
  // Signature buffer
  EpidSignature* sig = NULL;
  size_t sig_size = 0;

  // Group public key file
  unsigned char* pubkey_file_data = NULL;
  size_t pubkey_file_size = 0;

  // CA certificate
  EpidCaCertificate cacert = {0};

  // Group public key buffer
  GroupPubKey pubkey = {0};

  // Request buffer
  uint8_t* req_buf = NULL;
  size_t req_size = 0;

  size_t req_extra_space = (sizeof(EpidFileHeader) + sizeof(GroupId));

  int ret_value = EXIT_FAILURE;
  do {
    SigRlRequestTop* req_top = NULL;
    size_t req_file_size = 0;
    const size_t kMsgSizeSize = sizeof(((SigRlRequestMid*)0)->be_msg_size);

    if (!cacert_file || !sig_file || !pubkey_file || !req_file ||
        (!msg_str && 0 != msg_size)) {
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

    // Signature
    sig = NewBufferFromFile(sig_file, &sig_size);
    if (!sig) {
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
                pubkey_file, (int)GROUP_PUB_KEY_SIZE, (int)pubkey_file_size);
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
      log_msg("Creating SigRL revocation request:");
      log_msg("");
      log_msg(" [in]  Group ID: ");
      PrintBuffer(&pubkey.gid, sizeof(pubkey.gid));
      log_msg("");
      log_msg(" [in]  Signature Len: %d", (int)sig_size);
      log_msg(" [in]  Signature: ");
      PrintBuffer(sig, sig_size);
      log_msg("");
      log_msg(" [in]  Message Len: %d", (int)msg_size);
      log_msg(" [in]  Message: ");
      PrintBuffer(msg_str, msg_size);
      log_msg("==============================================");
    }

    req_extra_space += sig_size + kMsgSizeSize + msg_size;

    if (FileExists(req_file)) {
      req_file_size = GetFileSize_S(req_file, SIZE_MAX - req_extra_space);
    } else {
      log_msg("request file does not exsist, create new");
    }

    req_size = req_file_size + req_extra_space;

    req_buf = AllocBuffer(req_size);
    if (!req_buf) {
      ret_value = EXIT_FAILURE;
      break;
    }

    if (req_file_size > 0) {
      if (0 != ReadLoud(req_file, req_buf, req_file_size)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    req_top = (SigRlRequestTop*)(req_buf + req_file_size);

    FillRequest(&pubkey, sig, sig_size, msg_str, msg_size, req_buf, req_size,
                req_top);

    // Report Settings
    if (verbose) {
      log_msg("==============================================");
      log_msg("Reqest generated:");
      log_msg("");
      log_msg(" [in]  Request Len: %d", sizeof(SigRlRequestTop));
      log_msg(" [in]  Request: ");
      PrintBuffer(req_top, sizeof(SigRlRequestTop));
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
  if (sig) free(sig);
  if (req_buf) free(req_buf);

  return ret_value;
}
