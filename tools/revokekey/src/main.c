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
 * \brief Create private key revocation list request
 *
 */

#include <argtable3.h>
#include <stdlib.h>
#include <string.h>

#include "epid/common/file_parser.h"
#include "epid/member/api.h"
#include "util/buffutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"

const OctStr16 kEpidFileVersion = {2, 0};

// Defaults
#define PROGRAM_NAME "revokekey"
#define PRIVKEY_DEFAULT "mprivkey.dat"
#define REQFILE_DEFAULT "privreq.dat"
#define PUBKEYFILE_DEFAULT "pubkey.bin"
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 8

/// Partial signature request, includes all but message.
typedef struct PrivRlRequestTop {
  EpidFileHeader header;  ///< Intel(R) EPID File Header
  PrivKey privkey;        ///< Intel(R) EPID Private Key
} PrivRlRequestTop;

int OpenKey(char const* privkey_file, char const* gpubkey_file,
            char const* cacert_file, PrivKey* priv_key) {
  int retval = EXIT_FAILURE;
  size_t file_size = GetFileSize(privkey_file);

  if (0 == file_size && !FileExists(privkey_file)) {
    log_error("cannot access '%s'", privkey_file);
    return EXIT_FAILURE;
  }

  if (file_size == sizeof(PrivKey)) {
    if (0 != ReadLoud(privkey_file, priv_key, sizeof(PrivKey))) {
      return EXIT_FAILURE;
    }
    retval = EXIT_SUCCESS;
  } else if (file_size == sizeof(CompressedPrivKey)) {
    void* signed_pubkey = NULL;
    if (!cacert_file) {
      log_error("issuing CA public key must be specified for compressed key");
      return EXIT_FAILURE;
    }
    if (!gpubkey_file) {
      log_error("group public key must be specified for compressed key");
      return EXIT_FAILURE;
    }

    do {
      size_t signed_pubkey_size = 0;
      CompressedPrivKey cmp_key;
      EpidCaCertificate cacert;
      GroupPubKey pub_key;
      EpidStatus sts;
      if (0 != ReadLoud(privkey_file, &cmp_key, sizeof(CompressedPrivKey))) {
        retval = EXIT_FAILURE;
        break;
      }
      signed_pubkey = NewBufferFromFile(gpubkey_file, &signed_pubkey_size);
      if (!signed_pubkey) {
        retval = EXIT_FAILURE;
        break;
      }
      if (0 != ReadLoud(gpubkey_file, signed_pubkey, signed_pubkey_size)) {
        retval = EXIT_FAILURE;
        break;
      }
      if (0 != ReadLoud(cacert_file, &cacert, sizeof(cacert))) {
        retval = EXIT_FAILURE;
        break;
      }
      sts = EpidParseGroupPubKeyFile(signed_pubkey, signed_pubkey_size, &cacert,
                                     &pub_key);
      if (kEpidNoErr != sts) {
        log_error("error while parsing group public key");
        retval = EXIT_FAILURE;
        break;
      }
      sts = EpidDecompressPrivKey(&pub_key, &cmp_key, priv_key);
      if (kEpidNoErr != sts) {
        log_error("error while decompressing member private key");
        retval = EXIT_FAILURE;
        break;
      }
      retval = EXIT_SUCCESS;
    } while (0);
    free(signed_pubkey);
  } else {
    log_error("unexpected file size for '%s'", privkey_file);
    retval = EXIT_FAILURE;
  }
  return retval;
}

int MakeRequest(PrivKey const* priv_key, char const* req_file, bool verbose) {
  // Request buffer
  uint8_t* req_buf = NULL;
  size_t req_size = 0;
  size_t req_extra_space = 0;
  int ret_value = EXIT_FAILURE;
  do {
    size_t entry_size = sizeof(EpidFileHeader) + sizeof(PrivKey);
    size_t req_file_size = 0;
    bool duplicate = false;
    size_t i = 0;
    PrivRlRequestTop* req_top = NULL;

    if (!req_file) {
      log_error("internal error: badarg to MakeRequest()");
      ret_value = EXIT_FAILURE;
      break;
    }

    // convert command line args to usable formats

    // Report Settings
    if (verbose) {
      log_msg("==============================================");
      log_msg("Input settings:");
      log_msg("");
      log_msg(" [in]  Group ID: ");
      PrintBuffer(&(priv_key->gid), sizeof(priv_key->gid));
      log_msg("");
      log_msg(" [in]  Private Key Len: %d", sizeof(PrivKey));
      log_msg(" [in]  Private Key: ");
      PrintBuffer(priv_key, sizeof(PrivKey));
      log_msg("");
      log_msg("==============================================");
    }

    req_extra_space += entry_size;
    if (FileExists(req_file)) {
      req_file_size = GetFileSize_S(req_file, SIZE_MAX - req_extra_space);

      if (req_file_size < entry_size) {
        log_error("output file smaller then size of one entry");
        ret_value = EXIT_FAILURE;
        break;
      }

      if (req_file_size % entry_size != 0) {
        log_error("size of output file is not multiple of the entry size");
        ret_value = EXIT_FAILURE;
        break;
      }
    } else {
      log_msg("request file does not exsist, create new");
    }

    req_size = req_file_size + req_extra_space;

    req_buf = AllocBuffer(req_size);
    if (!req_buf) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // Load existing request file
    if (req_file_size > 0) {
      if (0 != ReadLoud(req_file, req_buf, req_file_size)) {
        ret_value = EXIT_FAILURE;
        break;
      }

      for (i = 0; i < req_file_size / entry_size; i++) {
        if (0 == memcmp(req_buf + entry_size * i + sizeof(EpidFileHeader),
                        priv_key, sizeof(PrivKey))) {
          duplicate = true;
          break;
        }
      }
      if (duplicate) {
        log_error("this private key already exists in output file");
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Append to the request
    req_top = (PrivRlRequestTop*)(req_buf + req_file_size);
    req_top->header.epid_version = kEpidFileVersion;
    req_top->header.file_type = kEpidFileTypeCode[kPrivRlRequestFile];
    req_top->privkey = *priv_key;

    // Report Settings
    if (verbose) {
      log_msg("==============================================");
      log_msg("Request generated:");
      log_msg("");
      log_msg(" [in]  Request Len: %d", sizeof(PrivRlRequestTop));
      log_msg(" [in]  Request: ");
      PrintBuffer(req_top, sizeof(PrivRlRequestTop));
      log_msg("==============================================");
    }

    // Store request
    if (0 != WriteLoud(req_buf, req_size, req_file)) {
      ret_value = EXIT_FAILURE;
      break;
    }

    ret_value = EXIT_SUCCESS;
  } while (0);

  // Free allocated buffers
  if (req_buf) free(req_buf);

  return ret_value;
}

/// Main entrypoint
int main(int argc, char* argv[]) {
  int retval = EXIT_FAILURE;

  // Verbose flag parameter
  static bool verbose_flag = false;

  // Private key
  PrivKey priv_key;

  struct arg_file* privkey_file = arg_file0(
      NULL, "mprivkey", "FILE",
      "load private key to revoke from FILE (default: " PRIVKEY_DEFAULT ")");
  struct arg_file* req_file = arg_file0(
      NULL, "req", "FILE",
      "append signature revocation request to FILE (default: " REQFILE_DEFAULT
      ")");
  struct arg_lit* help = arg_lit0(NULL, "help", "display this help and exit");
  struct arg_lit* verbose =
      arg_lit0("v", "verbose", "print status messages to stdout");
  struct arg_rem* comment_line = arg_rem(
      NULL, "The following options are only needed for compressed keys:");
  struct arg_file* gpubkey_file = arg_file0(
      NULL, "gpubkey", "FILE",
      "load group public key from FILE (default: " PUBKEYFILE_DEFAULT ")");
  struct arg_file* capubkey_file = arg_file0(
      NULL, "capubkey", "FILE", "load IoT Issuing CA public key from FILE");
  struct arg_end* end = arg_end(ARGPARSE_ERROR_MAX);
  void* argtable[ARGTABLE_SIZE];
  int nerrors;

  /* initialize the argtable array with ptrs to the arg_xxx structures
   * constructed above */
  argtable[0] = privkey_file;
  argtable[1] = req_file;
  argtable[2] = help;
  argtable[3] = verbose;
  argtable[4] = comment_line;
  argtable[5] = gpubkey_file;
  argtable[6] = capubkey_file;
  argtable[7] = end;

  // set program name for logging
  set_prog_name(PROGRAM_NAME);
  do {
    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable) != 0) {
      /* NULL entries were detected, some allocations must have failed */
      printf("%s: insufficient memory\n", PROGRAM_NAME);
      retval = EXIT_FAILURE;
      break;
    }

    /* set any command line default values prior to parsing */
    privkey_file->filename[0] = PRIVKEY_DEFAULT;
    gpubkey_file->filename[0] = PUBKEYFILE_DEFAULT;
    req_file->filename[0] = REQFILE_DEFAULT;
    capubkey_file->filename[0] = NULL;

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
      retval = EXIT_SUCCESS;
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
      retval = EXIT_FAILURE;
      break;
    }
    if (verbose_flag) {
      log_msg("\nOption values:");
      log_msg(" mprivkey  : %s", privkey_file->filename[0]);
      log_msg(" req       : %s", req_file->filename[0]);
      log_msg(" gpubkey   : %s", gpubkey_file->filename[0]);
      log_msg(" capubkey  : %s", capubkey_file->filename[0]);
      log_msg("");
    }

    retval = OpenKey(privkey_file->filename[0], gpubkey_file->filename[0],
                     capubkey_file->filename[0], &priv_key);
    if (EXIT_SUCCESS != retval) {
      break;
    }
    retval = MakeRequest(&priv_key, req_file->filename[0], verbose_flag);
  } while (0);

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return retval;
}
