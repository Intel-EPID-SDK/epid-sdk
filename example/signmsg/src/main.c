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
 * \brief Signmsg example implementation.
 */

#include <argtable3.h>
#include <stdlib.h>
#include <string.h>

#include "src/signmsg.h"
#include "util/buffutil.h"
#include "util/convutil.h"
#include "util/envutil.h"

// Defaults
#define PROGRAM_NAME "signmsg"
#define MPRIVKEYFILE_DEFAULT "mprivkey.dat"
#define PUBKEYFILE_DEFAULT "pubkey.bin"
#define SIG_DEFAULT "sig.dat"
#define CACERT_DEFAULT "cacert.bin"
#define HASHALG_DEFAULT "SHA-512"
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 14

bool IsCaCertAuthorizedByRootCa(void const* data, size_t size) {
  // Implementation of this function is out of scope of the sample.
  // In an actual implementation Issuing CA certificate must be validated
  // with CA Root certificate before using it in parse functions.
  (void)data;
  (void)size;
  return true;
}

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_SUCCESS;

  // intermediate return value for Intel(R) EPID functions
  EpidStatus result = kEpidErr;

  // User Settings

  // Message string parameter
  static char* msg_str = NULL;
  size_t msg_size = 0;
  char* msg_buf = NULL;  // message loaded from msg_file

  // Basename string parameter
  static char* basename_str = NULL;
  size_t basename_size = 0;
  char* basename_buf = NULL;  // basename loaded from basename_file

  // Verbose flag parameter
  static bool verbose_flag = false;

  // Buffers and computed values

  // Signature buffer
  EpidSignature* sig = NULL;
  size_t sig_size = 0;

  // SigRl file
  unsigned char* signed_sig_rl = NULL;
  size_t signed_sig_rl_size = 0;

  // Group public key file
  unsigned char* signed_pubkey = NULL;
  size_t signed_pubkey_size = 0;

  // CA certificate
  EpidCaCertificate cacert = {0};

  // Member private key buffer
  unsigned char* mprivkey = NULL;
  size_t mprivkey_size = 0;

  // Member pre-computed settings
  MemberPrecomp member_precmp = {0};
  MemberPrecomp* member_precmp_ptr = NULL;

  // Hash algorithm
  static HashAlg hashalg = kInvalidHashAlg;

  // Argument variables
  struct arg_file* sig_file =
      arg_file0(NULL, "sig", "FILE",
                "write signature to FILE (default: " SIG_DEFAULT ")");
  struct arg_str* msg = arg_str0(NULL, "msg", "MESSAGE", "MESSAGE to sign");
  struct arg_file* msg_file =
      arg_file0(NULL, "msgfile", "FILE", "FILE containing message to sign");
  struct arg_str* basename = arg_str0(
      NULL, "bsn", "BASENAME", "BASENAME to sign with (default: random)");
  struct arg_file* basename_file = arg_file0(
      NULL, "bsnfile", "FILE", "FILE containing basename to sign with");
  struct arg_file* sigrl_file = arg_file0(
      NULL, "sigrl", "FILE", "load signature based revocation list from FILE");
  struct arg_file* pubkey_file = arg_file0(
      NULL, "gpubkey", "FILE",
      "load group public key from FILE (default: " PUBKEYFILE_DEFAULT ")");
  struct arg_file* mprivkey_file = arg_file0(
      NULL, "mprivkey", "FILE",
      "load member private key from FILE (default: " MPRIVKEYFILE_DEFAULT ")");
  struct arg_file* mprecmpi_file = arg_file0(
      NULL, "mprecmpi", "FILE", "load pre-computed member data from FILE");
  struct arg_file* cacert_file = arg_file0(
      NULL, "capubkey", "FILE",
      "load IoT Issuing CA public key from FILE (default: " CACERT_DEFAULT ")");
  struct arg_str* hashalg_str =
      arg_str0(NULL, "hashalg", "{SHA-256 | SHA-384 | SHA-512 | SHA-512/256}",
               "use specified hash algorithm (default: " HASHALG_DEFAULT ")");
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
  argtable[3] = basename;
  argtable[4] = basename_file;
  argtable[5] = sigrl_file;
  argtable[6] = pubkey_file;
  argtable[7] = mprivkey_file;
  argtable[8] = mprecmpi_file;
  argtable[9] = cacert_file;
  argtable[10] = hashalg_str;
  argtable[11] = help;
  argtable[12] = verbose;
  argtable[13] = end;

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
    mprivkey_file->filename[0] = MPRIVKEYFILE_DEFAULT;
    cacert_file->filename[0] = CACERT_DEFAULT;
    hashalg_str->sval[0] = HASHALG_DEFAULT;

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt(
          "Usage: %s [OPTION]...\n"
          "Create Intel(R) EPID signature of message\n"
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

    if (basename->count > 0 && basename_file->count > 0) {
      log_error("options --bsn and --bsnfile cannot be used together");
      ret_value = EXIT_FAILURE;
      break;
    } else if (basename->count > 0) {
      basename_str = (char*)basename->sval[0];
      basename_size = strlen(basename_str);
    } else if (basename_file->count > 0) {
      basename_buf =
          NewBufferFromFile(basename_file->filename[0], &basename_size);
      if (!basename_buf) {
        log_error("Failed in reading basename from %s", basename_file);
        ret_value = EXIT_FAILURE;
        break;
      }
      basename_str = basename_buf;
    } else {
      basename_size = 0;
    }

    if (!StringToHashAlg(hashalg_str->sval[0], &hashalg)) {
      log_error("invalid hashalg: %s", hashalg_str->sval[0]);
      ret_value = EXIT_FAILURE;
      break;
    }

    if (verbose_flag) {
      log_msg("\nOption values:");
      log_msg(" sig_file      : %s", sig_file->filename[0]);
      log_msg(" msg_str       : %s", msg_str);
      log_msg(" basename_str  : %s", basename_str);
      log_msg(" pubkey_file   : %s", pubkey_file->filename[0]);
      log_msg(" mprivkey_file : %s", mprivkey_file->filename[0]);
      log_msg(" mprecmpi_file : %s", mprecmpi_file->filename[0]);
      log_msg(" hashalg       : %s", HashAlgToString(hashalg));
      log_msg(" cacert_file   : %s", cacert_file->filename[0]);
      log_msg("");
    }
    // convert command line args to usable formats

    // CA certificate
    if (0 != ReadLoud(cacert_file->filename[0], &cacert, sizeof(cacert))) {
      ret_value = EXIT_FAILURE;
      break;
    }
    // Security note:
    // Application must confirm that IoT Intel(R) EPID Issuing CA certificate
    // is authorized by IoT Intel(R) EPID Root CA, e.g.,
    // signed by IoT Intel(R) EPID Root CA.
    if (!IsCaCertAuthorizedByRootCa(&cacert, sizeof(cacert))) {
      log_error("CA certificate is not authorized");
      ret_value = EXIT_FAILURE;
      break;
    }
    // SigRl
    if (sigrl_file->count > 0) {
      if (FileExists(sigrl_file->filename[0])) {
        signed_sig_rl =
            NewBufferFromFile(sigrl_file->filename[0], &signed_sig_rl_size);
        if (!signed_sig_rl) {
          ret_value = EXIT_FAILURE;
          break;
        }

        if (0 != ReadLoud(sigrl_file->filename[0], signed_sig_rl,
                          signed_sig_rl_size)) {
          ret_value = EXIT_FAILURE;
          break;
        }
      } else {
        log_error("SigRL file %s does not exist", sigrl_file->filename[0]);
        ret_value = EXIT_FAILURE;
        break;
      }
    }
    // Group public key file
    signed_pubkey =
        NewBufferFromFile(pubkey_file->filename[0], &signed_pubkey_size);
    if (!signed_pubkey) {
      ret_value = EXIT_FAILURE;
      break;
    }
    if (0 !=
        ReadLoud(pubkey_file->filename[0], signed_pubkey, signed_pubkey_size)) {
      ret_value = EXIT_FAILURE;
      break;
    }
    // Member private key
    mprivkey = NewBufferFromFile(mprivkey_file->filename[0], &mprivkey_size);
    if (!mprivkey) {
      ret_value = EXIT_FAILURE;
      break;
    }
    if (mprivkey_size != sizeof(PrivKey) &&
        mprivkey_size != sizeof(CompressedPrivKey) &&
        mprivkey_size != sizeof(MembershipCredential)) {
      log_error("Private Key file size is inconsistent");
      ret_value = EXIT_FAILURE;
      break;
    }
    if (0 != ReadLoud(mprivkey_file->filename[0], mprivkey, mprivkey_size)) {
      ret_value = EXIT_FAILURE;
      break;
    }
    // Load Member pre-computed settings
    if (mprecmpi_file->count > 0) {
      if (sizeof(MemberPrecomp) != GetFileSize(mprecmpi_file->filename[0])) {
        log_error("incorrect input precomp size");
        ret_value = EXIT_FAILURE;
        break;
      }

      if (0 != ReadLoud(mprecmpi_file->filename[0], &member_precmp,
                        sizeof(MemberPrecomp))) {
        ret_value = EXIT_FAILURE;
        break;
      }
      member_precmp_ptr = &member_precmp;
    }

    // Report Settings
    if (verbose_flag) {
      log_msg("==============================================");
      log_msg("Signing Message:");
      log_msg("");
      log_msg(" [in]  Message Len: %d", (int)msg_size);
      log_msg(" [in]  Message: ");
      PrintBuffer(msg_str, msg_size);
      log_msg("");
      log_msg(" [in]  BaseName Len: %d", (int)basename_size);
      log_msg(" [in]  BaseName: ");
      PrintBuffer(basename_str, basename_size);
      log_msg("");
      log_msg(" [in]  SigRl Len: %d", (int)signed_sig_rl_size);
      log_msg(" [in]  SigRl: ");
      PrintBuffer(signed_sig_rl, signed_sig_rl_size);
      log_msg("");
      log_msg(" [in]  Group Public Key: ");
      PrintBuffer(signed_pubkey, signed_pubkey_size);
      log_msg("");
      log_msg(" [in]  Member Private Key: ");
      PrintBuffer(mprivkey, mprivkey_size);
      log_msg("");
      log_msg(" [in]  Hash Algorithm: %s", HashAlgToString(hashalg));
      log_msg("");
      log_msg(" [in]  IoT Intel(R) EPID Issuing CA Certificate: ");
      PrintBuffer(&cacert, sizeof(cacert));
      if (member_precmp_ptr) {
        log_msg("");
        log_msg(" [in]  Member PreComp: ");
        PrintBuffer(member_precmp_ptr, sizeof(member_precmp));
      }
      log_msg("==============================================");
    }

    // Sign
    result = SignMsg(msg_str, msg_size, basename_str, basename_size,
                     signed_sig_rl, signed_sig_rl_size, signed_pubkey,
                     signed_pubkey_size, mprivkey, mprivkey_size, hashalg,
                     member_precmp_ptr, &sig, &sig_size, &cacert);

    // Report Result
    if (kEpidNoErr != result) {
      if (kEpidSigRevokedInSigRl == result) {
        log_error("signature revoked in SigRL");
      } else {
        log_error("function SignMsg returned %s", EpidStatusToString(result));
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    if (sig && sig_size != 0) {
      // Store signature
      if (0 != WriteLoud(sig, sig_size, sig_file->filename[0])) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Success
    ret_value = EXIT_SUCCESS;
  } while (0);

  // Free allocated buffers
  if (sig) free(sig);
  if (msg_buf) free(msg_buf);
  if (basename_buf) free(basename_buf);
  if (signed_sig_rl) free(signed_sig_rl);
  if (signed_pubkey) free(signed_pubkey);
  if (mprivkey) free(mprivkey);

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}
