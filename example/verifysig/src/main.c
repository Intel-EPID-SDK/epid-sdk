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
 * \brief Verifysig example implementation.
 */

#include <argtable3.h>
#include <stdlib.h>
#include <string.h>

#include "epid/common/file_parser.h"
#include "epid/verifier/1.1/api.h"
#include "epid/verifier/api.h"
#include "src/verifysig.h"
#include "src/verifysig11.h"
#include "util/buffutil.h"
#include "util/convutil.h"
#include "util/envutil.h"

// Defaults
#define PROGRAM_NAME "verifysig"
#define PUBKEYFILE_DEFAULT "pubkey.bin"
#define PRIVRL_DEFAULT NULL
#define SIGRL_DEFAULT NULL
#define GRPRL_DEFAULT "grprl.bin"
#define VERIFIERRL_DEFAULT NULL
#define SIG_DEFAULT "sig.dat"
#define CACERT_DEFAULT "cacert.bin"
#define HASHALG_DEFAULT "SHA-512"
#define VPRECMPI_DEFAULT NULL
#define VPRECMPO_DEFAULT NULL
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 17

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
  void* sig = NULL;
  size_t sig_size = 0;

  // PrivRl buffer
  void* signed_priv_rl = NULL;
  size_t signed_priv_rl_size = 0;

  // SigRl buffer
  void* signed_sig_rl = NULL;
  size_t signed_sig_rl_size = 0;

  // GrpRl buffer
  void* signed_grp_rl = NULL;
  size_t signed_grp_rl_size = 0;

  // VerRl buffer
  VerifierRl* ver_rl = NULL;
  size_t ver_rl_size = 0;

  // Group public key buffer
  void* signed_pubkey = NULL;
  size_t signed_pubkey_size = 0;

  // Verifier pre-computed settings
  void* verifier_precmp = NULL;
  size_t vprecmpi_file_size = 0;

  // CA certificate
  EpidCaCertificate cacert = {0};
  // Hash algorithm
  static HashAlg hashalg = kInvalidHashAlg;

  // Argument variables
  struct arg_file* sig_file =
      arg_file0(NULL, "sig", "FILE",
                "load signature from FILE (default: " SIG_DEFAULT ")");
  struct arg_str* msg = arg_str0(NULL, "msg", "MESSAGE",
                                 "MESSAGE that was signed (default: empty)");
  struct arg_file* msg_file = arg_file0(
      NULL, "msgfile", "FILE", "FILE containing message that was signed");
  struct arg_str* basename = arg_str0(
      NULL, "bsn", "BASENAME", "BASENAME used in signature (default: random)");
  struct arg_file* basename_file = arg_file0(
      NULL, "bsnfile", "FILE", "FILE containing basename used in signature");
  struct arg_file* privrl_file = arg_file0(
      NULL, "privrl", "FILE", "load private key revocation list from FILE");
  struct arg_file* sigrl_file = arg_file0(
      NULL, "sigrl", "FILE", "load signature based revocation list from FILE");
  struct arg_file* grprl_file = arg_file0(
      NULL, "grprl", "FILE",
      "load group revocation list from FILE (default: " GRPRL_DEFAULT ")");
  struct arg_file* verrl_file = arg_file0(
      NULL, "verifierrl", "FILE", "load verifier revocation list from FILE");
  struct arg_file* pubkey_file = arg_file0(
      NULL, "gpubkey", "FILE",
      "load group public key from FILE (default: " PUBKEYFILE_DEFAULT ")");
  struct arg_file* vprecmpi_file = arg_file0(
      NULL, "vprecmpi", "FILE", "load pre-computed verifier data from FILE");
  struct arg_file* vprecmpo_file = arg_file0(
      NULL, "vprecmpo", "FILE", "write pre-computed verifier data to FILE");
  struct arg_file* cacert_file = arg_file0(
      NULL, "capubkey", "FILE",
      "load IoT Issuing CA public key from FILE (default: " CACERT_DEFAULT ")");
  struct arg_str* hashalg_str = arg_str0(
      NULL, "hashalg", "{SHA-256 | SHA-384 | SHA-512 | SHA-512/256}",
      "use specified hash algorithm for 2.0 groups (default: " HASHALG_DEFAULT
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
  argtable[3] = basename;
  argtable[4] = basename_file;
  argtable[5] = privrl_file;
  argtable[6] = sigrl_file;
  argtable[7] = grprl_file;
  argtable[8] = verrl_file;
  argtable[9] = pubkey_file;
  argtable[10] = vprecmpi_file;
  argtable[11] = vprecmpo_file;
  argtable[12] = cacert_file;
  argtable[13] = hashalg_str;
  argtable[14] = help;
  argtable[15] = verbose;
  argtable[16] = end;

  // set program name for logging
  set_prog_name(PROGRAM_NAME);
  do {
    EpidVersion epid_version = kNumEpidVersions;
    // Read command line args

    /* verify the argtable[] entries were allocated sucessfully */
    if (arg_nullcheck(argtable) != 0) {
      /* NULL entries were detected, some allocations must have failed */
      printf("%s: insufficient memory\n", PROGRAM_NAME);
      ret_value = EXIT_FAILURE;
      break;
    }

    /* set any command line default values prior to parsing */
    sig_file->filename[0] = SIG_DEFAULT;
    grprl_file->filename[0] = GRPRL_DEFAULT;
    pubkey_file->filename[0] = PUBKEYFILE_DEFAULT;
    cacert_file->filename[0] = CACERT_DEFAULT;
    hashalg_str->sval[0] = HASHALG_DEFAULT;

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt(
          "Usage: %s [OPTION]...\n"
          "Verify signature was created by group member in good standing\n"
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
      log_msg(" privrl_file   : %s", privrl_file->filename[0]);
      log_msg(" sigrl_file    : %s", sigrl_file->filename[0]);
      log_msg(" grprl_file    : %s", grprl_file->filename[0]);
      log_msg(" verrl_file    : %s", verrl_file->filename[0]);
      log_msg(" vprecmpi_file : %s", vprecmpi_file->filename[0]);
      log_msg(" vprecmpo_file : %s", vprecmpo_file->filename[0]);
      log_msg(" hashalg       : %s", HashAlgToString(hashalg));
      log_msg(" cacert_file   : %s", cacert_file->filename[0]);
      log_msg("");
    }
    // convert command line args to usable formats

    // Signature
    sig = NewBufferFromFile(sig_file->filename[0], &sig_size);
    if (!sig) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // PrivRl
    if (privrl_file->count > 0) {
      signed_priv_rl =
          NewBufferFromFile(privrl_file->filename[0], &signed_priv_rl_size);
      if (!signed_priv_rl) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // SigRl
    if (sigrl_file->count > 0) {
      signed_sig_rl =
          NewBufferFromFile(sigrl_file->filename[0], &signed_sig_rl_size);
      if (!signed_sig_rl) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // GrpRl
    signed_grp_rl =
        NewBufferFromFile(grprl_file->filename[0], &signed_grp_rl_size);
    if (!signed_grp_rl) {
      ret_value = EXIT_FAILURE;
      break;
    }
    // VerRl
    if (verrl_file->count > 0) {
      ver_rl =
          (VerifierRl*)NewBufferFromFile(verrl_file->filename[0], &ver_rl_size);
      if (!ver_rl) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Group public key
    signed_pubkey =
        NewBufferFromFile(pubkey_file->filename[0], &signed_pubkey_size);
    if (!signed_pubkey) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // CA certificate
    if (0 != ReadLoud(cacert_file->filename[0], &cacert, sizeof(cacert))) {
      ret_value = EXIT_FAILURE;
      break;
    }

    // Security note:
    // Application must confirm that IoT Issuing CA
    // certificate is authorized by IoT Root CA,
    // e.g., signed by IoT Root CA.
    if (!IsCaCertAuthorizedByRootCa(&cacert, sizeof(cacert))) {
      log_error("CA certificate is not authorized");
      ret_value = EXIT_FAILURE;
      break;
    }

    // Detect Intel(R) EPID version
    result = EpidParseFileHeader(signed_pubkey, signed_pubkey_size,
                                 &epid_version, NULL);
    if (kEpidNoErr != result || kNumEpidVersions <= epid_version) {
      log_error("EPID version can not be detected");
      ret_value = EXIT_FAILURE;
      break;
    }

    // Configure hashalg based on group
    if (kEpid1x == epid_version) {
      if (kSha256 != hashalg && hashalg_str->count > 0) {
        log_error(
            "unsupported hash algorithm: %s only supported for 2.0 groups",
            HashAlgToString(hashalg));
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Load Verifier pre-computed settings

    if (vprecmpi_file->count > 0) {
      vprecmpi_file_size = GetFileSize_S(vprecmpi_file->filename[0], SIZE_MAX);
      verifier_precmp = AllocBuffer(vprecmpi_file_size);

      if (0 != ReadLoud(vprecmpi_file->filename[0], verifier_precmp,
                        vprecmpi_file_size)) {
        ret_value = EXIT_FAILURE;
        break;
      }
    }

    // Report Settings
    if (verbose_flag) {
      log_msg("==============================================");
      log_msg("Verifying Message:");
      log_msg("");
      log_msg(" [in]  Intel(R) EPID version: %s",
              EpidVersionToString(epid_version));
      log_msg("");
      log_msg(" [in]  Signature Len: %d", (int)sig_size);
      log_msg(" [in]  Signature: ");
      PrintBuffer(sig, sig_size);
      log_msg("");
      log_msg(" [in]  Message Len: %d", (int)msg_size);
      log_msg(" [in]  Message: ");
      PrintBuffer(msg_str, msg_size);
      log_msg("");
      log_msg(" [in]  BaseName Len: %d", (int)basename_size);
      log_msg(" [in]  BaseName: ");
      PrintBuffer(basename_str, basename_size);
      log_msg("");
      log_msg(" [in]  PrivRl Len: %d", (int)signed_priv_rl_size);
      log_msg(" [in]  PrivRl: ");
      PrintBuffer(signed_priv_rl, signed_priv_rl_size);
      log_msg("");
      log_msg(" [in]  SigRl Len: %d", (int)signed_sig_rl_size);
      log_msg(" [in]  SigRl: ");
      PrintBuffer(signed_sig_rl, signed_sig_rl_size);
      log_msg("");
      log_msg(" [in]  GrpRl Len: %d", (int)signed_grp_rl_size);
      log_msg(" [in]  GrpRl: ");
      PrintBuffer(signed_grp_rl, signed_grp_rl_size);
      log_msg("");
      log_msg(" [in]  VerRl Len: %d", (int)ver_rl_size);
      log_msg(" [in]  VerRl: ");
      PrintBuffer(ver_rl, ver_rl_size);
      log_msg("");
      log_msg(" [in]  Group Public Key: ");
      PrintBuffer(signed_pubkey, sizeof(signed_pubkey_size));
      log_msg("");
      log_msg(" [in]  Hash Algorithm: %s", HashAlgToString(hashalg));
      if (vprecmpi_file->count > 0) {
        log_msg("");
        log_msg(" [in]  Verifier PreComp: ");
        PrintBuffer(verifier_precmp, vprecmpi_file_size);
      }
      log_msg("==============================================");
    }

    // Verify
    if (kEpid2x == epid_version) {
      if (verifier_precmp && vprecmpi_file_size != sizeof(VerifierPrecomp)) {
        if (vprecmpi_file_size == sizeof(VerifierPrecomp) - sizeof(GroupId)) {
          log_error(
              "incorrect input precomp size: precomp format may have changed, "
              "try regenerating it");
        } else {
          log_error("incorrect input precomp size");
        }
        ret_value = EXIT_FAILURE;
        break;
      }
      result =
          Verify(sig, sig_size, msg_str, msg_size, basename_str, basename_size,
                 signed_priv_rl, signed_priv_rl_size, signed_sig_rl,
                 signed_sig_rl_size, signed_grp_rl, signed_grp_rl_size, ver_rl,
                 ver_rl_size, signed_pubkey, signed_pubkey_size, &cacert,
                 hashalg, &verifier_precmp, &vprecmpi_file_size);
    } else if (kEpid1x == epid_version) {
      if (verifier_precmp &&
          vprecmpi_file_size != sizeof(Epid11VerifierPrecomp)) {
        log_error("incorrect input precomp size");
        ret_value = EXIT_FAILURE;
        break;
      }
      result = Verify11(sig, sig_size, msg_str, msg_size, basename_str,
                        basename_size, signed_priv_rl, signed_priv_rl_size,
                        signed_sig_rl, signed_sig_rl_size, signed_grp_rl,
                        signed_grp_rl_size, signed_pubkey, signed_pubkey_size,
                        &cacert, &verifier_precmp, &vprecmpi_file_size);
    } else {
      log_error("EPID version %s is not supported",
                EpidVersionToString(epid_version));
      ret_value = EXIT_FAILURE;
      break;
    }
    // Report Result
    if (kEpidNoErr == result) {
      log_msg("signature verified successfully");
    } else if (kEpidErr == result) {
      log_error(
          "signature verification failed: "
          "member did not prove it was not revoked");
      ret_value = result;
      break;
    } else {
      log_error("signature verification failed: %s",
                EpidStatusToString(result));
      ret_value = result;
      break;
    }

    // Store Verifier pre-computed settings
    if (vprecmpo_file->count > 0) {
      if (0 != WriteLoud(verifier_precmp, vprecmpi_file_size,
                         vprecmpo_file->filename[0])) {
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
  if (signed_priv_rl) free(signed_priv_rl);
  if (signed_sig_rl) free(signed_sig_rl);
  if (signed_grp_rl) free(signed_grp_rl);
  if (ver_rl) free(ver_rl);
  if (signed_pubkey) free(signed_pubkey);
  if (verifier_precmp) free(verifier_precmp);

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}
