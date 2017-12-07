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
 * \brief Extract group keys from group key output file
 */

#include <argtable3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "epid/common/file_parser.h"
#include "epid/common/types.h"
#include "util/buffutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"
#include "util/strutil.h"

#define PROGRAM_NAME "extractgrps"
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 5

#pragma pack(1)
/// Intel(R) EPID Key Output File Entry
typedef struct EpidBinaryGroupCertificate {
  EpidFileHeader header;     ///< Intel(R) EPID binary file header
  GroupPubKey pubkey;        ///< Intel(R) EPID 2.0 group public key
  EcdsaSignature signature;  ///< ECDSA Signature on SHA-256 of above values
} EpidBinaryGroupCertificate;
#pragma pack()

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_SUCCESS;

  size_t keyfile_size = 0;
  size_t num_keys_extracted = 0;
  size_t num_keys_in_file = 0;

  FILE* file = NULL;

  int i = 0;
  size_t bytes_read = 0;

  // Verbose flag parameter
  static bool verbose_flag = false;

  struct arg_file* keyfile =
      arg_file1(NULL, NULL, "FILE", "FILE containing keys to extract");
  struct arg_int* num_keys_to_extract =
      arg_int1(NULL, NULL, "NUM", "number of keys to extract");
  struct arg_lit* help = arg_lit0(NULL, "help", "display this help and exit");
  struct arg_lit* verbose =
      arg_lit0("v", "verbose", "print status messages to stdout");
  struct arg_end* end = arg_end(ARGPARSE_ERROR_MAX);
  void* argtable[ARGTABLE_SIZE];
  int nerrors;

  /* initialize the argtable array with ptrs to the arg_xxx structures
   * constructed above */
  argtable[0] = keyfile;
  argtable[1] = num_keys_to_extract;
  argtable[2] = help;
  argtable[3] = verbose;
  argtable[4] = end;

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

    /* Parse the command line as defined by argtable[] */
    nerrors = arg_parse(argc, argv, argtable);

    if (help->count > 0) {
      log_fmt(
          "Usage: %s [OPTION]... [FILE] [NUM]\n"
          "Extract the first NUM group certs from FILE to current "
          "directory\n"
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

    if (num_keys_to_extract->ival[0] < 0) {
      log_error("unable extract negative number of keys");
      ret_value = EXIT_FAILURE;
      break;
    }

    // check file existence
    if (!FileExists(keyfile->filename[0])) {
      log_error("cannot access '%s'", keyfile->filename[0]);
      ret_value = EXIT_FAILURE;
      break;
    }

    keyfile_size = GetFileSize(keyfile->filename[0]);
    if (0 != keyfile_size % sizeof(EpidBinaryGroupCertificate)) {
      log_error(
          "input file '%s' is invalid: does not contain integral number of "
          "group keys",
          keyfile->filename[0]);
      ret_value = EXIT_FAILURE;
      break;
    }
    num_keys_in_file = keyfile_size / sizeof(EpidBinaryGroupCertificate);

    if ((unsigned int)num_keys_to_extract->ival[0] > num_keys_in_file) {
      log_error("can not extract %d keys: only %d in file",
                num_keys_to_extract->ival[0], num_keys_in_file);
      ret_value = EXIT_FAILURE;
      break;
    }

    file = fopen(keyfile->filename[0], "rb");
    if (!file) {
      log_error("failed read from '%s'", keyfile->filename[0]);
      ret_value = EXIT_FAILURE;
      break;
    }

    // start extraction
    for (i = 0; i < num_keys_to_extract->ival[0]; i++) {
      EpidBinaryGroupCertificate temp;
      int seek_failed = 0;
      seek_failed = fseek(file, i * sizeof(temp), SEEK_SET);
      bytes_read = fread(&temp, 1, sizeof(temp), file);
      if (seek_failed || bytes_read != sizeof(temp)) {
        log_error("failed to extract key #%lu from '%s'", i,
                  keyfile->filename[0]);
      } else {
        // ulong max = 4294967295
        char outkeyname[256] = {0};
        if (memcmp(&kEpidVersionCode[kEpid2x], &temp.header.epid_version,
                   sizeof(temp.header.epid_version)) ||
            memcmp(&kEpidFileTypeCode[kGroupPubKeyFile], &temp.header.file_type,
                   sizeof(temp.header.file_type))) {
          log_error("failed to extract key #%lu from '%s': file is invalid", i,
                    keyfile->filename[0]);
          ret_value = EXIT_FAILURE;
          break;
        }
        snprintf(outkeyname, sizeof(outkeyname), "pubkey%010u.bin", i);
        if (FileExists(outkeyname)) {
          log_error("file '%s' already exists", outkeyname);
          ret_value = EXIT_FAILURE;
          break;
        }
        if (0 != WriteLoud(&temp, sizeof(temp), outkeyname)) {
          log_error("failed to write key #%lu from '%s'", i,
                    keyfile->filename[0]);
        } else {
          num_keys_extracted++;
        }
      }
    }
    if (EXIT_FAILURE == ret_value) {
      break;
    }

    log_msg("extracted %lu of %lu keys", num_keys_extracted, num_keys_in_file);
  } while (0);

  if (file) {
    fclose(file);
    file = NULL;
  }

  arg_freetable(argtable, sizeof(argtable) / sizeof(argtable[0]));

  return ret_value;
}
