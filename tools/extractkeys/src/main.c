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
 * \brief Extract member private keys from key output file
 *
 * Not validating SHA hashes in key file
 */

#include <stdio.h>
#include <stdlib.h>

#include <argtable3.h>
#include "epid/common/types.h"
#include "util/buffutil.h"
#include "util/envutil.h"
#include "util/stdtypes.h"
#include "util/strutil.h"

#define PROGRAM_NAME "extractkeys"
#define ARGPARSE_ERROR_MAX 20
#define ARGTABLE_SIZE 6

#pragma pack(1)
/// Intel(R) EPID Key Output File Entry
typedef struct EpidKeyOutputFileKey {
  unsigned char product_id[2];  ///< 2-byte Product ID (Big Endian)
  unsigned char key_id[8];      ///< 8-byte Key Unique Id(Big Endian)
  unsigned char svn[4];  ///< 4-byte Security Version Number (SVN) (Big Endian)
  PrivKey privkey;       ///< Intel(R) EPID 2.0 Private Key
  unsigned char hash[20];  ///< 20-byte SHA-1 of above
} EpidKeyOutputFileKey;

/// Intel(R) EPID Compressed Key Output File Entry
typedef struct EpidCompressedKeyOutputFileKey {
  unsigned char product_id[2];  ///< 2-byte Product ID (Big Endian)
  unsigned char key_id[8];      ///< 8-byte Key Unique Id(Big Endian)
  unsigned char svn[4];  ///< 4-byte Security Version Number (SVN) (Big Endian)
  CompressedPrivKey privkey;  ///< Intel(R) EPID 2.0 Compressed Private Key
  unsigned char hash[20];     ///< 20-byte SHA-1 of above
} EpidCompressedKeyOutputFileKey;
#pragma pack()

/// Main entrypoint
int main(int argc, char* argv[]) {
  // intermediate return value for C style functions
  int ret_value = EXIT_SUCCESS;
  // Buffer to store read key
  uint8_t temp[sizeof(EpidKeyOutputFileKey)] = {0};

  // Private key to extract
  void* privkey = 0;
  size_t privkey_size = 0;

  size_t keyfile_size = 0;
  size_t keyfile_entry_size = 0;
  size_t num_keys_extracted = 0;
  size_t num_keys_in_file = 0;

  FILE* file = NULL;

  // Verbose flag parameter
  static bool verbose_flag = false;

  int i = 0;
  size_t bytes_read = 0;

  struct arg_file* keyfile =
      arg_file1(NULL, NULL, "FILE", "FILE containing keys to extract");
  struct arg_int* num_keys_to_extract =
      arg_int1(NULL, NULL, "NUM", "number of keys to extract");
  struct arg_lit* compressed =
      arg_lit0("c", "compressed", "extract compressed keys");
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
  argtable[2] = compressed;
  argtable[3] = help;
  argtable[4] = verbose;
  argtable[5] = end;

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
          "Extract the first NUM private keys from FILE to current "
          "directory.\n"
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
    if (compressed->count > 0) {
      privkey_size = sizeof(CompressedPrivKey);
      privkey = &(((EpidCompressedKeyOutputFileKey*)&temp[0])->privkey);
      keyfile_entry_size = sizeof(EpidCompressedKeyOutputFileKey);
    } else {
      privkey_size = sizeof(PrivKey);
      privkey = &(((EpidKeyOutputFileKey*)&temp[0])->privkey);
      keyfile_entry_size = sizeof(EpidKeyOutputFileKey);
    }

    if (0 != keyfile_size % keyfile_entry_size) {
      log_error(
          "input file '%s' is invalid: does not contain integral number of "
          "keys",
          keyfile->filename[0]);
      ret_value = EXIT_FAILURE;
      break;
    }
    num_keys_in_file = keyfile_size / keyfile_entry_size;

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
    for (i = 0; i < num_keys_to_extract->ival[0]; ++i) {
      int seek_failed = 0;
      seek_failed = fseek(file, (int)(i * keyfile_entry_size), SEEK_SET);
      bytes_read = fread(&temp, 1, keyfile_entry_size, file);
      if (seek_failed || bytes_read != keyfile_entry_size) {
        log_error("failed to extract key #%lu from '%s'", i,
                  keyfile->filename[0]);
      } else {
        char outkeyname[256] = {0};
        snprintf(outkeyname, sizeof(outkeyname), "mprivkey%010u.dat", i);

        if (FileExists(outkeyname)) {
          log_error("file '%s' already exists", outkeyname);
          ret_value = EXIT_FAILURE;
          break;
        }
        if (0 != WriteLoud(privkey, privkey_size, outkeyname)) {
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
