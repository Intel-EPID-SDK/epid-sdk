/*############################################################################
  # Copyright 2016-2018 Intel Corporation
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
 * \brief Conversion utilities implementation.
 *
 */

#include "util/convutil.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "util/envutil.h"

#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

const char* epid_version_to_string[kNumEpidVersions] = {"1", "2"};

char const* EpidVersionToString(EpidVersion version) {
  if ((int)version < 0 || (size_t)version >= COUNT_OF(epid_version_to_string))
    return "unknown";
  return epid_version_to_string[version];
}

bool StringToEpidVersion(char const* str, EpidVersion* version) {
  size_t i;
  if (!version || !str) return false;
  for (i = 0; i < COUNT_OF(epid_version_to_string); i++) {
    if (0 == strcmp(str, epid_version_to_string[i])) {
      *version = (EpidVersion)i;
      return true;
    }
  }
  log_error("epid version \"%s\" is unknown", str);
  return false;
}

const char* epid_file_type_to_string[kNumFileTypes] = {
    "IssuingCaPubKey", "GroupPubKey", "PrivRl", "SigRl", "GroupRl"};

char const* EpidFileTypeToString(EpidFileType type) {
  if ((int)type < 0 || (size_t)type >= COUNT_OF(epid_file_type_to_string))
    return "unknown";
  return epid_file_type_to_string[type];
}

bool StringToEpidFileType(char const* str, EpidFileType* type) {
  size_t i;
  if (!type || !str) return false;
  for (i = 0; i < COUNT_OF(epid_file_type_to_string); i++) {
    if (0 == strcmp(str, epid_file_type_to_string[i])) {
      *type = (EpidFileType)i;
      return true;
    }
  }
  log_error("epid file type \"%s\" is unknown", str);
  return false;
}
