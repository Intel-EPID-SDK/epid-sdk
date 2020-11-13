#===============================================================================
# Copyright 2019-2020 Intel Corporation
# All Rights Reserved.
#
# If this  software was obtained  under the  Intel Simplified  Software License,
# the following terms apply:
#
# The source code,  information  and material  ("Material") contained  herein is
# owned by Intel Corporation or its  suppliers or licensors,  and  title to such
# Material remains with Intel  Corporation or its  suppliers or  licensors.  The
# Material  contains  proprietary  information  of  Intel or  its suppliers  and
# licensors.  The Material is protected by  worldwide copyright  laws and treaty
# provisions.  No part  of  the  Material   may  be  used,  copied,  reproduced,
# modified, published,  uploaded, posted, transmitted,  distributed or disclosed
# in any way without Intel's prior express written permission.  No license under
# any patent,  copyright or other  intellectual property rights  in the Material
# is granted to  or  conferred  upon  you,  either   expressly,  by implication,
# inducement,  estoppel  or  otherwise.  Any  license   under such  intellectual
# property rights must be express and approved by Intel in writing.
#
# Unless otherwise agreed by Intel in writing,  you may not remove or alter this
# notice or  any  other  notice   embedded  in  Materials  by  Intel  or Intel's
# suppliers or licensors in any way.
#
#
# If this  software  was obtained  under the  Apache License,  Version  2.0 (the
# "License"), the following terms apply:
#
# You may  not use this  file except  in compliance  with  the License.  You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#
# Unless  required  by   applicable  law  or  agreed  to  in  writing,  software
# distributed under the License  is distributed  on an  "AS IS"  BASIS,  WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the   License  for the   specific  language   governing   permissions  and
# limitations under the License.
#===============================================================================
cmake_minimum_required(VERSION 3.1)

set(DEFS_INCLUDE_DIR "../../defs/include")

set(SRC_FILES
        src/allowed_basenames.c
        src/config.c
        src/decompresskey.c
        src/gid_parser.c
        src/init.c
        src/join.c
        src/nrprove.c
        src/presig.c
        src/presig_compute.c
        src/provisioncompressed.c
        src/provisioncredential.c
        src/provisionkey.c
        src/registerbasename.c
        src/serialize.c
        src/sethashalg.c
        src/setsigrl.c
        src/sign.c
        src/signbasic.c
        src/stack.c
        src/startup.c
        src/validate.c
        src/write_precomp.c
        )

set(TEST_FILES
        unittests/internal/nr_prove-test.cc
        unittests/internal/presig_compute-test.cc
        unittests/internal/serialize-test.cc
        unittests/internal/signbasic-test.cc
        unittests/internal/validate-test.cc
        unittests/allowed_basenames-test.cc
        unittests/context-test.cc
        unittests/decompress_privkey-test.cc
        unittests/get_sigsize-test.cc
        unittests/join_request-simulator-test.cc
        unittests/join_request-test.cc
        unittests/main-testhelper.cc
        unittests/member-testhelper.cc
        unittests/presig-test.cc
        unittests/provision_compressed-test.cc
        unittests/provision_credential-test.cc
        unittests/provision_key-test.cc
        unittests/sign-test.cc
        unittests/write_precomp-test.cc
        )

if (SHARED_MODE)
    add_library(member_tiny SHARED ${SRC_FILES})
    set_property(TARGET member_tiny PROPERTY POSITION_INDEPENDENT_CODE 1)
else ()
    add_library(member_tiny STATIC ${SRC_FILES})
endif ()
target_include_directories(
        member_tiny
        PUBLIC include
        PUBLIC ../include
        PRIVATE ${DEFS_INCLUDE_DIR}
)

target_link_libraries(member_tiny tinymath)

enable_testing()
add_executable(member_tiny_test
        ${SRC_FILES}
        ${TEST_FILES}
        )
target_include_directories(member_tiny_test
        PUBLIC include
        PUBLIC ../include
        PRIVATE unittests
        PRIVATE ${DEFS_INCLUDE_DIR}
        ../../verifier/header
        )
target_compile_definitions(testhelper PRIVATE TINY=1)
target_link_libraries(member_tiny_test gtest_main)
target_link_libraries(member_tiny_test tinymath)
target_link_libraries(member_tiny_test verifier)
target_link_libraries(member_tiny_test testhelper)
add_test(member_tiny_test member_tiny_test)