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

add_subdirectory(tpm2)

set(DEFS_INCLUDE_DIR "../../defs/include")

set(SRC_FILE
        src/allowed_basenames.c
        src/context.c
        src/decompress_privkey.c
        src/get_sigsize.c
        src/join.c
        src/join_commitment.c
        src/nrprove.c
        src/nrprove_commitment.c
        src/precomp.c
        src/presig.c
        src/privateexp.c
        src/provision_bulk.c
        src/provision_compressed.c
        src/provision_join.c
        src/resize.c
        src/sign.c
        src/sign_commitment.c
        src/signbasic.c
        src/split_grouppubkey.c
        src/startup.c
        src/storage.c
        src/validatekey.c
        src/write_precomp.c
        )
set(TEST_FILES
        unittests/context-test.cc
        unittests/decompress_privkey-test.cc
        unittests/get_sigsize-test.cc
        unittests/iskeyvalid-test.cc
        unittests/join_request-simulator-test.cc
        unittests/join_request-test.cc
        unittests/main-test.cc
        unittests/member-testhelper.cc
        unittests/nr_prove-test.cc
        unittests/presig-test.cc
        unittests/privateexp-test.cc
        unittests/provision_compressed-test.cc
        unittests/provision_credential-test.cc
        unittests/provision_key-test.cc
        unittests/resize-test.cc
        unittests/sign-test.cc
        unittests/signbasic-test.cc
        unittests/split_grouppubkey-test.cc
        unittests/split_sign-test.cc
        unittests/split_signbasic-test.cc
        unittests/storage-test.cc
        unittests/write_precomp-test.cc
        )


if (SHARED_MODE)
    add_library(member_split SHARED ${SRC_FILE})
    set_property(TARGET member_split PROPERTY POSITION_INDEPENDENT_CODE 1)
else ()
    add_library(member_split STATIC ${SRC_FILE})
endif ()

target_include_directories(
        member_split
        PUBLIC ../include
        PRIVATE headers
        PRIVATE ${DEFS_INCLUDE_DIR}
)
if (MSVC)
    target_compile_options(member_split PRIVATE /sdl /WX /GS)
endif (MSVC)
target_link_libraries(member_split ipp_math)
target_link_libraries(member_split common)
target_link_libraries(member_split tpm2)
target_link_libraries(member_split ipp_math)
target_link_libraries(member_split common)

add_executable(member_split_test
        ${SRC_FILE}
        ${TEST_FILES}
        tpm2/unittests/tpm2_wrapper-testhelper.cc
        )
target_include_directories(member_split_test
        PUBLIC unittests
        PUBLIC ../include
        PRIVATE headers
        PRIVATE tpm2/unittests
        PRIVATE ${DEFS_INCLUDE_DIR}
        PRIVATE ../../verifier/header
        )


target_link_libraries(member_split_test gtest_main)
target_link_libraries(member_split_test ipp_math)
target_link_libraries(member_split_test common)
target_link_libraries(member_split_test verifier)
target_link_libraries(member_split_test testhelper)
target_link_libraries(member_split_test tpm2)

add_test(member_split_test member_split_test)
