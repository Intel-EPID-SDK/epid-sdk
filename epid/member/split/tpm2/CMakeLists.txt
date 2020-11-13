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

set(DEFS_INCLUDE_DIR "../../../defs/include")

set(BUILTIN_SRC_FILES
        builtin/commit.c
        builtin/config.c
        builtin/context.c
        builtin/createprimary.c
        builtin/flushcontext.c
        builtin/getrandom.c
        builtin/keyinfo.c
        builtin/load_external.c
        builtin/nv.c
        builtin/registerkey.c
        builtin/sign.c)

set(IBM_TSS_SRC_FILES
        ibm_tss/commit.c
        ibm_tss/config.c
        ibm_tss/context.c
        ibm_tss/conversion.c
        ibm_tss/createprimary.c
        ibm_tss/flushcontext.c
        ibm_tss/getrandom.c
        ibm_tss/keyinfo.c
        ibm_tss/load_external.c
        ibm_tss/nv.c
        ibm_tss/printtss.c
        ibm_tss/registerkey.c
        ibm_tss/sign.c
        )

set(TEST_FILES
        unittests/commit-simulator-test.cc
        unittests/commit-test.cc
        unittests/context-test.cc
        unittests/createprimary-test.cc
        unittests/getrandom-simulator-test.cc
        unittests/getrandom-test.cc
        unittests/load_external-simulator-test.cc
        unittests/load_external-test.cc
        unittests/main-testhelper.cc
        unittests/nv-test.cc
        unittests/sign-simulator-test.cc
        unittests/sign-test.cc
        unittests/tpm2-testhelper.cc
        unittests/tpm2_wrapper-testhelper.cc)
set(TSS_TEST_FILES
        unittests/conversion-tss-test.cc
        unittests/getrandom-tss-test.cc)

if (TSS_PATH)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTPM_TSS")
    add_library(tpm2
            ${IBM_TSS_SRC_FILES}
            )
    target_include_directories(tpm2
            PUBLIC ../headers
            ../../include
            PRIVATE ${DEFS_INCLUDE_DIR}
            PRIVATE ${COMMON_INCLUDE_DIR}
            PRIVATE ${IPP_MATH_INCLUDE_DIR}
            )

    enable_testing()
    add_executable(tpm2_test
            ${IBM_TSS_SRC_FILES}
            ${TEST_FILES}
            ${TSS_TEST_FILES}
            )
    target_include_directories(tpm2_test
            PUBLIC unittests
            PUBLIC ../headers
            ../../include
            PRIVATE ${DEFS_INCLUDE_DIR}
            )
    target_link_libraries(tpm2_test gtest_main)
    target_link_libraries(tpm2_test tinymath)
    target_link_libraries(tpm2_test verifier)
    target_link_libraries(tpm2_test testhelper)
    add_test(tpm2_test tpm2_test)

else ()
    add_library(tpm2 ${BUILTIN_SRC_FILES})

    target_include_directories(tpm2
            PUBLIC ../headers
            ../../include
            PRIVATE ${DEFS_INCLUDE_DIR}
            )

    target_link_libraries(tpm2 common)
    target_link_libraries(tpm2 ipp_math)
    enable_testing()
    add_executable(tpm2_test
            ${BUILTIN_SRC_FILES}
            ${TEST_FILES}
            )
    target_include_directories(tpm2_test
            PUBLIC unittests
            PUBLIC ../headers
            ../../include
            PRIVATE ${DEFS_INCLUDE_DIR}
            )
    target_link_libraries(tpm2_test gtest_main)
    target_link_libraries(tpm2_test tinymath)
    target_link_libraries(tpm2_test verifier)
    target_link_libraries(tpm2_test testhelper)
    add_test(tpm2_test tpm2_test)

endif (TSS_PATH)



