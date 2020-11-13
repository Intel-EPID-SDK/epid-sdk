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
project("verifier")

set(COMMON_INCLUDE_DIR "../internal/common/include")
set(DEFS_INCLUDE_DIR "../defs/include")
set(IPP_MATH_INCLUDE_DIR "../internal/ippmath/include")
set(IPP_CRYPTO_INCLUDE_DIR "../../ext/ipp-crypto/include")
set(GTEST_INCLUDE_DIR "../../ext/googletest/googletest/include" CACHE STRING "Where to find GTest header files")

set(SRC_FILES
        src/check_privrl_entry.c
        src/context.c
        src/nrverify.c
        src/sigs_linked.c
        src/verify.c
        src/verifybasic.c
        src/1.1/check_privrl_entry.c
        src/1.1/context.c
        src/1.1/nrverify.c
        src/1.1/sigs_linked.c
        src/1.1/verify.c
        src/1.1/verifybasic.c
        )
set(TEST_FILES
        unittests/blacklistsplit-test.cc
        unittests/check_privrl_entry-test.cc
        unittests/context-test.cc
        unittests/main-test.cc
        unittests/nrverify-test.cc
        unittests/setgroup-test.cc
        unittests/sigs_linked-test.cc
        unittests/sigs_linkedsplit-test.cc
        unittests/split_nrverify-test.cc
        unittests/verifier-testhelper.cc
        unittests/verify-test.cc
        unittests/verifybasic-test.cc
        unittests/verifybasicsplit-test.cc
        unittests/verifysplit-test.cc
        unittests/1.1/check_privrl_entry-test.cc
        unittests/1.1/context-test.cc
        unittests/1.1/nrverify-test.cc
        unittests/1.1/sigs_linked-test.cc
        unittests/1.1/verifier-testhelper.cc
        unittests/1.1/verify-test.cc
        unittests/1.1/verifybasic-test.cc
        )

add_library(verifier
        ${SRC_FILES})

target_include_directories(
        verifier
        PUBLIC include
        PRIVATE header
        PRIVATE ${DEFS_INCLUDE_DIR}
        PRIVATE ${COMMON_INCLUDE_DIR}
        PRIVATE ${IPP_MATH_INCLUDE_DIR}
        PRIVATE ${IPP_CRYPTO_INCLUDE_DIR}
)

if(MSVC)
    target_compile_options(verifier PRIVATE /sdl /WX /GS)
endif(MSVC)
target_link_libraries(verifier common)
target_link_libraries(verifier ipp_math)
target_link_libraries(verifier ipp-crypto)

add_executable(verifier_test
        ${SRC_FILES}
        ${TEST_FILES}
        )
target_include_directories(verifier_test
        PUBLIC include
        unittests
        PRIVATE header
        PRIVATE ${DEFS_INCLUDE_DIR}
        PRIVATE ${COMMON_INCLUDE_DIR}
        PRIVATE ${IPP_MATH_INCLUDE_DIR}
        PRIVATE ${IPP_CRYPTO_INCLUDE_DIR}
        ../internal/testhelper/include
        )
target_link_libraries(verifier_test gtest_main)
target_link_libraries(verifier_test common)
target_link_libraries(verifier_test ipp_math)
target_link_libraries(verifier_test testhelper)
#target_link_libraries(verifier_test ipp-crypto)

enable_testing()
add_test(verifier_test verifier_test)
