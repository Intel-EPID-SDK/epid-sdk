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
        src/gid_parser.c
        src/hashsize.c
        src/sig_types.c
        src/sigrlvalid.c
        src/stack.c
        src/ipp-impl/commitment.c
        src/ipp-impl/epid2params.c
        src/ipp-impl/grouppubkey.c
        src/ipp-impl/validate_privkey.c
        src/ipp-impl/1.1/commitment.c
        src/ipp-impl/1.1/epid11params.c
        src/ipp-impl/1.1/grouppubkey.c
        )

add_library(common ${SRC_FILES})
target_include_directories(common
        PUBLIC include
        PRIVATE ${DEFS_INCLUDE_DIR}
        )

if(MSVC)
    target_compile_options(common PRIVATE /sdl /WX /GS)
endif(MSVC)
target_link_libraries(common ipp_math)
target_link_libraries(common ipp-crypto)

set(TEST_FILES
        test/main-test.cc
        test/validate_privkey-test.cc
        )

add_executable(common_test
        ${SRC_FILES}
        ${TEST_FILES}
        )
target_include_directories(common_test
        PUBLIC include
        PRIVATE ${DEFS_INCLUDE_DIR}
        )

target_link_libraries(common_test gtest_main)
target_link_libraries(common_test ipp_math)
target_link_libraries(common_test ipp-crypto)

enable_testing()
add_test(common_test common_test)
