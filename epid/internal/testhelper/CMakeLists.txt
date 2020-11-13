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

AUX_SOURCE_DIRECTORY(unittests UNIT_TESTS_SRC)

set(SRC_FILES
        src/bignum_wrapper-testhelper.cc
        src/ecgroup_wrapper-testhelper.cc
        src/ecpoint_wrapper-testhelper.cc
        src/epid2params_wrapper-testhelper.cc
        src/epid_gtest-testhelper.cc
        src/epid_params-testhelper.cc
        src/ffelement_wrapper-testhelper.cc
        src/finite_field_wrapper-testhelper.cc
        src/mem_params-testhelper.cc
        src/member_wrapper-testhelper.cc
        src/octstr-testhelper.cc
        src/testapp-testhelper.cc
        src/verifier_wrapper-testhelper.cc
        src/1.1/epid_params-testhelper.cc
        src/1.1/verifier_wrapper-testhelper.cc
        )

add_library(testhelper
            ${SRC_FILES}
        )

target_include_directories(testhelper
        PUBLIC include
        ${DEFS_INCLUDE_DIR}
        ../../member/include
        )

target_link_libraries(testhelper ipp_math)
target_link_libraries(testhelper common)
target_link_libraries(testhelper verifier)
target_link_libraries(testhelper ipp-crypto)

add_executable(testhelper_tests
        ${SRC_FILES}
        ${UNIT_TESTS_SRC}
        )

target_include_directories(testhelper_tests
        PUBLIC include
        ${DEFS_INCLUDE_DIR}
        )

target_link_libraries(testhelper_tests gtest_main)
target_link_libraries(testhelper_tests ipp_math)
target_link_libraries(testhelper_tests ipp-crypto)
target_link_libraries(testhelper_tests common)
target_link_libraries(testhelper_tests verifier)
target_link_libraries(testhelper_tests member_tiny)

enable_testing()
add_test(testhelper_tests testhelper_tests)
