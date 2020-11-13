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


AUX_SOURCE_DIRECTORY(src SRC)

add_library(ipp_math
        ${SRC}
        ${IPP_CRYPTO}
        )

target_include_directories(ipp_math
        PUBLIC include
        PRIVATE src
        PRIVATE ${DEFS_INCLUDE_DIR}
        )

target_link_libraries(ipp_math ipp-crypto)

AUX_SOURCE_DIRECTORY(test UNIT_TESTS_SRC)

add_executable(ipp_math_test
        ${SRC}
        ${UNIT_TESTS_SRC}
        )

include_directories(ipp_math_test
        include
        ${DEFS_INCLUDE_DIR}
        )

target_link_libraries(ipp_math_test common)
target_link_libraries(ipp_math_test ipp-crypto)
target_link_libraries(ipp_math_test gtest_main)
target_link_libraries(ipp_math_test testhelper)


if (MSVC)

else ()
    target_compile_options(ipp_math PRIVATE -Wno-deprecated-declarations)
    target_compile_options(ipp_math_test PRIVATE -Wno-deprecated-declarations)
endif (MSVC)
enable_testing()
add_test(ipp_math_test ipp_math_test)
