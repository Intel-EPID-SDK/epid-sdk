############################################################################
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
############################################################################
# pylint: disable=locally-disabled, invalid-name, wildcard-import, unused-wildcard-import
"""
Configure gcc ARM toolchain
"""

from parts.platform_info import SystemPlatform
from parts.tools.Common.Finders import PathFinder
import parts.tools.GnuCommon.common
# import gcc tool from parts ( we only need to add configurations to be loaded)
from parts.tools.gcc import *

parts.tools.GnuCommon.common.gcc.Register(
    # compilation for Linux armel architecture system can be done from any Linux x86_64 system
    hosts=[SystemPlatform('posix', 'x86_64')],
    targets=[SystemPlatform('posix', 'arm')],
    info=[
        parts.tools.GnuCommon.common.GnuInfo(
            # default binary location for arm-linux-gnueabi-gcc compiler
            install_scanner=[PathFinder(['/usr/bin'])],
            opt_dirs=['/opt/'],
            script=None,
            subst_vars={},
            shell_vars={'PATH': '${GCC.INSTALL_ROOT}'},
            test_file='arm-linux-gnueabi-gcc')
    ]
)

parts.tools.GnuCommon.common.gcc.Register(
    # compilation for Linux armhf architecture system can be done from any Linux x86_64 system
    hosts=[SystemPlatform('posix', 'x86_64')],
    targets=[SystemPlatform('posix', 'arm_hf')],
    info=[
        parts.tools.GnuCommon.common.GnuInfo(
            # default binary location for arm-linux-gnueabihf-gcc compiler
            install_scanner=[PathFinder(['/usr/bin'])],
            opt_dirs=['/opt/'],
            script=None,
            subst_vars={},
            shell_vars={'PATH': '${GCC.INSTALL_ROOT}'},
            test_file='arm-linux-gnueabihf-gcc')
    ]
)

parts.tools.GnuCommon.common.gcc.Register(
    # compilation for Linux arm 64bit can be done from any Linux x86_64 system
    hosts=[SystemPlatform('posix', 'x86_64')],
    targets=[SystemPlatform('posix', 'aarch64')],
    info=[
        parts.tools.GnuCommon.common.GnuInfo(
            # default binary location for aarch64-linux-gnu-gcc compiler
            install_scanner=[PathFinder(['/usr/bin'])],
            opt_dirs=['/opt/'],
            script=None,
            subst_vars={},
            shell_vars={'PATH': '${GCC.INSTALL_ROOT}'},
            test_file='aarch64-linux-gnu-gcc')
    ]
)
