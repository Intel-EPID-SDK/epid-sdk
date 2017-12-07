############################################################################
# Copyright 2017 Intel Corporation
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
# pylint: disable=locally-disabled, invalid-name, missing-docstring

"""win32 gcc compiler configuration for embedded
"""
from parts.config import ConfigValues, configuration

def map_default_version(env):
    return env['GCC_VERSION']

config = configuration(map_default_version)

config.VersionRange(
    "3-*",
    append=ConfigValues(
        CCFLAGS=[
            # optimize for size
            '-Os',
            # prevent using built in stdlib replacement functions
            '-fno-builtin',
            '-fno-stack-protector',
            '-fomit-frame-pointer',
            '-fno-asynchronous-unwind-tables',
            # allow linker to optimize out not used stuff
            '-fdata-sections',
            '-ffunction-sections',
            # treat warnings as errors
            '-Werror',
            # enable all warnings
            '-Wall',
            # extra warnings
            '-Wextra',
            # Allow struct initilization with {0}
            '-Wno-missing-braces',
            # dump stack usage to file
            '-fstack-usage',
            # dump control flow graph
            '-fdump-tree-cfg-raw',
        ],
        CPPDEFINES=[
            'NDEBUG',
        ],
        SHLINKFLAGS=[
            # do not use stadard system entrypoint
            '-e 0',
        ],
        LINKFLAGS=[
            # do not link standard system libraries
            '-nodefaultlibs',
            '-nostdlib',
            # do not use stadard system startup
            '-nostartfiles',
            # remove all symbol table and relocation information
            '-s',
            # link only what is used
            '-Xlinker',
            '--gc-sections',
        ],))
