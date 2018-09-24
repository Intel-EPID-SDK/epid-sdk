############################################################################
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
############################################################################
"""Main SConstruct file for SDK"""

import re
import os
from parts import *

############################################################################
Default('build::')
Default('utest::')
#Default('run_utest::')

SetOptionDefault('TARGET_VARIANT', '${TARGET_OS}-${TARGET_ARCH}')

SetOptionDefault('CONFIG', 'release')

SetOptionDefault('INSTALL_ROOT', '#_install/')

SetOptionDefault('INSTALL_BIN', '$INSTALL_ROOT/bin/')

SetOptionDefault('INSTALL_DATA_SUBDIR', 'data')

SetOptionDefault('INSTALL_INCLUDE', '$INSTALL_ROOT/include')
SetOptionDefault('INSTALL_LIB', '$INSTALL_ROOT/lib/${TARGET_VARIANT}')

SetOptionDefault('INSTALL_TEST_BIN', '$INSTALL_ROOT/utest')
SetOptionDefault('INSTALL_FUZZTEST', '$INSTALL_ROOT/fuzztest/')
SetOptionDefault('INSTALL_ATEST', 'atest')

# package directory
SetOptionDefault('PKG_NO_INSTALL', '#_package/')

SetOptionDefault('mode', 'install_lib')

############################################################################
mode = re.split("[, ]", DefaultEnvironment().subst('$mode'))

AddOption("--enable-sanitizers",
          help=(
              "Build with sanitizers (https://github.com/google/sanitizers)."),
          action='store_true', dest='sanitizers',
          default=False)
if GetOption('sanitizers'):
    SetOptionDefault('sanitizers', True)

AddOption("--sanitizers-recover",
          help=("Configure sanititzers to recover and continue execution "
                "on error found. Only applicable when sanitizers are enabled."
                "See --enable-sanitizers option."),
          action='store_true', dest='sanitizers_recover',
          default=False)
if GetOption("sanitizers_recover"):
    SetOptionDefault('sanitizers_recover', True)

AddOption("--enable-fuzzer",
          help=("Enable compiler instrumentation for fuzzer."),
          action='store_true', dest='fuzzer',
          default=False)
if GetOption("fuzzer"):
    SetOptionDefault('fuzzer', True)
    # always enable sanitizers when fuzzing
    SetOptionDefault('sanitizers', True)
    # use clang by default
    SetOptionDefault('toolchain', 'clang')

AddOption("--split",
          help=("Build split member."),
          action='store_true', dest='split',
          default=False)
if GetOption("split"):
    mode.append('split')

AddOption("--use-tss",
          help=("Link with TPM TSS. The TSSROOT138 environment variable "
                "must be set."),
          action='store_true', dest='use-tss',
          default=False)
if GetOption("use-tss"):
    mode.append('use_tss')
    mode.append('split')

AddOption("--use-commercial-ipp",
          help=("Link with commercial IPP. The IPPCRYPTOROOT environment "
                "variable must be set."),
          action='store_true', dest='use-commercial-ipp',
          default=False)
if GetOption("use-commercial-ipp"):
    mode.append('use_commercial_ipp')

AddOption("--ipp-shared",
          help=("Build /ext/ipp as shared library."),
          action='store_true', dest='ipp-shared',
          default=False)
if GetOption('ipp-shared'):
    mode.append('build_ipp_shared')

############################################################################

def include_parts(part_list, **kwargs):
    for parts_file in part_list:
        if os.path.isfile(DefaultEnvironment().subst(parts_file)):
            Part(parts_file=parts_file, mode=mode, **kwargs)

############################################################################

sdk_parts = [
    # deps
    'ext/gtest/gtest.parts',
    'ext/ipp/ippcp.parts',
    'ext/argtable3/argtable3.parts',
    #'ext/google_benchmark/google_benchmark.parts',


    'epid/fuzz-testhelper/fuzz-testhelper.parts',
    'epid/common-testhelper/common-testhelper.parts',
    'epid/common/common.parts',

    # verifier
    'epid/verifier/verifier.parts',

    # member
    # member elsewhere due to multiple builds -- enhance as one part?

    # issuer
    'epid/issuer/issuer.parts',

    # samples
    'example/util/util.parts',
    'example/verifysig/verifysig.parts',
    'example/signmsg/signmsg.parts',

    'example/data/data.parts',
    'example/compressed_data/compressed_data.parts',
    'example/split_data/split_data.parts',

    # ikgf tools
    'tools/joinreq/joinreq.parts',
    'tools/mprecmp/mprecmp.parts',
    'tools/revokegrp/revokegrp.parts',
    'tools/revokekey/revokekey.parts',
    'tools/revokesig/revokesig.parts',
    'tools/extractkeys/extractkeys.parts',
    'tools/extractgrps/extractgrps.parts',

    # internal tools
    'tools/ikgfwrapper/ikgfwrapper.parts',

    # internal tests
    'test/testbot/testbot.parts',
    'test/testbot/signmsg/signmsg_testbot.parts',
    'test/testbot/verifysig/verifysig_testbot.parts',
    'test/testbot/integration/integration_testbot.parts',
    'test/testbot/ssh_remote/ssh_remote_testbot.parts',
    'test/testbot/revokegrp/revokegrp_testbot.parts',
    'test/testbot/revokekey/revokekey_testbot.parts',
    'test/testbot/revokesig/revokesig_testbot.parts',
    'test/testbot/extractkeys/extractkeys_testbot.parts',
    'test/testbot/extractgrps/extractgrps_testbot.parts',
    'test/testbot/joinreq/joinreq_testbot.parts',
    'test/testbot/mprecmp/mprecmp_testbot.parts',
    'test/tss/tss.parts',
    'test/fuzz/fuzz.parts',
    #'test/epid_data/epid_data.parts',
    #'test/performance/performance.parts',
]

if 'dist' in COMMAND_LINE_TARGETS:
    sdk_parts += [
        'dist_sdk.parts',
        'dist_issuer.parts',
        'dist.parts'
    ]

include_parts(sdk_parts)

Part(parts_file='epid/common/tinycommon.parts',
     config_independent=True,
     mode=mode)

if 'split' in mode or 'use_tss' in mode:
    Part(parts_file='epid/member/splitmember.parts', mode=mode)
else:
    member_cfg = ('embedded'
                  if not DefaultEnvironment().isConfigBasedOn('debug')
                  else DefaultEnvironment().subst('$CONFIG'))
    Part(parts_file='epid/member/tinymember.parts',
         config_independent=True,  # so utests can depend on it
         CONFIG=member_cfg,
         mode=mode
        )

############################################################################

env = DefaultEnvironment()
print env.DumpToolVersions()
for i in BUILD_TARGETS:
    if "utest::" in str(i):
        if not CanBeCompiled(env, CPP11_CODE):
            env.PrintError(
                "Toolchain doesn't support C++11, can't build unit tests")
        break
