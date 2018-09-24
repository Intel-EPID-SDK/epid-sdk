# pylint: disable=unused-wildcard-import,missing-docstring,wildcard-import,import-error
from parts.tools.IntelCommon.intelc_posix import *
import filescanner
import common

# 32-bit 16.0
Intelc.Register(
    hosts=[SystemPlatform('posix', 'any'),
           SystemPlatform('darwin', 'any')],
    targets=[SystemPlatform('posix', 'x86'),
             SystemPlatform('darwin', 'x86')],
    info=[
        IntelcInfo(
            version='16.*-*',
            install_scanner=filescanner.file_scanner16(
                path='/opt/intel',
                pattern=common.intel_16_plus_posix,
                arch='ia32',
                env=['ICPP_COMPILER16'],
                platform_subdir='linux'),
            script=None,
            subst_vars={},
            shell_vars={
                'PATH': '${INTELC.INSTALL_ROOT}/linux/bin/ia32/',
                'INCLUDE': '${INTELC.INSTALL_ROOT}/linux/compiler/include/',
                'LIB': '${INTELC.INSTALL_ROOT}/linux/compiler/lib/ia32/'
            },
            test_file='icc')
    ])

# 64-bit 16.0
Intelc.Register(
    hosts=[
        SystemPlatform('posix', 'x86_64'),
        SystemPlatform('darwin', 'x86_64')
    ],
    targets=[
        SystemPlatform('posix', 'x86_64'),
        SystemPlatform('darwin', 'x86_64')
    ],
    info=[
        IntelcInfo(
            version='16.*-*',
            install_scanner=filescanner.file_scanner16(
                path='/opt/intel',
                pattern=common.intel_16_plus_posix,
                arch='intel64',
                env=['ICPP_COMPILER16'],
                platform_subdir='linux'),
            script=None,
            subst_vars={},
            shell_vars={
                'PATH': '${INTELC.INSTALL_ROOT}/linux/bin/intel64/',
                'INCLUDE': '${INTELC.INSTALL_ROOT}/linux/compiler/include/',
                'LIB': '${INTELC.INSTALL_ROOT}/linux/compiler/lib/intel64/'
            },
            test_file='icc')
    ])
