# pylint: disable=locally-disabled, import-error
############################################################################
# Copyright 2016-2019 Intel Corporation
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
"""
Implements dumping of build system and compilation tool versions.

Example
   print DefaultEnvironment().DumpToolVersions()
"""

import copy
import os
import re
import shutil
import string
import subprocess
import sys
import tempfile
from collections import OrderedDict

import SCons.Script
from SCons.Script.SConscript import SConsEnvironment


class ConfigurationError(Exception):
    """Raised when build configuration has issues or not supported"""
    pass


def get_parts_versions(env):
    """Get Parts related versions given SCons environment env"""
    return OrderedDict({'python': string.split(sys.version, " ", 1)[0],
                        'scons': str(SCons.__version__),
                        'parts': str(env.PartsExtensionVersion())})


def _format_echo(text):
    """Compose system echo command outputs text"""
    quote = '' if os.name == 'nt' else '"'
    return 'echo {}{}{}'.format(quote, text, quote)


def _execute(cmd, env_variables):
    """Execute command in temporary folder with environment variables given"""
    temp_dir = tempfile.mkdtemp()
    try:
        proc = subprocess.Popen(cmd,
                                cwd=temp_dir,
                                env=env_variables,
                                shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError('failure executing: "{}"'.format(cmd))
        return stdout
    except:
        raise
    finally:
        shutil.rmtree(temp_dir)


def _try_compile(code, env):
    """Try compile and link C code. Returns verbose output."""
    cmd_content = _format_echo(code)
    if env.get('MSVC_VERSION', None):
        cmd_content = '{} > a.cpp | $CXX $CCFLAGS a.cpp /link /verbose'.format(
            cmd_content)
    elif env.get('GCC_VERSION', None) or env.get('CLANG_VERSION', None):
        if env.get('GXX_VERSION', None) or env.get('CLANG_VERSION', None):
            cmd_content = '{} | $CXX $CCFLAGS -xc++ -Wl,--verbose -'.format(
                cmd_content)
        else:
            cmd_content = '{} | $CC  $CCFLAGS -xc   -Wl,--verbose -'.format(
                cmd_content)
    else:
        raise ConfigurationError
    py2 = sys.version_info[0] == 2
    win = sys.platform.startswith('win')
    text_type = unicode if py2 else str
    env_variables = copy.deepcopy(env['ENV'])
    env_variables['PATH'] = str(env_variables.get('PATH', ''))
    if py2 and win:
        for key, val in env_variables.items():
            if py2 and win:
                if isinstance(key, text_type) or isinstance(val, text_type):
                    key_ = key.encode('ascii')
                    val_ = val.encode('ascii')
                    del env_variables[key]
                    env_variables[key_] = val_
    return _execute(env.subst(cmd_content), env_variables)


def _get_compiler_version(env):
    """Get compiler version string"""
    if env.get('MSVC_VERSION', None):
        version = 'MSVC {}'.format(env['MSVC_VERSION'])
    elif env.get('GCC_VERSION', None):
        version = 'GCC {}'.format(env['GCC_VERSION'])
        if env.get('GXX_VERSION', None):
            version = '{} and GXX {}'.format(version, env['GXX_VERSION'])
    elif env.get('CLANG_VERSION', None):
        version = 'CLANG {}'.format(env['CLANG_VERSION'])
    else:
        raise ConfigurationError

    # Intel(R) C compiler always depends from base toolchain
    if env.get('INTELC_VERSION', None):
        version = 'INTELC {0} with {1}'.format(
            env['INTELC_VERSION'],
            version)
    return version


def _get_default_libs(build_verbose_out, env):
    """Get compiler default libraries"""
    if env.get('MSVC_VERSION', None):
        defaultlib_regexp = r'.*Searching (.*\.lib).*'
    elif env.get('GCC_VERSION', None) or env.get('CLANG_VERSION', None):
        if os.name == 'nt':
            defaultlib_regexp = r'\n.* open (.*) succeeded'
        else:
            defaultlib_regexp = r'[\n(](/.*\.so[-.\da-fA-F]*).*'
    else:
        raise ConfigurationError

    return list(
        set(re.findall(defaultlib_regexp, build_verbose_out, re.M)))


def _get_crt(default_libs, env):
    """Extract runtime library version reference from default libraries"""
    if env['TARGET_OS'] == 'win32':
        runtime_version_set = set()
        for lib_path in default_libs:
            path_components = os.path.realpath(lib_path).split(os.sep)
            if 'Windows Kits' in path_components:
                i = path_components.index('Windows Kits')
                runtime_version_set.add(
                    'Windows Kits {0} {1}'.format(path_components[i + 1],
                                                  path_components[i + 3]))
            elif 'gcc' in path_components:
                i = path_components.index('gcc')
                runtime_version_set.add(
                    'GCC {0} {1}'.format(path_components[i + 1],
                                         path_components[i + 2]))
        sdk_or_libc = '; '.join(list(runtime_version_set))
    else:
        # for posix additionally report versions of libc used
        sdk_or_libc = os.path.split(os.path.realpath(
            next((lib for lib in default_libs
                  if 'libc' in lib.lower() and
                  'libcilk' not in lib.lower()),
                 None)))[1]
    return sdk_or_libc


def dump_tool_versions(env, include_toolchain=True):
    """Log tools and libraries versions given SCons environment env

    Args:
        env: Scons environment.
        include_toolchain: Log version of compilation toolchain if True.
    """
    versions = get_parts_versions(env)
    if include_toolchain:
        try:
            versions['compiler'] = _get_compiler_version(env)
            if 'fuzzer' in env.subst('$CCFLAGS'):
                code = 'extern \\"C\\" int LLVMFuzzerTestOneInput() {return 0;}'
            else:
                code = 'int main(){return 0;}'
            compiler_stdout = _try_compile(code, env)
            versions['default_libs'] = _get_default_libs(compiler_stdout, env)
            versions['sdk_or_libc'] = _get_crt(versions['default_libs'], env)
        except (ConfigurationError, RuntimeError):
            # keep going on compilation failures, versions will not be
            # displayed
            pass

    res = '**************** VERSIONS *************'
    long_names = {
        'python': 'Python Version',
        'scons': 'SCons  Version',
        'parts': 'Parts  Version',
        'compiler': 'Compiler Version',
        'sdk_or_libc': 'Libc/SDK',
        'default_libs': 'Default Libs'
    }
    for name, value in versions.iteritems():
        if not isinstance(value, list):
            res += '\n* {0}: {1}'.format(long_names.get(name, name), value)
        else:
            res += '\n* {0}:\n* \t{1}'.format(long_names.get(name, name),
                                              '\n* \t'.join(sorted(value)))
    res += '\n***************************************'
    return res


# adding logic to Scons Environment object
SConsEnvironment.DumpToolVersions = dump_tool_versions
