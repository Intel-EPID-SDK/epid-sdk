# pylint: disable=locally-disabled, invalid-name, missing-docstring, wrong-import-position, wrong-import-order, unused-variable, import-error
# import c++ core toolchain
cplusplus = __import__('c++', globals(), locals(), [])
# import c core toolchain
import SCons.Tool.cc
import parts.tools.Common
import parts.tools.GnuCommon
import parts.tools.cc


def generate(env):
    """
    Add Builders and construction variables for CLang compilers
    to an Environment.
    """

    static_obj, shared_obj = SCons.Tool.createObjBuilders(env)

    # get the basic C++ flags (unix based stuff only??)
    cplusplus.generate(env)
    parts.tools.cc.generate(env)

    # set up shell env for running compiler
    parts.tools.GnuCommon.clang.MergeShellEnv(env)

    env['CC'] = parts.tools.Common.toolvar(
        env['CLANG']['TOOL'], ('clang',), env=env)
    env['CXX'] = parts.tools.Common.toolvar(
        env['CLANG']['TOOL'].replace('clang', 'clang++'), ('clang++',), env=env)

    env['SHOBJSUFFIX'] = '.pic.o'
    env['OBJSUFFIX'] = '.o'

    env['SHCCFLAGS'] = SCons.Util.CLVar('$CCFLAGS -fPIC')


def exists(env):
    return parts.tools.GnuCommon.clang.Exists(env)
