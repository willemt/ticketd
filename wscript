# -*- mode: python -*-
# vi: set ft=python :

import sys
import os


def options(opt):
        opt.load('compiler_c')


def configure(conf):
    conf.load('compiler_c')
    conf.load('clib')


def build(bld):
    bld.load('clib')

    if sys.platform == 'linux2':
        platform = '-DLINUX'
    else:
        platform = ''

    clibs = """
        bitstream
        container_of
        h2o_helpers
        lmdb
        lmdb_helpers
        raft
        tpl
        uv_helpers
        """.split()

    h2o_includes = """
        ./deps/h2o/include
        ./deps/picohttpparser
        ./deps/klib
        """.split()

    uv_includes = """
        ./deps/libuv/include
        """.split()

    nm_includes = """
        ./deps/nanomsg/include
        """.split()

    bld.program(
        source="""
        src/main.c
        """.split() + bld.clib_c_files(clibs),
        includes=['./include'] + bld.clib_h_paths(clibs) + h2o_includes + uv_includes + nm_includes,
        target='kippud',
        stlibpath=['.'],
        libpath=[os.getcwd()],
        lib=['uv', 'h2o', 'ssl', 'crypto', 'nanomsg'],
        cflags=[
            #'-Werror',
            #'-Werror=format',
            '-Werror=int-to-pointer-cast',
            '-g',
            platform,
            '-fcolor-diagnostics',
            '-fdiagnostics-color',
            '-Werror=unused-variable',
            '-Werror=return-type',
            '-Werror=uninitialized',
            '-Werror=pointer-to-int-cast',
            #'-Wcast-align',
            ])
