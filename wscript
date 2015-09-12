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

    cflags = """
        -Werror=int-to-pointer-cast
        -g
        -Werror=unused-variable
        -Werror=return-type
        -Werror=uninitialized
        -Werror=pointer-to-int-cast
    """.split()

    lib = ['uv', 'h2o', 'ssl', 'crypto']

    if sys.platform == 'darwin':
        cflags.extend("""
            -fcolor-diagnostics
            -fdiagnostics-color
            """.split())
    elif sys.platform.startswith('linux'):
        cflags.extend("""
            -DLINUX
            """.split())
        lib.append('pthread')
        lib.append('rt')

    clibs = """
        container_of
        h2o_helpers
        lmdb
        lmdb_helpers
        raft
        tpl
        uv_helpers
        uv_multiplex
        """.split()

    h2o_includes = """
        ./deps/h2o/include
        ./deps/picohttpparser
        ./deps/klib
        """.split()

    uv_includes = """
        ./deps/libuv/include
        """.split()

    bld.program(
        source="""
        src/main.c
        """.split() + bld.clib_c_files(clibs),
        includes=['./include'] + bld.clib_h_paths(clibs) + h2o_includes + uv_includes,
        target='ticketd',
        stlibpath=['.'],
        libpath=[os.getcwd()],
        lib=lib,
        cflags=cflags)
