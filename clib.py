#!/usr/bin/env python
# encoding: utf-8
# Willem-Hendrik Thiart, 2014

from waflib.Configure import conf

import simplejson as json
import os
import itertools


# TODO
# Add exception for instances where there are multiple packages with same name


class PackageNotFoundException(Exception):
    pass


class ClibPackage(object):
    pass


def build(ctx):
    ctx.clib_index()


def unionsets_if_list(func):
    def func_wrapper(self, package, **kwargs):
        if isinstance(package, list):
            s = set()
            for p in package:
                s.update(func(self, p, **kwargs))
            return list(s)
        else:
            return func(self, package, **kwargs)
    return func_wrapper


@unionsets_if_list
def _clib_h_files(self, package, include_deps=True):
    files = filter(lambda x: x.endswith(".h"), self.clib_manifest(package)['src'])
    files = map(lambda x: '{0}{1}'.format(self.clib_path(package), os.path.basename(x)), files)
    if include_deps:
        deps = self.clib_dependencies(package)
        files.extend(itertools.chain.from_iterable([self.clib_h_files(pkg) for pkg in deps]))
    return list(set(files))


@unionsets_if_list
def _clib_c_files(self, package, include_deps=True):
    files = filter(lambda x: x.endswith(".c"), self.clib_manifest(package)['src'])
    files = map(lambda x: '{0}{1}'.format(self.clib_path(package), os.path.basename(x)), files)
    if include_deps:
        deps = self.clib_dependencies(package)
        files.extend(itertools.chain.from_iterable([self.clib_c_files(pkg) for pkg in deps]))
    return list(set(files))


@conf
def clib_h_files(self, package, include_deps=True):
    """ Return all header files from package

        Parameters
        ----------
        package : string or list of strings
            The package (repo or name) to get header files from.
            This can be a list of packages. 
        include_deps: boolean
            Whether or not to include package depedencies
    """
    return _clib_h_files(self, package, include_deps=include_deps)


@conf
def clib_c_files(self, package, include_deps=True):
    """ Return all c files from package

        Parameters
        ----------
        package : string or list of strings
            The package (repo or name) to get c files from.
            This can be a list of packages. 
        include_deps: boolean
            Whether or not to include package depedencies
    """
    return _clib_c_files(self, package, include_deps=include_deps)


@unionsets_if_list
def _clib_h_paths(self, package, include_deps=True):
    paths = set([self.clib_path(package)])
    if include_deps:
        deps = self.clib_dependencies(package)
        paths.update(itertools.chain.from_iterable([self.clib_paths(pkg) for pkg in deps]))
    return paths


@conf
def clib_h_paths(self, package, include_deps=True):
    """ Return all paths that contain h files from package

        Parameters
        ----------
        package : string or list of strings
            The package (repo or name) to get h paths from.
            This can be a list of packages. 
        include_deps: boolean
            Whether or not to include package depedencies
    """
    return list(set([h[:h.rfind('/')]
                     for h in self.clib_h_files(package, include_deps=include_deps)]))


@conf
def clib_path(self, package):
    """ Return package path

        Parameters
        ----------
        package : string
            The package (repo or name) to get the path from.
    """
    #return '{0}/{1}/'.format(os.getcwd(), self.clib_get(package).path)
    return '{0}/'.format(self.clib_get(package).path)


@conf
def clib_index(self):
    """ Read package.json files inside deps folder """
    self.packages_by_name = {}
    self.packages_by_repo = {}
    for dirname, dirnames, filenames in os.walk('deps/'):
        if 'package.json' in filenames:
            pkg = ClibPackage()
            pkg.path = dirname
            json_data = open("{0}/package.json".format(pkg.path))
            pkg.manifest = json.load(json_data)
            json_data.close()
            self.packages_by_repo[pkg.manifest['repo']] = pkg
            self.packages_by_name[pkg.manifest['name']] = pkg


@conf
def clib_manifest(self, package):
    """ Return the dictionary contents of package.json file

        Parameters
        ----------
        package : string
            The package (repo or name) to get the manifset from.
    """
    return self.clib_get(package).manifest


@conf
def clib_dependencies(self, package):
    """ Return a package's dependecies (repo name)

        Parameters
        ----------
        package : string
            The package (repo or name) to get the depedencies from.
    """

    deps = set()
    for dep in self.clib_manifest(package).get('dependencies', {}).iterkeys():
        deps.add(dep)
        for d in self.clib_dependencies(dep):
            deps.add(d)
    return deps


@conf
def clib_get(self, package):
    """ Return package object """
    if package in self.packages_by_name:
        return self.packages_by_name[package]
    elif package in self.packages_by_repo:
        return self.packages_by_repo[package]
    raise PackageNotFoundException(package)


