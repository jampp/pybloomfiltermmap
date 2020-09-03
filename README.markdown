# pybloomfiltermmap [![Build Status](https://secure.travis-ci.org/axiak/pybloomfiltermmap.png?branch=master)](http://travis-ci.org/axiak/pybloomfiltermmap)

The goal of `pybloomfiltermmap` is simple: to provide a fast, simple, scalable,
correct library for Bloom Filters in Python.

## Docs

See <http://axiak.github.com/pybloomfiltermmap/>.

## Overview

After you install, the interface to use is a cross between a file
interface and a ste interface. As an example:

    >>> fruit = pybloomfilter.BloomFilter(100000, 0.1, '/tmp/words.bloom')
    >>> fruit.update(('apple', 'pear', 'orange', 'apple'))
    >>> len(fruit)
    3
    >>> 'mike' in fruit
    False
    >>> 'apple' in fruit
    True

## Install

You may or may not want to use Cython. If you have it installed, the
setup file will build the C file from the pyx file. Otherwise, it will
skip that step automatically and build from the packaged C file.

To install:

   $ sudo python setup.py install

and you should be set.

### Troubleshooting

Mac users may face problems when installing the package, it happens because on the build, the compiler tries to import a module that is provided by OpenSSL, and most of the cases it fails because it can't find the module.
What to do in these cases:
 - Make sure openssl is installed `brew install openssl`
 - Set an environment variable that tells the path to the openssl installed `export CFLAGS="-L/usr/local/opt/openssl/lib -I/usr/local/opt/openssl/include"`
 - You may need extra flags to the compiler, check with `brew info openssl`

## License

See the LICENSE file. It's under the MIT License.
