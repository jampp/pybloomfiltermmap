VERSION = (0, 4, 0)
AUTHOR = "Michael Axiak"

__VERSION__ = VERSION


cimport cbloomfilter
cimport cpython
from cbloomfilter cimport uint32_t, uint64_t, BTYPE

import random
import os
import math
import errno as eno
import array
import zlib
import shutil
import sys
import operator

from base64 import b64encode, b64decode

cdef extern int errno

cdef construct_mode(mode):
    result = os.O_RDONLY
    if 'w' in mode:
        result |= os.O_RDWR
    if 'b' in mode and hasattr(os, 'O_BINARY'):
        result |= os.O_BINARY
    if mode.endswith('+'):
        result |= os.O_CREAT
    return result

cdef construct_access(mode):
    result = os.F_OK
    if 'w' in mode:
        result |= os.W_OK
    if 'r' in mode:
        result |= os.R_OK
    return result

cdef NoConstruct = object()
cdef ReadFile = object()

def bf_from_base64(filename, string, perm=0755):
    bfile = open(filename, 'w+', perm)
    bfile.write(zlib.decompress(zlib.decompress(string.decode('base64')).decode('base64')))
    bfile.close()
    return BloomFilter.open(filename)

def bf_from_file(filename, mode='r'):
    return BloomFilter(ReadFile, 0.1, filename, mode, 0)

class IndeterminateCountError(ValueError):
    pass

cdef class BloomFilter:
    """
    The BloomFilter class implements a bloom filter that uses mmap'd files.
    For more information on what a bloom filter is, please read the Wikipedia article about it.
    """
    cdef cbloomfilter.BloomFilter * _bf
    cdef int _closed
    cdef int _in_memory
    cdef int _writable
    cdef public ReadFile

    def __cinit__(
            self,
            capacity,
            double error_rate,
            filename=None,
            mode='rw+',
            int perm=0755,
            seed=None,
            unsigned char version=cbloomfilter.BF_CURRENT_VERSION,
    ):

        """
        mode: chmod type access to file, default rw+ for creating the bloom filter
        perm, permissions for when the file is created, not opened. 0755 means Read, Write, Execute access for owner,
        read, execute for group owner and others.
        seed: If set, seed to use to generate the hash_seeds.
        bf_version: Version to use when creating a new BloomFilter.
        """
        cdef char * seeds
        cdef BTYPE num_bits
        cdef int oflags
        cdef uint64_t _capacity
        self._closed = 0
        self._in_memory = 0
        self._writable = 1
        self.ReadFile = self.__class__.ReadFile

        if filename is NoConstruct:
            return

        if not 1 <= version <= cbloomfilter.BF_CURRENT_VERSION:
            raise ValueError("Invalid %s version" % self.__class__.__name__)

        if capacity is self.ReadFile:
            # Cannot create if we read
            mode = mode.replace('+','')

            _capacity = 0
            if not os.path.exists(filename):
                raise OSError("File %s not found" % filename)

            if not os.access(filename, construct_access(mode)):
                raise OSError("Insufficient permissions for file %s mode %r" % (filename, mode))
        else:
            _capacity = capacity

        oflags = construct_mode(mode)

        if not oflags & os.O_CREAT: #if the file is already created
            if os.path.exists(filename):
                filename_ = filename if isinstance(filename, bytes) else filename.encode()
                self._bf = cbloomfilter.bloomfilter_Create_Mmap(_capacity,
                                                           error_rate,
                                                           filename_,
                                                           0,
                                                           oflags,
                                                           perm,
                                                           NULL, 0,
                                                           version)
                if self._bf is NULL:
                    raise ValueError("Invalid %s file: %s" % (self.__class__.__name__, filename))
                elif self._bf.bf_version > cbloomfilter.BF_CURRENT_VERSION:
                        version = self._bf.bf_version
                        self.close()
                        raise ValueError(
                            "%s version %d is not supported by this version of the library." % (
                                self.__class__.__name__, version
                            )
                        )
            else:
                raise OSError(eno.ENOENT, '%s: %s' % (os.strerror(eno.ENOENT),
                                                      filename))
        else:
            # Make sure that if the filename is defined, that the
            # file exists
            if filename and os.path.exists(filename):
                os.unlink(filename)

            # For why we round down for determining the number of hashes:
            # http://corte.si/%2Fposts/code/bloom-filter-rules-of-thumb/index.html
            # "The number of hashes determines the number of bits that need to
            # be read to test for membership, the number of bits that need to be
            # written to add an element, and the amount of computation needed to
            # calculate hashes themselves. We may sometimes choose to use a less
            # than optimal number of hashes for performance reasons (especially
            # when we choose to round down when the calculated optimal number of
            # hashes is fractional)."

            assert(error_rate > 0.0 and error_rate < 1.0), "error_rate allowable range (0.0,1.0) %f" % (error_rate,)
            num_hashes = max(int(math.floor(math.log(1.0 / error_rate, 2.0))),1)
            bits_per_hash = int(math.ceil(
                    _capacity * abs(math.log(error_rate)) /
                    (num_hashes * (math.log(2) ** 2))))

            # mininum bitvector of 128 bits
            num_bits = max(num_hashes * bits_per_hash,128)

            #print "k = %d  m = %d  n = %d   p ~= %.8f" % (
            #    num_hashes, num_bits, capacity,
            #    (1.0 - math.exp(- float(num_hashes) * float(capacity) / num_bits))
            #    ** num_hashes)

            rand = random.Random()
            if seed is not None:
                rand.seed(seed)
            hash_seeds = array.array('I')
            hash_seeds.extend([rand.getrandbits(32) for i in range(num_hashes)])
            test = _array_tobytes(hash_seeds)
            seeds = test

            # If a filename is provided, we should make a mmap-file
            # backed bloom filter. Otherwise, it will be malloc
            if filename:
                self._bf = cbloomfilter.bloomfilter_Create_Mmap(_capacity,
                                                       error_rate,
                                                       filename.encode(),
                                                       num_bits,
                                                       oflags,
                                                       perm,
                                                       <uint32_t *>seeds,
                                                       num_hashes,
                                                       version)
            else:
                self._in_memory = 1
                self._bf = cbloomfilter.bloomfilter_Create_Malloc(_capacity,
                                                       error_rate,
                                                       num_bits,
                                                       <uint32_t *>seeds,
                                                       num_hashes,
                                                       version)
            if self._bf is NULL:
                if filename:
                    raise OSError(errno, '%s: %s' % (os.strerror(errno),
                                                     filename))
                else:
                    cpython.PyErr_NoMemory()

        self._writable = self._in_memory or 'w' in mode

    def __dealloc__(self):
        cbloomfilter.bloomfilter_Destroy(self._bf)
        self._bf = NULL

    property hash_seeds:
        def __get__(self):
            self._assert_open()
            result = array.array('I')
            _array_frombytes(
                result,
                (<char *>self._bf.hash_seeds)[:4 * self.num_hashes]
            )
            return result

    property hash_func:
        def __get__(self):
            self._assert_open()
            if self.version >= 2 and self.num_bits >= cbloomfilter.HASH64_THRESHOLD:
                return "xxhash64"
            return "xxhash32"

    property capacity:
        def __get__(self):
            self._assert_open()
            return self._bf.max_num_elem

    property error_rate:
        def __get__(self):
            self._assert_open()
            return self._bf.error_rate

    property num_hashes:
        def __get__(self):
            self._assert_open()
            return self._bf.num_hashes

    property num_bits:
        def __get__(self):
            self._assert_open()
            return self._bf.array.bits

    property version:
        def __get__(self):
            self._assert_open()
            return self._bf.bf_version

    property name:
        def __get__(self):
            self._assert_open()
            if self._bf.array.filename is not NULL:
                return self._bf.array.filename
            else:
                return None

    def fileno(self):
        self._assert_open()
        return self._bf.array.fd

    def __repr__(self):
        self._assert_open()
        my_name = self.__class__.__name__
        return '<%s version: %d, capacity: %d, error: %0.3f, num_hashes: %d>' % (
            my_name, self._bf.bf_version, self._bf.max_num_elem, self._bf.error_rate,
            self._bf.num_hashes)

    def __str__(self):
        return self.__repr__()

    def sync(self):
        self._assert_open()
        return cbloomfilter.mbarray_Sync(self._bf.array)

    def clear_all(self):
        self._assert_open()
        self._assert_writable()
        cbloomfilter.mbarray_ClearAll(self._bf.array)

    def __contains__(self, item):
        self._assert_open()
        cdef cbloomfilter.Key key
        if isinstance(item, bytes):
            key.shash = item
            key.nhash = len(item)
        elif isinstance(item, unicode):
            item = item.encode("utf8")
            key.shash = item
            key.nhash = len(item)
        else:
            key.shash = NULL
            key.nhash = hash(item)
        return cbloomfilter.bloomfilter_Test(self._bf, &key) == 1

    def copy_template(self, filename, mode='rw+', perm=0755):
        self._assert_open()
        cdef BloomFilter copy = BloomFilter(0, 0, NoConstruct)

        if filename:
            oflags = construct_mode(mode)
            if oflags & os.O_CREAT and os.path.exists(filename):
                os.unlink(filename)
            copy._bf = cbloomfilter.bloomfilter_Create_Mmap(self._bf.max_num_elem,
                                                            self._bf.error_rate,
                                                            filename.encode(),
                                                            self._bf.array.bits,
                                                            oflags,
                                                            perm,
                                                            self._bf.hash_seeds,
                                                            self._bf.num_hashes,
                                                            self._bf.bf_version)
        else:
            copy._in_memory = 1
            copy._bf = cbloomfilter.bloomfilter_Create_Malloc(self._bf.max_num_elem,
                                                              self._bf.error_rate,
                                                              self._bf.array.bits,
                                                              self._bf.hash_seeds,
                                                              self._bf.num_hashes,
                                                              self._bf.bf_version)

        return copy

    def copy(self, filename):
        self._assert_open()
        if not self._in_memory and filename:
            # mmap to mmap. Just copy file and open it
            shutil.copy(self._bf.array.filename, filename)
            return self.__class__(self.ReadFile, 0.1, filename, perm=0)

        copy = self.copy_template(filename)
        copy |= self
        return copy

    cdef _add(self, item):
        cdef cbloomfilter.Key key
        if isinstance(item, bytes):
            key.shash = item
            key.nhash = len(item)
        elif isinstance(item, unicode):
            item = item.encode("utf8")
            key.shash = item
            key.nhash = len(item)
        else:
            key.shash = NULL
            key.nhash = hash(item)

        result = cbloomfilter.bloomfilter_Add(self._bf, &key)
        if result == 2:
            raise RuntimeError("Some problem occured while trying to add key.")
        return bool(result)

    def add(self, item):
        self._assert_open()
        self._assert_writable()
        return self._add(item)

    def update(self, iterable):
        self._assert_open()
        self._assert_writable()
        for item in iterable:
            self._add(item)

    def __len__(self):
        self._assert_open()
        if not self._bf.count_correct:
            raise IndeterminateCountError("Length of %s object is unavailable "
                                          "after intersection or union called." %
                                          self.__class__.__name__)
        return self._bf.elem_count

    def close(self):
        if self._closed == 0:
            self._closed = 1
            cbloomfilter.bloomfilter_Destroy(self._bf)
            self._bf = NULL

    def __ior__(self, BloomFilter other):
        self._assert_open()
        self._assert_writable()
        self._assert_comparable(other)
        cbloomfilter.mbarray_Or(self._bf.array, other._bf.array)
        self._bf.count_correct = 0
        return self

    def union(self, BloomFilter other):
        self._assert_open()
        self._assert_writable()
        other._assert_open()
        self._assert_comparable(other)
        cbloomfilter.mbarray_Or(self._bf.array, other._bf.array)
        self._bf.count_correct = 0
        return self

    def __iand__(self, BloomFilter other):
        self._assert_open()
        self._assert_writable()
        other._assert_open()
        self._assert_comparable(other)
        cbloomfilter.mbarray_And(self._bf.array, other._bf.array)
        self._bf.count_correct = 0
        return self

    def intersection(self, BloomFilter other):
        self._assert_open()
        self._assert_writable()
        other._assert_open()
        self._assert_comparable(other)
        cbloomfilter.mbarray_And(self._bf.array, other._bf.array)
        self._bf.count_correct = 0
        return self

    def _assert_open(self):
        if self._closed != 0:
            raise ValueError("I/O operation on closed file")

    def _assert_writable(self):
        if self._writable == 0:
            raise ValueError("Write operation on not writable file")

    def _assert_comparable(self, BloomFilter other):
        error = ValueError("The two %s objects are not the same type (hint, "
                           "use copy_template)" % self.__class__.__name__)
        for prop in ('version', 'capacity', 'error_rate', 'num_hashes', 'num_bits', 'hash_seeds'):
            if getattr(self, prop) != getattr(other, prop):
                raise error
        return

    def to_base64(self):
        self._assert_open()
        bfile = open(self.name, 'rb')
        result = b64encode(zlib.compress(b64encode(zlib.compress(bfile.read(), 9))))
        bfile.close()
        return result

    @classmethod
    def from_base64(cls, filename, string, perm=0755):
        bfile_fp = os.open(filename, construct_mode('w+'), perm)
        os.write(bfile_fp, zlib.decompress(b64decode(
            zlib.decompress(b64decode(string)))))
        os.close(bfile_fp)
        return cls.open(filename)

    @classmethod
    def open(cls, filename, mode='r'):
        return cls(cls.ReadFile, 0.1, filename, mode, 0)


if sys.version_info >= (3, 2):
    _array_tobytes = operator.methodcaller('tobytes')
    def _array_frombytes(ar, s):
        return ar.frombytes(s)
else:
    _array_tobytes = operator.methodcaller('tostring')
    def _array_frombytes(ar, s):
        return ar.fromstring(s)
