cdef extern from "mmapbitarray.h":
     ctypedef unsigned long long BTYPE

     ctypedef struct MBArray:
         BTYPE bits
         size_t size
         char * filename
         int fd

     MBArray * mbarray_ClearAll(MBArray * array)
     int mbarray_Sync(MBArray * array)
     MBArray * mbarray_And(MBArray * dest, MBArray * src)
     MBArray * mbarray_Or(MBArray * dest, MBArray * src)


cdef extern from "bloomfilter.h":
     ctypedef unsigned long uint32_t
     ctypedef unsigned long long uint64_t

     cdef enum:
         BF_CURRENT_VERSION
         HASH64_THRESHOLD

     ctypedef struct BloomFilter:
         uint64_t max_num_elem
         double error_rate
         uint32_t num_hashes
         uint32_t * hash_seeds
         MBArray * array
         unsigned char bf_version
         unsigned char count_correct
         uint64_t elem_count

     ctypedef struct Key:
         long nhash
         char * shash

     BloomFilter * bloomfilter_Create_Mmap(uint64_t max_num_elem,
                                      double error_rate,
                                      char * fname, BTYPE num_bits,
                                      int oflags, int perms,
                                      uint32_t * hash_seeds, uint32_t num_hashes,
                                      unsigned char bf_version)
     BloomFilter * bloomfilter_Create_Malloc(uint64_t max_num_elem,
                                      double error_rate,
                                      BTYPE num_bits,
                                      uint32_t * hash_seeds, uint32_t num_hashes,
                                      unsigned char bf_version)
     void bloomfilter_Destroy(BloomFilter * bf)
     int bloomfilter_Add(BloomFilter * bf, Key * key)
     int bloomfilter_Test(BloomFilter * bf, Key * key)
