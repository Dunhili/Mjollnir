Author: Brian Bowden <bbowden1@vt.edu>

- This program uses its own implementation of all hashing algorithms and also implements a hash
  cracking implementation to try to find the original passwords used for each hash.
- Cryptographic Hashing Algorithms currently supported:
  - MD5 (for hashing only)

- Notes: The libcu library is used for its hash table implementation and any and all credit goes to the
  author(s) for their implementation. 

- To Do:
  - Finish MD5 hash cracking
    * pthreads
    * CUDA
    * MPI
    * MPI + pthreads
    * MPI + CUDA
  - SHA0
  - SHA1
  - SHA2
  - SHA3?
  - MD4
  - Tiger
  - Whirlpool
