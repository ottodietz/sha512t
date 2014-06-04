sha512t
=======
Implementation of truncated SHA-512/t hash function (as defined in FIPS-180)

run

$ make

to create shared lib sha512iv.so 

sha512t.py contains the python wrapper for the C functions and the initial
vector generator for hash length t=0..511 bit.

License
=======

C code is derived from openSSL and thus covered by the openSSL Licence. See LICENSE-sha512iv.c.txt for more details.

Python code published under GPLv2. See LICENSE-sha512t.py.txt for more details
