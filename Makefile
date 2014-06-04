all:
	 gcc -fPIC -c sha512iv.c 
#   Link sha512iv for test purposes
#	 gcc -lssl -lcrypto -o sha512iv sha512iv.o
	 gcc -lssl -lcrypto -shared -o sha512iv.so sha512iv.o 

clean:
	rm sha512iv.o sha512iv.so sha512iv
