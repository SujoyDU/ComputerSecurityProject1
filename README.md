# Welcome to Stan's branch

So far I got RSA working with my own random number generator. Don't judge for the mix of c and c++..  

RSA test builds with
```shell
# Beware of your paths
gcc rsa-test.cpp ../rsa.cpp ../prf.cpp -O2 -Wall -std=c++14 -lstdc++ -lgmp -lgmpxx -lcrypto -lssl -I/usr/local/Cellar/openssl@1.1/1.1.1j/include -L/usr/local/Cellar/openssl@1.1/1.1.1j/lib
```

Yes, I am going to adjust the Makefile at some point..

`randomprime.h` defines 2 functions -- one gets you a random prime number specified bit length; the other finds a random coprime, used for finding `e` in RSA key generation.

![Zoidberg](/.bad-code.jpg)