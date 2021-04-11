# Welcome to Stan's branch

### Build
The following steps are performed from the repository root directory.

1. Adjust Makefile's `CPPFLAGS` and `LDFLAGS` in case includes and libs of openssl and gmp are not in 
global lookup directories (such as `/usr/local/include`).
```makefile
CPPFLAGS := $(CPPFLAGS) $(COMMON) -I/usr/local/Cellar/openssl@1.1/1.1.1k/include
LDFLAGS  := -L/usr/local/Cellar/openssl@1.1/1.1.1k/lib
```

2. Run make.
```shell
make
```

### Test
1. Run all tests.
```shell
./test.sh
```

2. Inspect output.
```shell
cat output
```

### Woop Woop Woop
![Zoidberg](bad-code.jpg)