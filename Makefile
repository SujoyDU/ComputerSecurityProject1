SOURCES := $(wildcard *.c)
OBJECTS := $(SOURCES:.c=.o)
HEADERS := $(wildcard *.h)
TARGETS := kem-enc
TSOURCE := $(wildcard tests/*.cpp)
TESTS   := $(TSOURCE:.cpp=)

COMMON   := -O2 -Wall -std=c++14 
CFLAGS   := $(CFLAGS) $(COMMON) 
CPPFLAGS := $(CPPFLAGS) $(COMMON) -I/usr/local/Cellar/openssl@1.1/1.1.1k/include
CC       := gcc 
LDADD    := -lstdc++ -lgmp -lgmpxx -lcrypto -lssl
LD       := $(CC)
LDFLAGS  := -L/usr/local/Cellar/openssl@1.1/1.1.1k/lib
DEFS     :=
ifeq ($(shell uname),Linux)
DEFS += -DLINUX
endif

IMPL := ske.o rsa.o kem-enc.o
ifdef skel
IMPL := $(IMPL:.o=-skel.o)
endif

all : $(TARGETS) tests
.PHONY : all

# {{{ for debugging
debug : CFLAGS += -g -DDEBUG=1
debug : $(TARGETS) $(TESTS)
.PHONY : debug
# }}}

$(OBJECTS) : %.o : %.cpp $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@ 

$(TARGETS) : $(IMPL) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

tests : $(TESTS)
.PHONY : tests

$(TESTS) : % : %.o $(filter-out kem-enc.o,$(IMPL)) prf.o
	$(LD) $(LDFLAGS) -o $@ $^ $(LDADD)

.PHONY : clean
clean :
	rm -f $(OBJECTS) $(TARGETS) $(TESTS) $(TSOURCE:.cpp=.o)
