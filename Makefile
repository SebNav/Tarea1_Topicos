CXX      ?= g++
CXXFLAGS ?= -O2 -march=native -std=c++17 -Wall -Wextra -Wno-implicit-fallthrough

.PHONY: all clean
all: bin/codigo

bin/codigo: codigos/Codigo.cpp codigos/MurmurHash3.cpp codigos/MurmurHash3.h
	@mkdir -p bin
	$(CXX) $(CXXFLAGS) -o $@ codigos/Codigo.cpp codigos/MurmurHash3.cpp

clean:
	rm -f bin/codigo
