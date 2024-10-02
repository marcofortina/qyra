# Define the compiler and compilation flags
CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -I../src/include

# Define the libraries and their paths
LIBS = -loqs -lssl -lcrypto -lqyra
LDFLAGS = -L../src/.libs $(LIBS)

# Define the runtime library path
RPATH = -Wl,-rpath=$(shell realpath ../src/.libs)

# Define the source files and target executables
SRC_FILES = example1.cpp example2.cpp
TARGETS = example1 example2

# Define debug flags
DEBUG_FLAGS = -O0 -g

# The default target
all: $(TARGETS)

# Rule to build each target executables with debug flags
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGETS)

# Rule to build each target executables
example1: example1.cpp
	$(CXX) $(CXXFLAGS) example1.cpp $(RPATH) $(LDFLAGS) -o example1

example2: example2.cpp
	$(CXX) $(CXXFLAGS) example2.cpp $(RPATH) $(LDFLAGS) -o example2

# Clean rule to remove the executables and any other generated files
clean:
	rm -f $(TARGETS)