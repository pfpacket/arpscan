CXX         = g++
CXXFLAGS    = -Wall -Wextra -std=c++17 -pedantic -O2
LDFLAGS     = -pthread
INCLUDES    =
LIBS        =
TARGET      = arpscan
OBJS        = arpscan.o

all:  $(TARGET)
rebuild:  clean all

run: $(TARGET)
	@./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJS)

$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

.cpp.o:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

