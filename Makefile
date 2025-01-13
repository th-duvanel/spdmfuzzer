CC = g++
CPPFLAGS = -g -Wall

OBJDIR = src
HEDDIR = include
BUILDDIR = build

DEPS =  $(BUILDDIR)/utils.o $(BUILDDIR)/io.o $(BUILDDIR)/observer.o $(BUILDDIR)/packet.o $(BUILDDIR)/fuzzer.o $(BUILDDIR)/mocks.o $(BUILDDIR)/packet_factory.o $(BUILDDIR)/fuzz_strategy.o

all: $(OBJDIR)/spdmfuzzer.cpp $(DEPS)
	$(CC) $(CPPFLAGS) -o spdmfuzzer $(OBJDIR)/spdmfuzzer.cpp $(DEPS)

$(BUILDDIR)/%.o: $(OBJDIR)/%.cpp $(HEDDIR)/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $< 

$(BUILDDIR)/%.o: $(OBJDIR)/fuzzing/%.cpp $(HEDDIR)/fuzzing/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: $(OBJDIR)/generation/%.cpp $(HEDDIR)/generation/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f $(BUILDDIR)/*.o spdmfuzzer
