CC = g++
CPPFLAGS = -g -Wall

OBJDIR = src
HEDDIR = include
BUILDDIR = build

DEPS =  $(BUILDDIR)/io.o $(BUILDDIR)/observer.o $(BUILDDIR)/utils.o $(BUILDDIR)/packet.o $(BUILDDIR)/fuzzer.o $(BUILDDIR)/mocks.o $(BUILDDIR)/packet_factory.o $(BUILDDIR)/fuzz_strategy.o

all: $(BUILDDIR) $(OBJDIR)/spdmfuzzer.cpp $(DEPS)
	$(CC) $(CPPFLAGS) -o spdmfuzzer $(OBJDIR)/spdmfuzzer.cpp $(DEPS)

$(BUILDDIR)/%.o: $(OBJDIR)/%.cpp $(HEDDIR)/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $< 

$(BUILDDIR)/%.o: $(OBJDIR)/fuzzing/%.cpp $(HEDDIR)/fuzzing/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $<

$(BUILDDIR)/%.o: $(OBJDIR)/generation/%.cpp $(HEDDIR)/generation/%.hpp
	$(CC) $(CPPFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

clean:
	rm -f $(BUILDDIR)/*.o spdmfuzzer
