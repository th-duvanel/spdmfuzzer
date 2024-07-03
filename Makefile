CC = g++
CPPFLAGS = -g -Wall

OBJDIR = src
HEDDIR = include
DEPS = $(OBJDIR)/utils.o $(OBJDIR)/socket.o $(OBJDIR)/grammar.o $(OBJDIR)/fuzzing.o $(OBJDIR)/mocks.o

all: $(OBJDIR)/spdmfuzzer.cpp $(DEPS)
	$(CC) $(CPPFLAGS) -o spdmfuzzer $(OBJDIR)/spdmfuzzer.cpp $(DEPS)

$(OBJDIR)/utils.o: $(OBJDIR)/utils.cpp $(HEDDIR)/utils.hpp
	$(CC) $(CPPFLAGS) -c $(OBJDIR)/utils.cpp -o $(OBJDIR)/utils.o

$(OBJDIR)/mocks.o: $(OBJDIR)/mocks.cpp $(HEDDIR)/mocks.hpp
	$(CC) $(CPPFLAGS) -c $(OBJDIR)/mocks.cpp -o $(OBJDIR)/mocks.o
	
$(OBJDIR)/grammar.o: $(OBJDIR)/grammar.cpp $(HEDDIR)/grammar.hpp
	$(CC) $(CPPFLAGS) -c $(OBJDIR)/grammar.cpp -o $(OBJDIR)/grammar.o

$(OBJDIR)/socket.o: $(OBJDIR)/utils.o $(OBJDIR)/socket.cpp $(HEDDIR)/socket.hpp
	$(CC) $(CPPFLAGS) -c $(OBJDIR)/socket.cpp -o $(OBJDIR)/socket.o
    
$(OBJDIR)/fuzzing.o: $(OBJDIR)/utils.o $(OBJDIR)/grammar.o $(OBJDIR)/socket.o $(OBJDIR)/fuzzing.cpp $(HEDDIR)/fuzzing.hpp
	$(CC) $(CPPFLAGS) -c $(OBJDIR)/fuzzing.cpp -o $(OBJDIR)/fuzzing.o

clean:
	rm -f $(OBJDIR)/*.o spdmfuzzer