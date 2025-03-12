#include "../observer.hpp"
#include "../generation/mocks.hpp"
#include "../generation/packet_factory.hpp"

class FuzzStrategy {
protected:
    Observer *Logger;
    PacketFactory *Factory;

    bool certifiedSent;

public: 
    FuzzStrategy(Observer *Logger);

    virtual ~FuzzStrategy() = default;

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) = 0;

    bool CheckRequest(MessageSPDM *request, MessageSPDM *response);    
};

class MockedStrategy : public FuzzStrategy {
public:
    MockedStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class RandomStrategy : public FuzzStrategy {
public:
    RandomStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class GrammaticalStrategy : public FuzzStrategy {
public:
    GrammaticalStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class SizedStrategy : public FuzzStrategy {
public:
    SizedStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class BacktrackStrategy : public FuzzStrategy {
private:
    std::vector<MessageSPDM> StoredResponses;

public:
    BacktrackStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class CheckpointStrategy : public FuzzStrategy {
private:
    int8_t Checkpoint;
    int8_t CurrentCheckpoint;

public:
    CheckpointStrategy(Observer *Logger, u8 Checkpoint);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};