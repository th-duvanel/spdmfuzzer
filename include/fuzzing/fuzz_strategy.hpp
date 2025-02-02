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

class SizedStrategy : public GrammaticalStrategy {
public:
    SizedStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class BacktrackStrategy : public GrammaticalStrategy {
private:
    std::vector<MessageSPDM> StoredResponses;

public:
    BacktrackStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class CheckpointStrategy : public GrammaticalStrategy {
private:
    u8 Checkpoint;
    u8 CurrentCheckpoint;

public:
    CheckpointStrategy(Observer *Logger, u8 Checkpoint);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};