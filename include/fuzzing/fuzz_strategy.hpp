#include "../utils.hpp"
#include "../observer.hpp"
#include "../generation/mocks.hpp"

class FuzzStrategy {
protected:
    Observer *Logger;

public: 
    FuzzStrategy(Observer *Logger);

    virtual ~FuzzStrategy() = default;

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) = 0;
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

class LinearStrategy : public GrammaticalStrategy {
public:
    LinearStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class BacktrackStrategy : public GrammaticalStrategy {
public:
    BacktrackStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};

class CheckpointStrategy : public GrammaticalStrategy {
public:
    CheckpointStrategy(Observer *Logger);

    virtual bool InterpretRequest(MessageSPDM *request, MessageSPDM *response) override;
};