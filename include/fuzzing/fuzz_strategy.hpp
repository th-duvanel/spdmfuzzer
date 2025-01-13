#include "../utils.hpp"
#include "../generation/mocks.hpp"

class FuzzStrategy {
public: 
    virtual ~FuzzStrategy() = default;

    virtual MessageSPDM InterpretRequest(MessageSPDM &request) = 0;
};

class MockedStrategy : public FuzzStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};

class RandomStrategy : public FuzzStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};

class GrammaticalStrategy : public FuzzStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};

class LinearStrategy : public GrammaticalStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};

class BacktrackStrategy : public GrammaticalStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};

class CheckpointStrategy : public GrammaticalStrategy {
public:
    virtual MessageSPDM InterpretRequest(MessageSPDM &request) override;
};