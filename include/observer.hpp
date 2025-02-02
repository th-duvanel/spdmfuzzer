#pragma once

#include "utils.hpp"

inline std::map<std::string, u8> RequestResponseCode;

class Observer {
public:
    virtual void onResponse(MessageSPDM &Message, u8 fuzzStrategy) = 0;
    virtual void onEvent(const std::string &type, const std::string &Message) = 0;
    virtual void ShowStart() = 0;
    virtual void ShowEnd() = 0;

    virtual ~Observer() = default;
};

class ConsoleLogger : public Observer {
private:
    bool verbose;
public:
    ConsoleLogger(bool verbose);

    void onResponse(MessageSPDM &Message, u8 fuzzStrategy) override;
    void onEvent(const std::string &type, const std::string &Message) override;
    void ShowStart() override;
    void ShowEnd() override;
};