#pragma once

#include "utils.hpp"

class Observer {
public:
    virtual void onResponse(u8 code, MessageSPDM &Message) = 0;
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

    void onResponse(u8 code, MessageSPDM &Message) override;
    void onEvent(const std::string &type, const std::string &Message) override;
    void ShowStart() override;
    void ShowEnd() override;
};