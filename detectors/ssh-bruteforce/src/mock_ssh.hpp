//detectors/ssh-bruteforce/src/mock_ssh.hpp
#pragma once
#include <nlohmann/json.hpp>
#include <vector>
#include <random>

using json = nlohmann::json;

class MockSSH {
public:
    static std::vector<json> generate_events(int count = 15) {
        std::vector<json> events;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> ip_octet(1, 255);
        std::uniform_int_distribution<> rule_id(5710, 5719);

        for (int i = 0; i < count; ++i) {
            std::string ip = std::to_string(ip_octet(gen)) + "." +
                           std::to_string(ip_octet(gen)) + "." +
                           std::to_string(ip_octet(gen)) + "." +
                           std::to_string(ip_octet(gen));

            events.push_back({
                {"rule", {
                    {"id", rule_id(gen)},
                    {"description", "Failed SSH login"}
                }},
                {"data", {
                    {"srcip", ip},
                    {"srcuser", (i % 3 == 0) ? "root" : "admin"},
                    {"description", "Failed password attempt"}
                }}
            });
        }
        return events;
    }
};