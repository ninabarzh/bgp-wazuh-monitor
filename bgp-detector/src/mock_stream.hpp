#pragma once
#include <vector>
#include <string>
#include <nlohmann/json.hpp>
#include <random>

using json = nlohmann::json;

class MockBGPStream {
public:
    static std::vector<json> generate_events(int count = 3) {
        std::vector<json> events;
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> asn_dist(1000, 9999);
        std::uniform_int_distribution<> prefix_dist(1, 254);

        for (int i = 0; i < count; ++i) {
            std::string hijacker_asn = "AS" + std::to_string(asn_dist(gen));
            std::string victim_asn = "AS" + std::to_string(asn_dist(gen));
            std::string prefix = std::to_string(prefix_dist(gen)) + "." +
                               std::to_string(prefix_dist(gen)) + ".0.0/16";

            events.push_back({
                {"type", "HIJACK"},
                {"hijacker_asn", hijacker_asn},
                {"victim_prefix", prefix},
                {"victim_asn", victim_asn},
                {"start_time", "2024-01-01T00:00:00Z"},
                {"duration_min", 5 + i}
            });
        }
        return events;
    }
};