// detectors/bgp-hijack/src/detector.cpp
#include <iostream>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <cstdlib>
#include "mock_stream.hpp"
#include "../shared/wazuh_client.hpp"

using json = nlohmann::json;

const int CHECK_INTERVAL = 300; // 5 minutes

class BgpAnalyzer {
public:
    BgpAnalyzer(bool use_mock) : use_mock_(use_mock) {}

    void run() {
        while (true) {
            auto events = fetch_bgp_events();
            analyze_events(events);
            std::this_thread::sleep_for(std::chrono::seconds(CHECK_INTERVAL));
        }
    }

private:
    struct BgpEvent {
        std::string hijacker_asn;
        std::string victim_prefix;
        std::string start_time;
    };

    bool use_mock_;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> last_alert_;

    std::vector<BgpEvent> fetch_bgp_events() {
        if (use_mock_) {
            return MockBGPStream::generate_events();
        } else {
            // Production implementation would call BGPStream API
            return {};
        }
    }

    void analyze_events(const std::vector<BgpEvent>& events) {
        for (const auto& event : events) {
            if (should_alert(event.hijacker_asn)) {
                json alert = {
                    {"timestamp", std::time(nullptr)},
                    {"rule", {
                        {"id", 900100},
                        {"description", "BGP Hijack Detected"},
                        {"level", 12},
                        {"mitre", {"T1574"}}
                    }},
                    {"bgp", {
                        {"hijacker_asn", event.hijacker_asn},
                        {"victim_prefix", event.victim_prefix},
                        {"is_mock", use_mock_}
                    }}
                };
                WazuhClient::send_alert(alert);
                last_alert_[event.hijacker_asn] = std::chrono::system_clock::now();
            }
        }
    }

    bool should_alert(const std::string& asn) {
        auto now = std::chrono::system_clock::now();
        auto last = last_alert_.find(asn);
        return last == last_alert_.end() ||
               (now - last->second) > std::chrono::hours(24);
    }
};

int main(int argc, char** argv) {
    bool use_mock = (argc > 1 && std::string(argv[1]) == "--mock");

    std::cout << "Starting BGP Hijack Detector ("
              << (use_mock ? "MOCK" : "PRODUCTION") << " MODE)\n";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    BgpAnalyzer analyzer(use_mock);
    analyzer.run();
    curl_global_cleanup();
    return 0;
}