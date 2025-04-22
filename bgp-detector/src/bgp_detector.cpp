#include <iostream>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <cstdlib>
#include "mock_stream.hpp"  // Our mock data generator

using json = nlohmann::json;

// Configuration - now uses mock data
const int CHECK_INTERVAL = 300; // 5 minutes

// Mock credentials (unused but kept for compatibility)
const std::string API_KEY = "mock_key";
const std::string WAZUH_API = std::getenv("WAZUH_API") ? std::getenv("WAZUH_API") : "http://wazuh-manager:55000";
const std::string API_USER = std::getenv("WAZUH_API_USER") ? std::getenv("WAZUH_API_USER") : "admin";
const std::string API_PASS = std::getenv("WAZUH_API_PASS") ? std::getenv("WAZUH_API_PASS") : "password";

class BgpAnalyzer {
public:
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

    // Modified to use mock data
    std::vector<BgpEvent> fetch_bgp_events() {
        auto mock_events = MockBGPStream::generate_events();
        std::vector<BgpEvent> events;

        for (const auto& e : mock_events) {
            events.push_back({
                e["hijacker_asn"].get<std::string>(),
                e["victim_prefix"].get<std::string>(),
                e["start_time"].get<std::string>()
            });
        }
        return events;
    }

    void analyze_events(const std::vector<BgpEvent>& events) {
        for (const auto& event : events) {
            json alert = {
                {"timestamp", std::time(nullptr)},
                {"rule", {
                    {"id", 900100},
                    {"description", "BGP Hijack Detected (MOCK)"},
                    {"level", 12},
                    {"mitre", {"T1574", "Hijack Trusted Route"}}
                }},
                {"bgp", {
                    {"hijacker_asn", event.hijacker_asn},
                    {"victim_prefix", event.victim_prefix},
                    {"duration_min", calculate_duration(event.start_time)},
                    {"is_mock", true}  // Flag mock data
                }}
            };

            send_to_wazuh(alert);
        }
    }

    int calculate_duration(const std::string& start_time) {
        // Mock duration calculation
        return 5 + (std::hash<std::string>{}(start_time) % 30);
    }

    static size_t write_callback(void*, size_t size, size_t nmemb, std::string*) {
        return size * nmemb;
    }

    void send_to_wazuh(const json& alert) {
        CURL *curl = curl_easy_init();
        if (!curl) return;

        std::string json_str = alert.dump();
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("Authorization: Basic " +
            std::string(curl_easy_escape(curl, API_USER.c_str(), API_USER.length())) + ":" +
            std::string(curl_easy_escape(curl, API_PASS.c_str(), API_PASS.length()))).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, WAZUH_API.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        // Debug (uncomment to see sent alerts)
        // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Failed to send alert: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
};

int main() {
    std::cout << "Starting BGP Hijack Detector (MOCK MODE)\n";
    std::cout << "Sample ASN Range: AS1000-AS9999\n";
    std::cout << "Sample Prefixes: 1.1.0.0/16 to 254.254.0.0/16\n";

    curl_global_init(CURL_GLOBAL_DEFAULT);
    BgpAnalyzer analyzer;
    analyzer.run();
    curl_global_cleanup();
    return 0;
}