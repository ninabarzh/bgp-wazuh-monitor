//detectors/ssh-bruteforce/src/detector.cpp
#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <chrono>
#include <nlohmann/json.hpp>
#include <regex>
#include "../shared/wazuh_client.hpp"

using json = nlohmann::json;

const int CHECK_INTERVAL = 60; // Seconds
const int FAILED_ATTEMPT_THRESHOLD = 5;
const int TIME_WINDOW_MINUTES = 10;

class SSHBruteForceDetector {
public:
    SSHBruteForceDetector(bool use_mock) : use_mock_(use_mock) {}

    void run() {
        while (true) {
            auto events = fetch_ssh_events();
            analyze_events(events);
            std::this_thread::sleep_for(std::chrono::seconds(CHECK_INTERVAL));
        }
    }

private:
    struct AttemptRecord {
        int count;
        std::chrono::system_clock::time_point first_attempt;
    };

    bool use_mock_;
    std::unordered_map<std::string, AttemptRecord> attempts_;
    const std::regex ssh_failure_regex_ =
        std::regex(R"(.*sshd.*Failed password for (invalid user )?(\w+).*)", std::regex::icase);

    std::vector<json> fetch_ssh_events() {
        if (use_mock_) {
            return MockSSH::generate_events();
        } else {
            std::vector<json> alerts;
            std::ifstream alert_file("/var/ossec/logs/alerts/alerts.json");
            std::string line;

            while (std::getline(alert_file, line)) {
                try {
                    alerts.push_back(json::parse(line));
                } catch (...) {}
            }
            return alerts;
        }
    }

    void analyze_events(const std::vector<json>& events) {
        auto now = std::chrono::system_clock::now();

        for (const auto& alert : events) {
            if (is_ssh_failure(alert)) {
                std::string ip = alert["data"]["srcip"];
                record_attempt(ip, now);
            }
        }
        check_thresholds(now);
    }

    bool is_ssh_failure(const json& alert) {
        if (!alert.contains("rule") || !alert["rule"].contains("id")) return false;

        int rule_id = alert["rule"]["id"];
        return (rule_id >= 5710 && rule_id <= 5719); // Wazuh SSH failure IDs
    }

    void record_attempt(const std::string& ip,
                       const std::chrono::system_clock::time_point& now) {
        auto& record = attempts_[ip];
        if (record.count == 0) record.first_attempt = now;
        record.count++;
    }

    void check_thresholds(const std::chrono::system_clock::time_point& now) {
        for (const auto& [ip, record] : attempts_) {
            auto elapsed_min = std::chrono::duration_cast<std::chrono::minutes>(
                now - record.first_attempt).count();

            if (record.count >= FAILED_ATTEMPT_THRESHOLD &&
                elapsed_min <= TIME_WINDOW_MINUTES) {

                json alert = {
                    {"timestamp", std::time(nullptr)},
                    {"rule", {
                        {"id", 900001},
                        {"description", "SSH brute force detected"},
                        {"level", 10},
                        {"mitre", {"T1110"}}
                    }},
                    {"agent", {
                        {"ip", ip}
                    }},
                    {"ssh", {
                        {"attempts", record.count},
                        {"time_window_min", elapsed_min},
                        {"is_mock", use_mock_}
                    }}
                };
                WazuhClient::send_alert(alert);
            }
        }
    }
};

int main(int argc, char** argv) {
    bool use_mock = (argc > 1 && std::string(argv[1]) == "--mock");

    std::cout << "Starting SSH Bruteforce Detector ("
              << (use_mock ? "MOCK" : "PRODUCTION") << " MODE)\n"
              << "Threshold: " << FAILED_ATTEMPT_THRESHOLD
              << " attempts in " << TIME_WINDOW_MINUTES << " minutes\n";

    SSHBruteForceDetector detector(use_mock);
    detector.run();
    return 0;
}