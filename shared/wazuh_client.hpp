// detectors/shared/wazuh_client.hpp
#pragma once
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <string>
#include <iostream>

using json = nlohmann::json;

class WazuhClient {
public:
    static void send_alert(const json& alert) {
        CURL *curl = curl_easy_init();
        if (!curl) {
            std::cerr << "Failed to initialize CURL" << std::endl;
            return;
        }

        std::string json_str = alert.dump();
        struct curl_slist *headers = nullptr;

        // Get credentials from env
        const char* api_user = std::getenv("WAZUH_API_USER");
        const char* api_pass = std::getenv("WAZUH_API_PASS");
        const char* api_url = std::getenv("WAZUH_API");

        if (!api_user || !api_pass || !api_url) {
            std::cerr << "Missing Wazuh API credentials" << std::endl;
            return;
        }

        // Prepare headers
        headers = curl_slist_append(headers, "Content-Type: application/json");
        std::string auth = std::string(api_user) + ":" + std::string(api_pass);
        headers = curl_slist_append(headers, ("Authorization: Basic " + base64_encode(auth)).c_str());

        // Configure CURL
        curl_easy_setopt(curl, CURLOPT_URL, api_url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        // Execute and clean up
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "Alert send failed: " << curl_easy_strerror(res) << std::endl;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

private:
    static std::string base64_encode(const std::string& in) {
        // Simple base64 implementation or use a library
        static const char* chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        // ... implementation ...
        return out;
    }
};