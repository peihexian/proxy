#ifndef PROXY_ROUTING_RULES_HPP
#define PROXY_ROUTING_RULES_HPP

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cctype>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
// #include <boost/algorithm/string/predicate.hpp> // For iequals - replaced by strutil
#include "proxy/strutil.hpp" // For strutil::to_lower_copy
#include "proxy/ipip.hpp" // Include for ipip_datx definition

namespace proxy {

enum class RuleAction {
    DIRECT,
    PROXY,
    BLOCK
};

struct RoutingRule {
    RuleAction action_;

    RoutingRule(RuleAction action) : action_(action) {}
    virtual ~RoutingRule() = default;

    virtual bool matches(const std::string& destination_host, uint16_t destination_port, const ipip_datx* ipip_db) const = 0;
    virtual std::string get_proxy_url() const { return ""; }
};

struct ProxyRuleMixin {
    std::string proxy_url_;

    ProxyRuleMixin(const std::string& proxy_url) : proxy_url_(proxy_url) {}
    std::string get_proxy_url() const { return proxy_url_; }
};

struct CIDRRule : public RoutingRule {
    boost::asio::ip::network_v4 network_;
    std::string cidr_str_; // Store for logging or other purposes

    CIDRRule(const std::string& cidr_str, RuleAction action)
        : RoutingRule(action), network_(boost::asio::ip::make_network_v4(cidr_str)), cidr_str_(cidr_str) {}

    CIDRRule(const std::string& cidr_str, RuleAction action, const std::string& proxy_url)
        : RoutingRule(action), network_(boost::asio::ip::make_network_v4(cidr_str)), cidr_str_(cidr_str), proxy_mixin_(proxy_url) {
        if (action != RuleAction::PROXY) {
            // Optionally, throw an error or log a warning if proxy_url is provided for non-PROXY actions
        }
    }

    bool matches(const std::string& destination_host, uint16_t /*destination_port*/, const ipip_datx* /*ipip_db*/) const override {
        try {
            boost::system::error_code ec;
            auto dest_addr = boost::asio::ip::make_address_v4(destination_host, ec);
            if (ec) { // Not a valid IPv4 address
                return false;
            }
            return network_.hosts().find(dest_addr) != network_.hosts().end() || dest_addr == network_.network() || dest_addr == network_.broadcast();
        } catch (const std::exception& /*e*/) {
            // If destination_host is not a valid IP address string
            return false;
        }
    }

    std::string get_proxy_url() const override {
        if (action_ == RuleAction::PROXY) {
            return proxy_mixin_.get_proxy_url();
        }
        return RoutingRule::get_proxy_url();
    }

private:
    // Embed ProxyRuleMixin only if action is PROXY, or manage proxy_url directly
    // For simplicity, let's assume a proxy_url can be stored but only used if action_ is PROXY.
    // A more robust way would be to use std::optional<ProxyRuleMixin> or templates.
    ProxyRuleMixin proxy_mixin_{""}; // Default construct if not a PROXY rule with a specific URL
};

struct DomainRule : public RoutingRule {
    std::string domain_pattern_;

    DomainRule(const std::string& pattern, RuleAction action)
        : RoutingRule(action), domain_pattern_(pattern) {}

    DomainRule(const std::string& pattern, RuleAction action, const std::string& proxy_url)
        : RoutingRule(action), domain_pattern_(pattern), proxy_mixin_(proxy_url) {
        if (action != RuleAction::PROXY) {
            // Log warning or throw
        }
    }

    bool matches(const std::string& destination_host, uint16_t /*destination_port*/, const ipip_datx* /*ipip_db*/) const override {
        // If destination_host is an IP, this rule should not match.
        // A simple check: if it parses as an IP, it's not a domain.
        boost::system::error_code ec;
        boost::asio::ip::make_address_v4(destination_host, ec);
        if (!ec) { // It's a valid IPv4 address
            boost::asio::ip::make_address_v6(destination_host, ec);
            if (!ec) { // It's a valid IPv6 address
                 return false;
            }
        }
        
        // Exact match
        if (domain_pattern_ == destination_host) {
            return true;
        }

        // Wildcard match (*.example.com)
        if (domain_pattern_.rfind("*.", 0) == 0) { // starts with *.
            std::string suffix = domain_pattern_.substr(1); // .example.com
            if (destination_host.length() > suffix.length() && 
                destination_host.rfind(suffix) == destination_host.length() - suffix.length()) {
                // Check that the part before the suffix is not empty and does not contain dots (e.g. sub.example.com not ..example.com)
                std::string prefix = destination_host.substr(0, destination_host.length() - suffix.length());
                return !prefix.empty() && prefix.find('.') == std::string::npos;
            }
        }

        // Suffix match (.example.com)
        if (domain_pattern_.rfind(".", 0) == 0) { // starts with .
             if (destination_host.length() > domain_pattern_.length() &&
                destination_host.rfind(domain_pattern_) == destination_host.length() - domain_pattern_.length()) {
                return true;
            }
        }
        return false;
    }

    std::string get_proxy_url() const override {
        if (action_ == RuleAction::PROXY) {
            return proxy_mixin_.get_proxy_url();
        }
        return RoutingRule::get_proxy_url();
    }

private:
    ProxyRuleMixin proxy_mixin_{""};
};

// Forward declaration from proxy/ipip.hpp - actual include might be needed in .cpp or for full definition
// struct ipip_datx; 

struct CountryRule : public RoutingRule {
    std::string country_code_;

    CountryRule(const std::string& code, RuleAction action)
        : RoutingRule(action), country_code_(code) {}

    CountryRule(const std::string& code, RuleAction action, const std::string& proxy_url)
        : RoutingRule(action), country_code_(code), proxy_mixin_(proxy_url) {
        if (action != RuleAction::PROXY) {
            // Log warning or throw
        }
    }

    bool matches(const std::string& destination_host, uint16_t /*destination_port*/, const ipip_datx* ipip_db) const override {
        if (!ipip_db) {
            return false;
        }

        boost::system::error_code ec;
        auto ip_addr = boost::asio::ip::make_address(destination_host, ec);
        if (ec) {
            return false;
        }

        auto [regions, isp] = ipip_db->lookup(ip_addr);
        if (regions.empty()) {
            return false;
        }
        std::string country_name = regions.front();

        // If the database already returns a two letter code, compare directly.
        std::string upper_name = strutil::to_upper(country_name);
        if (upper_name.size() == 2 && std::isalpha(static_cast<unsigned char>(upper_name[0])) && std::isalpha(static_cast<unsigned char>(upper_name[1]))) {
            return upper_name == country_code_;
        }

        static const std::unordered_map<std::string, std::string> country_map = {
            {"中国", "CN"},
            {"中华人民共和国", "CN"},
            {"中国台湾", "TW"},
            {"台湾", "TW"},
            {"中国香港", "HK"},
            {"香港", "HK"},
            {"中国澳门", "MO"},
            {"澳门", "MO"},
            {"美国", "US"},
            {"United States", "US"},
            {"日本", "JP"},
            {"Japan", "JP"},
            {"韩国", "KR"},
            {"South Korea", "KR"},
            {"英国", "GB"},
            {"United Kingdom", "GB"},
            {"俄罗斯", "RU"},
            {"Russia", "RU"},
            {"德国", "DE"},
            {"Germany", "DE"},
            {"法国", "FR"},
            {"France", "FR"},
            {"加拿大", "CA"},
            {"Canada", "CA"},
            {"澳大利亚", "AU"},
            {"Australia", "AU"},
            {"印度", "IN"},
            {"India", "IN"},
            {"巴西", "BR"},
            {"Brazil", "BR"}
        };

        auto it = country_map.find(country_name);
        if (it != country_map.end()) {
            return it->second == country_code_;
        }

        // Fallback: compare uppercased name with the desired code.
        return upper_name == country_code_;
    }

    std::string get_proxy_url() const override {
        if (action_ == RuleAction::PROXY) {
            return proxy_mixin_.get_proxy_url();
        }
        return RoutingRule::get_proxy_url();
    }

private:
    ProxyRuleMixin proxy_mixin_{""};
};

} // namespace proxy

#endif // PROXY_ROUTING_RULES_HPP
