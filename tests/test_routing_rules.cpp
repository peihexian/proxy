#include <iostream>
#include <vector>
#include <string>
#include <memory>
#include <cassert>

// Need to adjust include paths based on how this test would be compiled.
// Assuming it's compiled from a directory that has 'proxy' and 'common' as subdirs,
// or that include paths are set up accordingly.
#include "proxy/routing_rules.hpp"
#include "proxy/strutil.hpp" // For strutil::split
#include "proxy/ipip.hpp"    // For ipip_datx (though we'll mock its usage for CountryRule)

// From boost, used in routing_rules.hpp and potentially here
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/network_v4.hpp>
#include <boost/algorithm/string/case_conv.hpp> // For boost::to_upper_copy for country codes
#include <boost/algorithm/string/predicate.hpp> // For boost::iequals

// Mock ipip_datx for CountryRule testing if needed, or skip its matching test
// For now, we will focus on parsing CountryRule and basic matching tests for CIDR/Domain.
// A more complete CountryRule test would require a mock ipip_datx.

using namespace proxy;

// Helper function to simulate rule parsing from main.cpp
std::shared_ptr<RoutingRule> parse_test_rule(const std::string& rule_str) {
    auto parts = strutil::split(rule_str, ":");

    if (parts.size() < 3) {
        std::cerr << "Test Parse Error: Invalid rule string format (too few parts): '" << rule_str << "'" << std::endl;
        return nullptr;
    }

    std::string type_str = std::string(parts[0]);
    std::string value_str = std::string(parts[1]);
    std::string action_str = std::string(parts[2]);
    std::string proxy_url_val;

    RuleAction action_enum_val;
    if (boost::iequals(action_str, "direct")) {
        action_enum_val = RuleAction::DIRECT;
    } else if (boost::iequals(action_str, "proxy")) {
        action_enum_val = RuleAction::PROXY;
        if (parts.size() >= 4) {
            size_t proxy_url_start_pos = parts[0].length() + parts[1].length() + parts[2].length() + 3;
            if (rule_str.length() > proxy_url_start_pos) {
                proxy_url_val = rule_str.substr(proxy_url_start_pos);
            }
        }
    } else if (boost::iequals(action_str, "block")) {
        action_enum_val = RuleAction::BLOCK;
    } else {
        std::cerr << "Test Parse Error: Invalid action in rule string: '" << action_str << "' in rule: '" << rule_str << "'" << std::endl;
        return nullptr;
    }

    try {
        if (boost::iequals(type_str, "cidr")) {
            if (action_enum_val == RuleAction::PROXY) {
                return std::make_shared<CIDRRule>(value_str, action_enum_val, proxy_url_val);
            } else {
                return std::make_shared<CIDRRule>(value_str, action_enum_val);
            }
        } else if (boost::iequals(type_str, "domain")) {
            if (action_enum_val == RuleAction::PROXY) {
                return std::make_shared<DomainRule>(value_str, action_enum_val, proxy_url_val);
            } else {
                return std::make_shared<DomainRule>(value_str, action_enum_val);
            }
        } else if (boost::iequals(type_str, "country")) {
            std::string country_code_upper = boost::to_upper_copy<std::string>(value_str);
            if (action_enum_val == RuleAction::PROXY) {
                return std::make_shared<CountryRule>(country_code_upper, action_enum_val, proxy_url_val);
            } else {
                return std::make_shared<CountryRule>(country_code_upper, action_enum_val);
            }
        } else {
            std::cerr << "Test Parse Error: Invalid type in rule string: '" << type_str << "' in rule: '" << rule_str << "'" << std::endl;
            return nullptr;
        }
    } catch (const boost::system::system_error& e) {
        std::cerr << "Test Parse Error (boost::system::system_error): " << e.what() << " for rule '" << rule_str << "'" << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Test Parse Error (std::exception): " << e.what() << " for rule '" << rule_str << "'" << std::endl;
        return nullptr;
    }
    return nullptr; // Should not be reached if type is valid
}

void test_cidr_rule_parsing() {
    std::cout << "Testing CIDR Rule Parsing..." << std::endl;

    auto rule1 = parse_test_rule("cidr:192.168.1.0/24:direct");
    assert(rule1 != nullptr);
    assert(rule1->action_ == RuleAction::DIRECT);
    auto cidr_rule1 = std::dynamic_pointer_cast<CIDRRule>(rule1);
    assert(cidr_rule1 != nullptr);
    assert(cidr_rule1->cidr_str_ == "192.168.1.0/24");

    auto rule2 = parse_test_rule("cidr:10.0.0.0/8:proxy:socks5://localhost:1080");
    assert(rule2 != nullptr);
    assert(rule2->action_ == RuleAction::PROXY);
    assert(rule2->get_proxy_url() == "socks5://localhost:1080");
    auto cidr_rule2 = std::dynamic_pointer_cast<CIDRRule>(rule2);
    assert(cidr_rule2 != nullptr);
    assert(cidr_rule2->cidr_str_ == "10.0.0.0/8");
    
    auto rule3 = parse_test_rule("cidr:172.16.0.0/12:block");
    assert(rule3 != nullptr);
    assert(rule3->action_ == RuleAction::BLOCK);
    auto cidr_rule3 = std::dynamic_pointer_cast<CIDRRule>(rule3);
    assert(cidr_rule3 != nullptr);
    assert(cidr_rule3->cidr_str_ == "172.16.0.0/12");

    // Test invalid CIDR
    auto rule_invalid_cidr = parse_test_rule("cidr:192.168.1.0/33:direct"); // Invalid mask
    assert(rule_invalid_cidr == nullptr); 
    
    auto rule_invalid_cidr2 = parse_test_rule("cidr:not-a-cidr:direct");
    assert(rule_invalid_cidr2 == nullptr);

    std::cout << "CIDR Rule Parsing Tests Passed." << std::endl;
}

void test_domain_rule_parsing() {
    std::cout << "Testing Domain Rule Parsing..." << std::endl;

    auto rule1 = parse_test_rule("domain:example.com:direct");
    assert(rule1 != nullptr);
    assert(rule1->action_ == RuleAction::DIRECT);
    auto domain_rule1 = std::dynamic_pointer_cast<DomainRule>(rule1);
    assert(domain_rule1 != nullptr);
    assert(domain_rule1->domain_pattern_ == "example.com");

    auto rule2 = parse_test_rule("domain:.example.com:proxy:http://localhost:3128");
    assert(rule2 != nullptr);
    assert(rule2->action_ == RuleAction::PROXY);
    assert(rule2->get_proxy_url() == "http://localhost:3128");
    auto domain_rule2 = std::dynamic_pointer_cast<DomainRule>(rule2);
    assert(domain_rule2 != nullptr);
    assert(domain_rule2->domain_pattern_ == ".example.com");

    auto rule3 = parse_test_rule("domain:*.example.net:block");
    assert(rule3 != nullptr);
    assert(rule3->action_ == RuleAction::BLOCK);
    auto domain_rule3 = std::dynamic_pointer_cast<DomainRule>(rule3);
    assert(domain_rule3 != nullptr);
    assert(domain_rule3->domain_pattern_ == "*.example.net");
    
    // Test proxy URL with colons
    auto rule4 = parse_test_rule("domain:test.com:proxy:socks5://user:pass@example.com:1080");
    assert(rule4 != nullptr);
    assert(rule4->action_ == RuleAction::PROXY);
    assert(rule4->get_proxy_url() == "socks5://user:pass@example.com:1080");
    auto domain_rule4 = std::dynamic_pointer_cast<DomainRule>(rule4);
    assert(domain_rule4 != nullptr);
    assert(domain_rule4->domain_pattern_ == "test.com");


    std::cout << "Domain Rule Parsing Tests Passed." << std::endl;
}

void test_country_rule_parsing() {
    std::cout << "Testing Country Rule Parsing..." << std::endl;

    auto rule1 = parse_test_rule("country:US:direct");
    assert(rule1 != nullptr);
    assert(rule1->action_ == RuleAction::DIRECT);
    auto country_rule1 = std::dynamic_pointer_cast<CountryRule>(rule1);
    assert(country_rule1 != nullptr);
    assert(country_rule1->country_code_ == "US");

    auto rule2 = parse_test_rule("country:cn:proxy:socks5://anotherproxy:1080"); // Test lowercase country code
    assert(rule2 != nullptr);
    assert(rule2->action_ == RuleAction::PROXY);
    assert(rule2->get_proxy_url() == "socks5://anotherproxy:1080");
    auto country_rule2 = std::dynamic_pointer_cast<CountryRule>(rule2);
    assert(country_rule2 != nullptr);
    assert(country_rule2->country_code_ == "CN"); // Should be uppercased

    auto rule3 = parse_test_rule("country:GB:block");
    assert(rule3 != nullptr);
    assert(rule3->action_ == RuleAction::BLOCK);
    auto country_rule3 = std::dynamic_pointer_cast<CountryRule>(rule3);
    assert(country_rule3 != nullptr);
    assert(country_rule3->country_code_ == "GB");
    
    std::cout << "Country Rule Parsing Tests Passed." << std::endl;
}

void test_invalid_rule_parsing() {
    std::cout << "Testing Invalid Rule Parsing..." << std::endl;

    // Incorrect type
    auto rule1 = parse_test_rule("foo:bar:direct");
    assert(rule1 == nullptr);

    // Wrong number of parts
    auto rule2 = parse_test_rule("cidr:192.168.1.0/24");
    assert(rule2 == nullptr);
    auto rule3 = parse_test_rule("domain:example.com:proxy"); // Missing proxy_url should be allowed
    assert(rule3 != nullptr);
    assert(rule3->action_ == RuleAction::PROXY);
    assert(rule3->get_proxy_url().empty());

    // Invalid action
    auto rule4 = parse_test_rule("cidr:192.168.1.0/24:allow");
    assert(rule4 == nullptr);

    // Malformed proxy URL (though current parser is basic)
    // The current parser might accept some malformed URLs as it just takes the rest of the string.
    // A more robust URL parsing/validation isn't part of this rule parser.
    // auto rule5 = parse_test_rule("domain:example.com:proxy:htt p://localhost:8080");
    // assert(rule5 == nullptr); // This might pass current parsing but fail in practice

    std::cout << "Invalid Rule Parsing Tests Passed." << std::endl;
}

void test_cidr_rule_matching() {
    std::cout << "Testing CIDR Rule Matching..." << std::endl;
    CIDRRule rule_lan("192.168.1.0/24", RuleAction::DIRECT);
    CIDRRule rule_wan("10.0.0.0/8", RuleAction::DIRECT);

    assert(rule_lan.matches("192.168.1.100", 0, nullptr) == true);
    assert(rule_lan.matches("192.168.1.1", 0, nullptr) == true); // Network address itself (if hosts() allows)
    assert(rule_lan.matches("192.168.1.254", 0, nullptr) == true);
    assert(rule_lan.matches("192.168.1.0", 0, nullptr) == true); // Network address
    assert(rule_lan.matches("192.168.1.255", 0, nullptr) == true); // Broadcast address

    assert(rule_lan.matches("192.168.2.1", 0, nullptr) == false);
    assert(rule_lan.matches("10.0.0.1", 0, nullptr) == false);
    assert(rule_lan.matches("not-an-ip", 0, nullptr) == false);

    assert(rule_wan.matches("10.1.2.3", 0, nullptr) == true);
    assert(rule_wan.matches("10.255.255.254", 0, nullptr) == true);
    assert(rule_wan.matches("11.0.0.1", 0, nullptr) == false);

    std::cout << "CIDR Rule Matching Tests Passed." << std::endl;
}

void test_domain_rule_matching() {
    std::cout << "Testing Domain Rule Matching..." << std::endl;
    DomainRule rule_exact("exact.example.com", RuleAction::DIRECT);
    DomainRule rule_suffix(".suffix.example.com", RuleAction::DIRECT);
    DomainRule rule_wildcard("*.wildcard.example.com", RuleAction::DIRECT);

    // Exact match
    assert(rule_exact.matches("exact.example.com", 0, nullptr) == true);
    assert(rule_exact.matches("www.exact.example.com", 0, nullptr) == false);
    assert(rule_exact.matches("anotherexample.com", 0, nullptr) == false);
    assert(rule_exact.matches("1.2.3.4", 0, nullptr) == false); // Should not match IPs

    // Suffix match
    assert(rule_suffix.matches("test.suffix.example.com", 0, nullptr) == true);
    assert(rule_suffix.matches("another.test.suffix.example.com", 0, nullptr) == true);
    assert(rule_suffix.matches("suffix.example.com", 0, nullptr) == false); // ".suffix.example.com" requires something before it
    assert(rule_suffix.matches("example.com", 0, nullptr) == false);
    assert(rule_suffix.matches("test.suffix.example.co", 0, nullptr) == false);
    assert(rule_suffix.matches("1.2.3.4", 0, nullptr) == false);

    // Wildcard match
    assert(rule_wildcard.matches("sub.wildcard.example.com", 0, nullptr) == true);
    assert(rule_wildcard.matches("foo.wildcard.example.com", 0, nullptr) == true);
    assert(rule_wildcard.matches("wildcard.example.com", 0, nullptr) == false); // Requires one label for '*'
    assert(rule_wildcard.matches("sub.sub.wildcard.example.com", 0, nullptr) == false); // '*' only matches one label
    assert(rule_wildcard.matches("another.example.com", 0, nullptr) == false);
    assert(rule_wildcard.matches("1.2.3.4", 0, nullptr) == false);
    
    // Test specific case for wildcard from problem description (*.example.com should match sub.example.com but not ..example.com)
    DomainRule rule_wild_specific("*.example.com", RuleAction::DIRECT);
    assert(rule_wild_specific.matches("sub.example.com", 0, nullptr) == true);
    // assert(rule_wild_specific.matches(".example.com", 0, nullptr) == false); // This case depends on interpretation, current logic might pass.
                                                                                // The current logic: prefix must not be empty and not contain '.'
                                                                                // If destination_host is ".example.com", prefix is "" -> false.
                                                                                // If destination_host is "..example.com", prefix is "." -> false.

    std::cout << "Domain Rule Matching Tests Passed." << std::endl;
}

// CountryRule matching is hard to test without a mock ipip_datx or a real db.
// We've tested its parsing. For matching, we'd need to simulate ipip_db->lookup.
// void test_country_rule_matching() { ... }


// Proxy Session Rule Evaluation Tests would be more complex and require
// mocking parts of proxy_session and proxy_server_option.
// These are closer to integration tests.
// void test_proxy_session_evaluation() { ... }

int main() {
    std::cout << "Starting Routing Rule Tests..." << std::endl;

    test_cidr_rule_parsing();
    test_domain_rule_parsing();
    test_country_rule_parsing();
    test_invalid_rule_parsing();

    test_cidr_rule_matching();
    test_domain_rule_matching();
    // test_country_rule_matching(); // If implemented

    // test_proxy_session_evaluation(); // If implemented

    std::cout << "All Routing Rule Tests Completed." << std::endl;
    return 0;
}
