#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include <cmath>

// Sanitizers quarantine freed memory (stale residue of earlier tests stays scannable) and
// shadow-map huge regions, so "completely clean process" assertions are only meaningful without them.
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_THREAD__)
#define NOESCAPE_UNDER_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(thread_sanitizer)
#define NOESCAPE_UNDER_SANITIZER 1
#endif
#endif

namespace noescape::test {

class TestRunner {
public:
    using TestCase = std::function<void()>;

    static TestRunner& Instance() {
        static TestRunner instance;
        return instance;
    }

    void RegisterTest(std::string suite, std::string name, TestCase test) {
        tests_.push_back({std::move(suite), std::move(name), std::move(test)});
    }

    int RunAll() {
        int passed = 0;
        int failed = 0;

        std::cout << "\033[1;35m====================================================\n"
                  << "        NoEscape Anti-Cheat C++20 Test Suite         \n"
                  << "====================================================\033[0m\n\n";

        for (const auto& t : tests_) {
            std::cout << "\033[1;34m[ RUN      ]\033[0m " << t.suite << "." << t.name << " ... " << std::flush;
            try {
                t.func();
                std::cout << "\033[1;32mPASSED\033[0m\n";
                passed++;
            } catch (const std::exception& ex) {
                std::cout << "\033[1;31mFAILED\033[0m\n";
                std::cout << "  \033[31mError: " << ex.what() << "\033[0m\n";
                failed++;
            } catch (...) {
                std::cout << "\033[1;31mFAILED (Unknown exception)\033[0m\n";
                failed++;
            }
        }

        std::cout << "\n\033[1;35m====================================================\033[0m\n";
        std::cout << "Total Tests: " << tests_.size() << " | \033[32mPassed: " << passed 
                  << "\033[0m | \033[" << (failed > 0 ? "31" : "32") << "mFailed: " << failed << "\033[0m\n";

        return failed == 0 ? 0 : 1;
    }

private:
    struct Entry {
        std::string suite;
        std::string name;
        TestCase func;
    };
    std::vector<Entry> tests_;
};

struct TestRegistrar {
    TestRegistrar(std::string suite, std::string name, TestRunner::TestCase test) {
        TestRunner::Instance().RegisterTest(std::move(suite), std::move(name), std::move(test));
    }
};

#define TEST(suite, name) \
    void test_##suite##_##name(); \
    static ::noescape::test::TestRegistrar reg_##suite##_##name(#suite, #name, test_##suite##_##name); \
    void test_##suite##_##name()

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error("Assertion failed: " #cond " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_FALSE(cond) \
    do { \
        if (cond) { \
            throw std::runtime_error("Assertion failed: NOT " #cond " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if (!((a) == (b))) { \
            throw std::runtime_error("Assertion failed: " #a " == " #b " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_NE(a, b) \
    do { \
        if ((a) == (b)) { \
            throw std::runtime_error("Assertion failed: " #a " != " #b " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_GT(a, b) \
    do { \
        if (!((a) > (b))) { \
            throw std::runtime_error("Assertion failed: " #a " > " #b " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_LT(a, b) \
    do { \
        if (!((a) < (b))) { \
            throw std::runtime_error("Assertion failed: " #a " < " #b " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

#define ASSERT_NEAR(a, b, eps) \
    do { \
        if (std::abs((a) - (b)) > (eps)) { \
            throw std::runtime_error("Assertion failed: |" #a " - " #b "| <= " #eps " at " __FILE__ ":" + std::to_string(__LINE__)); \
        } \
    } while (0)

} // namespace noescape::test
