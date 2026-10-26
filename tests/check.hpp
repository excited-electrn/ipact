#pragma once
// A tiny test framework so the project needs no dependencies. (GoogleTest or Catch2 work the
// same way; switch whenever you like.)
#include <cstdio>
#include <functional>
#include <vector>

struct TestCase { const char* name; std::function<void()> fn; };
inline std::vector<TestCase>& test_registry() { static std::vector<TestCase> r; return r; }
inline int& test_failures() { static int n = 0; return n; }
struct TestRegistrar {
    TestRegistrar(const char* name, std::function<void()> fn) { test_registry().push_back({name, std::move(fn)}); }
};

#define TEST(name)                                       \
    static void name();                                  \
    static TestRegistrar registrar_##name(#name, name);  \
    static void name()

#define CHECK(cond)                                                                        \
    do {                                                                                   \
        if (!(cond)) {                                                                     \
            std::printf("    FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
            ++test_failures();                                                             \
        }                                                                                  \
    } while (0)

#define CHECK_EQ(a, b)                                                                     \
    do {                                                                                   \
        auto va = (a);                                                                     \
        auto vb = (b);                                                                     \
        if (!(va == vb)) {                                                                 \
            std::printf("    FAILED %s:%d: %s == %s  (%lld vs %lld)\n", __FILE__, __LINE__, #a, #b, \
                        (long long)va, (long long)vb);                                     \
            ++test_failures();                                                             \
        }                                                                                  \
    } while (0)

inline int run_all_tests() {
    for (auto& t : test_registry()) {
        int before = test_failures();
        std::printf("[ RUN  ] %s\n", t.name);
        t.fn();
        std::printf("[ %s ] %s\n", test_failures() == before ? " OK " : "FAIL", t.name);
    }
    std::printf("\n%zu tests, %d failed checks\n", test_registry().size(), test_failures());
    return test_failures() == 0 ? 0 : 1;
}
