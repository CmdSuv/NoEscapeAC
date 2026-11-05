#include "tests/test_framework.hpp"
#include "noescape/core/thread_pool.hpp"
#include <atomic>

using namespace noescape::core;

TEST(ThreadPool, ExecutionAndFuture) {
    ThreadPool pool(4);
    std::atomic<int> counter{0};

    std::vector<std::future<int>> futures;
    for (int i = 0; i < 20; ++i) {
        futures.push_back(pool.Enqueue([&counter, i]() {
            counter++;
            return i * 2;
        }));
    }

    for (int i = 0; i < 20; ++i) {
        int res = futures[i].get();
        ASSERT_EQ(res, i * 2);
    }

    ASSERT_EQ(counter.load(), 20);
}
