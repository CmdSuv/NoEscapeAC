#include "tests/test_framework.hpp"
#include <cstdlib>

int main() {
#if defined(_WIN32)
    _putenv("NOESCAPE_TEST_MODE=1");
#else
    setenv("NOESCAPE_TEST_MODE", "1", 1);
#endif
    return noescape::test::TestRunner::Instance().RunAll();
}
