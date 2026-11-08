#include "tests/test_framework.hpp"
#include <cstdlib>

#if defined(_WIN32)
#include <windows.h>
#endif

int main() {
#if defined(_WIN32)
    SetEnvironmentVariableA("NOESCAPE_TEST_MODE", "1");
    _putenv("NOESCAPE_TEST_MODE=1");
#else
    setenv("NOESCAPE_TEST_MODE", "1", 1);
#endif
    return noescape::test::TestRunner::Instance().RunAll();
}
