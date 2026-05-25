// bd-gq1kz7.2: Minimal C++ exception throw/catch fixture
// Expected to FAIL until owned unwinder is implemented
// Must not use libgcc_s or host unwinder

#include <cstdio>
#include <exception>

class TestException : public std::exception {
public:
    const char* what() const noexcept override {
        return "TestException from minimal_throw_catch";
    }
};

int throw_and_catch() {
    try {
        throw TestException();
    } catch (const TestException& e) {
        printf("CAUGHT: %s\n", e.what());
        return 0; // Success
    } catch (...) {
        printf("CAUGHT: unknown exception\n");
        return 1;
    }
    return 2; // Should not reach
}

int main() {
    printf("minimal_throw_catch: starting\n");

    int result = throw_and_catch();

    if (result == 0) {
        printf("PASS: exception caught correctly\n");
    } else {
        printf("FAIL: exception handling failed (code %d)\n", result);
    }

    return result;
}
