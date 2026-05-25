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

#ifdef FRANKENLIBC_WRAP_CXA_THROW
extern "C" [[noreturn]] void __real___cxa_throw(
    void* thrown_exception,
    void* type_info,
    void (*destructor)(void*)
);

extern "C" __attribute__((noinline, noreturn)) void __wrap___cxa_throw(
    void* thrown_exception,
    void* type_info,
    void (*destructor)(void*)
) {
    __real___cxa_throw(thrown_exception, type_info, destructor);
    __builtin_unreachable();
}
#endif

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

extern "C" int minimal_throw_catch_entry() {
    printf("minimal_throw_catch: starting\n");

    int result = throw_and_catch();

    if (result == 0) {
        printf("PASS: exception caught correctly\n");
    } else {
        printf("FAIL: exception handling failed (code %d)\n", result);
    }

    return result;
}

int main() {
    return minimal_throw_catch_entry();
}
