#include <new>
extern "C" __declspec(noreturn) void __cdecl network162_throw(int kind) {
    if(kind) throw std::bad_alloc();
    throw 162;
}
