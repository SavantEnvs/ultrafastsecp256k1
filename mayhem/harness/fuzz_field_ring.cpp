// ============================================================================
// LibFuzzer harness: field multiplication ring laws
// ============================================================================
//
// TARGET: FieldElement::operator*, operator*=, square(), square_inplace(),
//         operator+, from_bytes() — the public field API (secp256k1/field.hpp).
//
// INPUT:  96 bytes -> three 32-byte big-endian field elements (a, b, c).
//
// ORACLE: GF(p) is a field, so for ANY a, b, c:
//           a * (b + c) == a * b + a * c        (distributivity)
//           (a * b) * c == a * (b * c)          (associativity)
//           a * b == b * a, a * a == a.square() (commutativity, squaring)
//         and the in-place forms agree with the value-returning ones.
//         Unlike a check of a*b against b*a (the same reduction of the same
//         product), distributivity and associativity compare DIFFERENT
//         products, so a reduction that returns a wrong residue for some
//         products breaks an identity and traps.
// ============================================================================
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "secp256k1/field.hpp"

using secp256k1::fast::FieldElement;

static FieldElement load(const uint8_t* p) {
    std::array<uint8_t, 32> buf{};
    std::memcpy(buf.data(), p, 32);
    return FieldElement::from_bytes(buf);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 96) return -1;

    FieldElement const a = load(data);
    FieldElement const b = load(data + 32);
    FieldElement const c = load(data + 64);

    // Distributivity: a(b + c) == ab + ac
    FieldElement const ab = a * b;
    FieldElement const ac = a * c;
    if (!(a * (b + c) == ab + ac)) __builtin_trap();

    // Associativity: (ab)c == a(bc)
    FieldElement const bc = b * c;
    if (!(ab * c == a * bc)) __builtin_trap();

    // Commutativity and squaring
    if (!(ab == b * a)) __builtin_trap();
    if (!(a * a == a.square())) __builtin_trap();

    // In-place forms agree with the value-returning ones
    FieldElement t = a;
    t *= b;
    if (!(t == ab)) __builtin_trap();
    t = a;
    t.square_inplace();
    if (!(t == a.square())) __builtin_trap();

    // (a + b)^2 == a^2 + 2ab + b^2
    FieldElement const s = a + b;
    if (!(s.square() == a.square() + ab + ab + b.square())) __builtin_trap();

    return 0;
}
