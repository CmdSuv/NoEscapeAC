#include "noescape/network/ed25519.hpp"
#include <cstring>
#include <array>

namespace noescape::network::ed25519 {

namespace {

// ============================================================================
// SHA-512 Implementation (FIPS 180-4)
// ============================================================================
struct Sha512Ctx {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t buffer[128];
};

inline uint64_t RotR64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64_t Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

inline uint64_t Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t Sigma0(uint64_t x) {
    return RotR64(x, 28) ^ RotR64(x, 34) ^ RotR64(x, 39);
}

inline uint64_t Sigma1(uint64_t x) {
    return RotR64(x, 14) ^ RotR64(x, 18) ^ RotR64(x, 41);
}

inline uint64_t Gamma0(uint64_t x) {
    return RotR64(x, 1) ^ RotR64(x, 8) ^ (x >> 7);
}

inline uint64_t Gamma1(uint64_t x) {
    return RotR64(x, 19) ^ RotR64(x, 61) ^ (x >> 6);
}

const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2dbf8350ULL, 0xb00327c898fb213fULL, 0xbf597fc7bee0ee30ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47867a1ULL, 0x92722c851482353bULL,
    0x9c30d532ef924daeULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24787922797ab0fULL,
    0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL,
    0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL,
    0x8cc702081a6439ecULL, 0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL,
    0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL,
    0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL
};

void Sha512Init(Sha512Ctx* ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

void Sha512Transform(uint64_t state[8], const uint8_t block[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; ++i) {
        W[i] = (static_cast<uint64_t>(block[i * 8 + 0]) << 56) |
               (static_cast<uint64_t>(block[i * 8 + 1]) << 48) |
               (static_cast<uint64_t>(block[i * 8 + 2]) << 40) |
               (static_cast<uint64_t>(block[i * 8 + 3]) << 32) |
               (static_cast<uint64_t>(block[i * 8 + 4]) << 24) |
               (static_cast<uint64_t>(block[i * 8 + 5]) << 16) |
               (static_cast<uint64_t>(block[i * 8 + 6]) << 8) |
               (static_cast<uint64_t>(block[i * 8 + 7]));
    }
    for (int i = 16; i < 80; ++i) {
        W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
    }

    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (int i = 0; i < 80; ++i) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K512[i] + W[i];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void Sha512Update(Sha512Ctx* ctx, const uint8_t* data, size_t len) {
    size_t index = static_cast<size_t>((ctx->count[0] >> 3) & 0x7F);
    uint64_t bitLen = static_cast<uint64_t>(len) << 3;
    ctx->count[0] += bitLen;
    if (ctx->count[0] < bitLen) {
        ctx->count[1]++;
    }
    ctx->count[1] += (static_cast<uint64_t>(len) >> 61);

    size_t partLen = 128 - index;
    size_t i = 0;
    if (len >= partLen) {
        std::memcpy(&ctx->buffer[index], data, partLen);
        Sha512Transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 127 < len; i += 128) {
            Sha512Transform(ctx->state, &data[i]);
        }
        index = 0;
    }
    std::memcpy(&ctx->buffer[index], &data[i], len - i);
}

void Sha512Final(Sha512Ctx* ctx, uint8_t digest[64]) {
    uint8_t bits[16];
    for (int i = 0; i < 8; ++i) {
        bits[i] = static_cast<uint8_t>((ctx->count[1] >> ((7 - i) * 8)) & 0xFF);
        bits[8 + i] = static_cast<uint8_t>((ctx->count[0] >> ((7 - i) * 8)) & 0xFF);
    }
    size_t index = static_cast<size_t>((ctx->count[0] >> 3) & 0x7F);
    size_t padLen = (index < 112) ? (112 - index) : (240 - index);
    static const uint8_t padding[128] = { 0x80 };
    Sha512Update(ctx, padding, padLen);
    Sha512Update(ctx, bits, 16);

    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j) {
            digest[i * 8 + j] = static_cast<uint8_t>((ctx->state[i] >> ((7 - j) * 8)) & 0xFF);
        }
    }
}

void Sha512(const uint8_t* data, size_t len, uint8_t digest[64]) {
    Sha512Ctx ctx;
    Sha512Init(&ctx);
    Sha512Update(&ctx, data, len);
    Sha512Final(&ctx, digest);
}

// ============================================================================
// Curve25519 & Ed25519 Arithmetic (TweetNaCl Compatible / Standard Ref10)
// ============================================================================
using gf = int64_t[16];

const gf gf0 = {0};
const gf gf1 = {1};
const gf d = {-0x5dbc, 0x6739, 0x5b3c, 0x1d5e, -0x3f5c, -0x3c2a, 0x7292, -0x3454,
              -0x3841, 0x3d0b, -0x3344, 0x14f9, 0x6339, 0x2e06, -0x3bbd, 0x57eb};
const gf d2 = {-0x3b78, -0x318d, -0x4988, 0x3abe, -0x7eb8, -0x7854, 0x6524, -0x68a8,
               -0x7082, 0x7a16, -0x6688, 0x29f2, 0x4672, 0x5c0c, -0x777a, 0x2fd6};
const gf I = {0x450b, 0x2f60, -0x7b04, -0x296e, -0x501c, -0x5a18, 0x55d0, -0x5a1c,
              0x5396, -0x559e, 0x683c, -0x3244, 0x3d5c, 0x429e, 0x5e8c, 0x2b80};

void car25519(gf o) {
    for (int i = 0; i < 16; ++i) {
        o[i] += (1LL << 16);
        int64_t c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

void sel25519(gf p, gf q, int b) {
    int64_t c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
        int64_t t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

void pack25519(uint8_t* o, const gf n) {
    gf m, t;
    std::memcpy(t, n, sizeof(gf));
    car25519(t);
    car25519(t);
    car25519(t);
    for (int j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (int i = 1; i < 15; ++i) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        int b = static_cast<int>((m[15] >> 16) & 1);
        m[14] &= 0xffff;
        sel25519(t, m, 1 - b);
    }
    for (int i = 0; i < 16; ++i) {
        o[2 * i] = static_cast<uint8_t>(t[i] & 0xFF);
        o[2 * i + 1] = static_cast<uint8_t>((t[i] >> 8) & 0xFF);
    }
}

int par25519(const gf a) {
    uint8_t d_bytes[32];
    pack25519(d_bytes, a);
    return d_bytes[0] & 1;
}

void unpack25519(gf o, const uint8_t* n) {
    for (int i = 0; i < 16; ++i) {
        o[i] = n[2 * i] + (static_cast<int64_t>(n[2 * i + 1]) << 8);
    }
    o[15] &= 0x7fff;
}

void A(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] + b[i];
}

void Z(gf o, const gf a, const gf b) {
    for (int i = 0; i < 16; ++i) o[i] = a[i] - b[i];
}

void M(gf o, const gf a, const gf b) {
    int64_t t[31] = {0};
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (int i = 0; i < 15; ++i) {
        t[i] += 38 * t[i + 16];
    }
    for (int i = 0; i < 16; ++i) o[i] = t[i];
    car25519(o);
    car25519(o);
}

void S(gf o, const gf a) {
    M(o, a, a);
}

void inv25519(gf o, const gf i) {
    gf c;
    std::memcpy(c, i, sizeof(gf));
    for (int a = 253; a >= 0; --a) {
        S(c, c);
        if (a != 2 && a != 4) M(c, c, i);
    }
    std::memcpy(o, c, sizeof(gf));
}

int vn(const uint8_t* x, const uint8_t* y, int n) {
    uint32_t d_res = 0;
    for (int i = 0; i < n; ++i) d_res |= (x[i] ^ y[i]);
    return (1 & ((d_res - 1) >> 8)) - 1;
}

int crypto_verify_32(const uint8_t* x, const uint8_t* y) {
    return vn(x, y, 32);
}

const uint64_t L_const[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd0, 0xce, 0x52, 0x45, 0x34, 0x4c, 0x6e, 0x8b,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

void modL(uint8_t* r, int64_t x[64]) {
    for (int i = 63; i >= 32; --i) {
        int64_t carry = 0;
        for (int j = i - 32, k = i - 12; j < k; ++j) {
            x[j] += carry - 16 * x[i] * L_const[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[i - 12] += carry;
        x[i] = 0;
    }
    int64_t carry = 0;
    for (int j = 0; j < 32; ++j) {
        x[j] += carry - (x[31] >> 4) * L_const[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (int j = 0; j < 32; ++j) {
        x[j] -= carry * L_const[j];
    }
    for (int i = 0; i < 32; ++i) {
        x[i + 1] += x[i] >> 8;
        r[i] = static_cast<uint8_t>(x[i] & 255);
    }
}

void reduce(uint8_t* r) {
    int64_t x[64];
    for (int i = 0; i < 64; ++i) x[i] = static_cast<uint8_t>(r[i]);
    for (int i = 0; i < 64; ++i) r[i] = 0;
    modL(r, x);
}

void add(gf p[4], gf q[4]) {
    gf a, b, c, d_gf, t, e, f, g, h;
    Z(a, p[1], p[0]);
    Z(t, q[1], q[0]);
    M(a, a, t);
    A(b, p[1], p[0]);
    A(t, q[1], q[0]);
    M(b, b, t);
    M(c, p[3], q[3]);
    M(c, c, d2);
    M(d_gf, p[2], q[2]);
    A(d_gf, d_gf, d_gf);
    Z(e, b, a);
    Z(f, d_gf, c);
    A(g, d_gf, c);
    A(h, b, a);
    M(p[0], e, f);
    M(p[1], h, g);
    M(p[2], g, f);
    M(p[3], e, h);
}

void cswap(gf p[4], gf q[4], int b) {
    for (int i = 0; i < 4; ++i) {
        sel25519(p[i], q[i], b);
    }
}

void scalarmult(gf p[4], gf q[4], const uint8_t* s) {
    std::memcpy(p[0], gf0, sizeof(gf));
    std::memcpy(p[1], gf1, sizeof(gf));
    std::memcpy(p[2], gf1, sizeof(gf));
    std::memcpy(p[3], gf0, sizeof(gf));
    for (int i = 255; i >= 0; --i) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        cswap(p, q, b);
        add(q, p);
        add(p, p);
        cswap(p, q, b);
    }
}

void scalarbase(gf p[4], const uint8_t* s) {
    gf q[4];
    std::memcpy(q[0], gf0, sizeof(gf));
    std::memcpy(q[1], gf1, sizeof(gf));
    std::memcpy(q[2], gf1, sizeof(gf));
    std::memcpy(q[3], gf0, sizeof(gf));

    // Base point B = (x, 4/5)
    // x = 0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a
    // y = 4/5 mod 2^255-19
    static const uint8_t B_y[32] = {
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
    };
    static const uint8_t B_x[32] = {
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
        0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
        0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
        0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21
    };
    unpack25519(q[0], B_x);
    unpack25519(q[1], B_y);
    std::memcpy(q[2], gf1, sizeof(gf));
    M(q[3], q[0], q[1]);

    scalarmult(p, q, s);
}

} // namespace

bool CreateKeyPair(const uint8_t* seed, uint8_t* out_public_key, uint8_t* out_private_key) {
    if (!seed || !out_public_key || !out_private_key) return false;

    uint8_t d_hash[64];
    Sha512(seed, 32, d_hash);
    d_hash[0] &= 248;
    d_hash[31] &= 127;
    d_hash[31] |= 64;

    gf p[4];
    scalarbase(p, d_hash);

    gf invZ;
    inv25519(invZ, p[2]);
    gf x, y;
    M(x, p[0], invZ);
    M(y, p[1], invZ);
    pack25519(out_public_key, y);
    out_public_key[31] ^= (par25519(x) << 7);

    std::memcpy(out_private_key, seed, 32);
    std::memcpy(out_private_key + 32, out_public_key, 32);
    return true;
}

bool Sign(const uint8_t* private_key, size_t private_key_len,
          const uint8_t* message, size_t message_len,
          uint8_t* out_signature) {
    if (!private_key || (private_key_len != 32 && private_key_len != 64) || !out_signature) {
        return false;
    }
    const uint8_t* seed = private_key;
    uint8_t pk[32];
    if (private_key_len == 64) {
        std::memcpy(pk, private_key + 32, 32);
    } else {
        uint8_t dummy_sk[64];
        CreateKeyPair(seed, pk, dummy_sk);
    }

    uint8_t d_hash[64];
    Sha512(seed, 32, d_hash);
    d_hash[0] &= 248;
    d_hash[31] &= 127;
    d_hash[31] |= 64;

    Sha512Ctx ctx;
    Sha512Init(&ctx);
    Sha512Update(&ctx, d_hash + 32, 32);
    Sha512Update(&ctx, message, message_len);
    uint8_t r_hash[64];
    Sha512Final(&ctx, r_hash);
    reduce(r_hash);

    gf p[4];
    scalarbase(p, r_hash);

    gf invZ;
    inv25519(invZ, p[2]);
    gf x, y;
    M(x, p[0], invZ);
    M(y, p[1], invZ);
    pack25519(out_signature, y);
    out_signature[31] ^= (par25519(x) << 7);

    Sha512Init(&ctx);
    Sha512Update(&ctx, out_signature, 32);
    Sha512Update(&ctx, pk, 32);
    Sha512Update(&ctx, message, message_len);
    uint8_t h_hash[64];
    Sha512Final(&ctx, h_hash);
    reduce(h_hash);

    int64_t x_accum[64] = {0};
    for (int i = 0; i < 32; ++i) x_accum[i] = r_hash[i];
    for (int i = 0; i < 32; ++i) {
        for (int j = 0; j < 32; ++j) {
            x_accum[i + j] += static_cast<int64_t>(h_hash[i]) * static_cast<int64_t>(d_hash[j]);
        }
    }
    modL(out_signature + 32, x_accum);
    return true;
}

bool Verify(const uint8_t* public_key,
            const uint8_t* message, size_t message_len,
            const uint8_t* signature) {
    if (!public_key || !signature) return false;

    // Check S < L
    uint8_t s_copy[32];
    std::memcpy(s_copy, signature + 32, 32);
    if ((s_copy[31] & 224) != 0) return false;

    // Unpack public key A
    gf A_pt[4];
    gf y, u, v, vxx, check_v;
    unpack25519(y, public_key);
    std::memcpy(A_pt[1], y, sizeof(gf));
    std::memcpy(A_pt[2], gf1, sizeof(gf));
    S(u, y);
    M(v, u, d);
    Z(u, u, A_pt[2]);
    A(v, v, A_pt[2]);

    gf invV;
    inv25519(invV, v);
    M(A_pt[0], u, invV); // x^2 = u/v

    // Compute square root: x = (u/v)^((p+3)/8)
    gf x_cand;
    // x_cand = u * v^3 * (u * v^7)^((p-5)/8)
    gf v3, v7, uv7;
    S(v3, v); M(v3, v3, v);
    S(v7, v3); M(v7, v7, v3); M(v7, v7, v);
    M(uv7, u, v7);
    // uv7^((p-5)/8)
    gf p58;
    std::memcpy(p58, uv7, sizeof(gf));
    for (int a = 250; a >= 0; --a) {
        S(p58, p58);
        if (a != 0 && a != 2) M(p58, p58, uv7);
    }
    M(x_cand, u, v3);
    M(x_cand, x_cand, p58);

    S(vxx, x_cand);
    M(vxx, vxx, v);
    Z(check_v, vxx, u);
    if (par25519(check_v)) {
        A(check_v, vxx, u);
        if (par25519(check_v)) return false; // not on curve
        M(x_cand, x_cand, I);
    }
    if (par25519(x_cand) != (public_key[31] >> 7)) {
        Z(x_cand, gf0, x_cand);
    }
    std::memcpy(A_pt[0], x_cand, sizeof(gf));
    M(A_pt[3], A_pt[0], A_pt[1]);

    // Compute H(R, A, M)
    Sha512Ctx ctx;
    Sha512Init(&ctx);
    Sha512Update(&ctx, signature, 32);
    Sha512Update(&ctx, public_key, 32);
    Sha512Update(&ctx, message, message_len);
    uint8_t h_hash[64];
    Sha512Final(&ctx, h_hash);
    reduce(h_hash);

    // Compute R_expected = SB - HA
    gf SB[4], HA[4];
    scalarbase(SB, signature + 32);
    scalarmult(HA, A_pt, h_hash);

    // HA negate: negate x and t
    Z(HA[0], gf0, HA[0]);
    Z(HA[3], gf0, HA[3]);

    add(SB, HA); // SB + (-HA) = SB - HA

    gf invZ2;
    inv25519(invZ2, SB[2]);
    gf r_x, r_y;
    M(r_x, SB[0], invZ2);
    M(r_y, SB[1], invZ2);

    uint8_t r_packed[32];
    pack25519(r_packed, r_y);
    r_packed[31] ^= (par25519(r_x) << 7);

    return crypto_verify_32(signature, r_packed) == 0;
}

} // namespace noescape::network::ed25519
