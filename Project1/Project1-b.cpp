#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include <random>
#include <windows.h>
using namespace std;
static const uint8_t Sbox[256] = { //SM4的标准S-Box
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
static const uint8_t MK[16] = { //固定的128 bits主密钥
    0x01,0x23,0x45,0x67, 0x89,0xab,0xcd,0xef,
    0xfe,0xdc,0xba,0x98, 0x76,0x54,0x32,0x10
};
static const uint32_t FK[4] = { //FK常量，用于密钥扩展混合流程
    0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
};
static const uint32_t CK[32] = { //CK常量，用于32轮加密
    0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
    0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
    0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
    0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
    0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
    0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
    0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
    0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};
static inline uint32_t move(uint32_t x, int n) { //左循环移位
    return (x << n) | (x >> (32 - n));
}
static inline uint32_t map(uint32_t n) { //线性变换
    return n ^ move(n, 2) ^ move(n, 10) ^ move(n, 18) ^ move(n, 24);
}
static uint32_t T[256]; //全局T-Table
void init_T() { //初始化T-table
    for (int i = 0; i < 256; i++) {
        uint32_t b = Sbox[i]; //合并计算，避免重复
        T[i] = map((b << 24) | (b << 16) | (b << 8) | b);
    }
}
static inline uint32_t noliner(uint32_t a) { //非线性变换
    uint8_t a0 = (a >> 24) & 0xFF, a1 = (a >> 16) & 0xFF, a2 = (a >> 8) & 0xFF, a3 = a & 0xFF;
    return (uint32_t)Sbox[a0] << 24 | (uint32_t)Sbox[a1] << 16
        | (uint32_t)Sbox[a2] << 8 | (uint32_t)Sbox[a3];
}
void expand(const uint8_t key[16], uint32_t rk[32]) { //密钥扩展
    uint32_t K[36];
    for (int i = 0; i < 4; i++) {
        K[i] = ((uint32_t)key[4 * i] << 24) | ((uint32_t)key[4 * i + 1] << 16)
            | ((uint32_t)key[4 * i + 2] << 8) | ((uint32_t)key[4 * i + 3]);
        K[i] ^= FK[i];
    }
    for (int i = 0; i < 32; i++) { //生成32轮子密钥
        uint32_t tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ CK[i];
        uint32_t buf = noliner(tmp);
        buf = buf ^ move(buf, 13) ^ move(buf, 23);
        rk[i] = K[i] ^ buf;//迭代生成rk
        K[i + 4] = rk[i];
    }
}
void encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t rk[32]) {
    uint32_t res[36]; //加密函数，输出密文
    for (int i = 0; i < 4; i++) {
        res[i] = ((uint32_t)in[4 * i] << 24) | ((uint32_t)in[4 * i + 1] << 16)
            | ((uint32_t)in[4 * i + 2] << 8) | ((uint32_t)in[4 * i + 3]);
    }
    for (int i = 0; i < 32; i++) { //使用 T-Table 加速32轮迭代
        uint32_t tmp = res[i + 1] ^ res[i + 2] ^ res[i + 3] ^ rk[i];
        res[i + 4] = res[i] ^ T[(tmp >> 24) & 0xFF]
            ^ T[(tmp >> 16) & 0xFF]
            ^ T[(tmp >> 8) & 0xFF]
            ^ T[(tmp) & 0xFF];
    }
    for (int i = 0; i < 4; i++) { //逆序输出
        uint32_t x = res[35 - i];
        out[4 * i] = (x >> 24) & 0xFF;
        out[4 * i + 1] = (x >> 16) & 0xFF;
        out[4 * i + 2] = (x >> 8) & 0xFF;
        out[4 * i + 3] = x & 0xFF;
    }
}
//128 bits类型,定义高电平和低电平
struct u128 { uint64_t high, low; };
u128 GF128_mul(const u128& X, const u128& Y) { //GF(2^128)上的乘法实现
    u128 Z{ 0,0 }; //累加计数器
    u128 V = X;
    for (int i = 0; i < 128; i++) {
        if ((Y.high >> (127 - i)) & 1) { //遍历Y
            Z.high ^= V.high;  Z.low ^= V.low;
        }
        bool lsb = V.low & 1; //右移V,低位移入高位
        V.low = (V.low >> 1) | (V.high << 63);
        V.high = (V.high >> 1);
        if (lsb) V.high ^= 0xE100000000000000ULL; //多项式 0xE1移位
    }
    return Z;
}
//GCM工作模式下的HASH
u128 GHASH(const u128& H, const vector<uint8_t>& data) {
    u128 Y{ 0,0 };
    size_t cknum = data.size() / 16;
    for (size_t i = 0; i < cknum; i++) {
        //读取128 bits的X
        u128 X{ 0,0 };
        const uint8_t* ptr = data.data() + i * 16;
        for (int j = 0; j < 8; j++) X.high = (X.high << 8) | ptr[j];
        for (int j = 0; j < 8; j++) X.low = (X.low << 8) | ptr[8 + j];
        //异或得到结果并输出
        Y.high ^= X.high;  Y.low ^= X.low;
        Y = GF128_mul(Y, H);
    }
    return Y;
}
//对低32位加1操作
void count32(uint8_t counter[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++counter[i] != 0) 
            break;
    }
}
///  - rk[32]: 子密钥
///  - IV: 初始向量（任意长度 >0）
///  - plaintext: 待加密明文
///  - ciphertext, res: 输出
void GCM( const uint32_t rk[32],const vector<uint8_t>& IV,const vector<uint8_t>& plaintext,vector<uint8_t>& ciphertext,
    uint8_t res[16]) //GCM模式加密主体
{
    uint8_t zero_blk[16] = { 0 },H_blk[16]; //两个全零缓冲区
    encrypt(zero_blk, H_blk, rk); //rk为子密钥
    u128 H{ 0,0 }; //便于后续划分H
    for (int i = 0; i < 8; i++)
    { //前8字节封装成高位
        H.high = (H.high << 8) | H_blk[i];
    }
    for (int i = 0; i < 8; i++)
    {  //后8字节封装成低位
        H.low = (H.low << 8) | H_blk[8 + i];
    }
    vector<uint8_t> count(16, 0); //初始计数块
    if (IV.size() == 12) { //处理IV的特殊情况
        memcpy(count.data(), IV.data(), 12);
        count[15] = 1;
    }
    else {
        vector<uint8_t> tmp = IV;
        size_t rem = tmp.size() % 16;
        if (rem) tmp.insert(tmp.end(), 16 - rem, 0);
        uint64_t iv_bits = (uint64_t)IV.size() * 8;
        for (int i = 0; i < 8; i++) tmp.push_back(0);
        for (int i = 0; i < 8; i++) tmp.push_back((iv_bits >> (56 - 8 * i)) & 0xFF);
        u128 res = GHASH(H, tmp); //对tmp进行计算得到中间值
        for (int i = 0; i < 8; i++) count[i] = (res.high >> (56 - 8 * i)) & 0xFF;
        for (int i = 0; i < 8; i++) count[8 + i] = (res.low >> (56 - 8 * i)) & 0xFF;
    }
    //CTR模式加密明文
    size_t n = plaintext.size(); //明文长度
    ciphertext.resize(n); //调整密文大小存放输出
    uint8_t CTR[16];
    memcpy(CTR, count.data(), 16);
    count32(CTR); 
    for (size_t off = 0; off < n; off += 16) {
        uint8_t S[16];
        encrypt(CTR, S, rk);
        size_t blk = min<size_t>(16, n - off);
        for (size_t i = 0; i < blk; i++)
            ciphertext[off + i] = plaintext[off + i] ^ S[i];
        count32(CTR); //计数器加1进入下一块
    }
    vector<uint8_t> tmp;
    tmp.insert(tmp.end(), ciphertext.begin(), ciphertext.end()); //拷贝密文部分
    if (ciphertext.size() % 16) //填充密文
        tmp.insert(tmp.end(), 16 - (ciphertext.size() % 16), 0);
    for (int i = 0; i < 8; i++) tmp.push_back(0);
    uint64_t c_bits = (uint64_t)ciphertext.size() * 8;
    for (int i = 0; i < 8; i++) //计算GHASH
        tmp.push_back((c_bits >> (56 - 8 * i)) & 0xFF);
    u128 S_res = GHASH(H, tmp);
    uint8_t E_count[16]; //认证标签生成
    encrypt(count.data(), E_count, rk);
    for (int i = 0; i < 16; i++) {
        res[i] = E_count[i] ^ (
            (i < 8) ? ((S_res.high >> (56 - 8 * i)) & 0xFF)
            : ((S_res.low >> (120 - 8 * i)) & 0xFF)
            );
    }
}
int main() {
    init_T();
    uint32_t rk[32]; //初始化子密钥
    expand(MK, rk);
    // 随机 IV（12 字节更推荐）
    vector<uint8_t> IV(12);
    random_device rd; mt19937 g(rd());
    uniform_int_distribution<int> d(0, 255);
    for (auto& b : IV) b = d(g);
    string s = "SDUzxj"; //测试明文
    vector<uint8_t> pt(s.begin(), s.end()), ct, res(16);
    LARGE_INTEGER Freq; //API高精度计时器，微秒级
    LARGE_INTEGER Start;
    LARGE_INTEGER End;
    QueryPerformanceFrequency(&Freq);
    QueryPerformanceCounter(&Start);
    GCM(rk, IV, pt, ct, res.data()); //传入参数
    QueryPerformanceCounter(&End);
    double time = (((End.QuadPart - Start.QuadPart) * 10.0) / Freq.QuadPart);
    cout << "测试明文：" << s << endl;
    cout << "GCM模式加密用时:" << time << "ms" << endl;
    cout << "加密结果为：";
    for (auto b : res)
    { //拷贝结果并用十六进制流输出
        cout << hex << setw(2) << setfill('0') << (int)b;
    }
    cout << endl;
    return 0;
}