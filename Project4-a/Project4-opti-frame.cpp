#include <iostream>
#include <cstring>
#include <immintrin.h>
#include <iomanip> //流操作库
#include <windows.h>
#include <cinttypes>
using namespace std;
//本代码仅按照大体的SIMD指令集优化思路进行了实现，加密结果并不正确，故没有加密部分的结果验证
uint32_t T[64]; //全局化常量表T
void sm3_iter4(const uint8_t* data[4], uint32_t h[4][8]) 
{
    auto moE = [](uint32_t x, size_t i)
        {return  (x >> (32 - i)) | (x << i); }; //左循环移位
    alignas(32) uint32_t W[4][68];
    alignas(32) uint32_t W1[4][64]; //初始化W和W1
    for(size_t i = 0; i < 16; ++i)
    {
        T[i] = 0x79CC4519;
    }
    for(size_t i = 16; i < 64; ++i)
    {
        T[i] = 0x7A879D8A;//常量初始化
    }
    // 扩展每条消息
    for(int j = 0; j < 4; j++) //消息扩展，但是四次并行
    {
        for(int i = 0; i < 16; i++) //分组
        {
            const uint8_t* tmp = data[j] + i * 4;
            W[j][i] = (tmp[0] << 24) | (tmp[1] << 16) | (tmp[2] << 8) | tmp[3];
        }
        for(int i = 16; i < 68; i++) //消息扩展组件
        {
            uint32_t x = W[j][i - 16] ^ W[j][i - 9] ^ moE(W[j][i - 3], 15);
            x ^= moE(x, 15) ^ moE(x, 23); 
            W[j][i] = x ^ moE(W[j][i - 13], 7) ^ W[j][i - 6];
        }
        for(int i = 0; i < 64; i++) //处理分组
        {
            W1[j][i] = W[j][i] ^ W[j][i + 4];
        }
    }
    //把四条流的IV装入向量寄存器,初始化寄存器
    __m256i A = _mm256_setr_epi32(h[0][0], h[1][0], h[2][0], h[3][0], 0, 0, 0, 0);
    __m256i B = _mm256_setr_epi32(h[0][1], h[1][1], h[2][1], h[3][1], 0, 0, 0, 0);
    __m256i C = _mm256_setr_epi32(h[0][2], h[1][2], h[2][2], h[3][2], 0, 0, 0, 0);
    __m256i D = _mm256_setr_epi32(h[0][3], h[1][3], h[2][3], h[3][3], 0, 0, 0, 0);
    __m256i E = _mm256_setr_epi32(h[0][4], h[1][4], h[2][4], h[3][4], 0, 0, 0, 0);
    __m256i F = _mm256_setr_epi32(h[0][5], h[1][5], h[2][5], h[3][5], 0, 0, 0, 0);
    __m256i G = _mm256_setr_epi32(h[0][6], h[1][6], h[2][6], h[3][6], 0, 0, 0, 0);
    __m256i H = _mm256_setr_epi32(h[0][7], h[1][7], h[2][7], h[3][7], 0, 0, 0, 0);
    for(int i = 0; i< 64; i++) { //并行原先的64轮压缩
        __m256i vT = _mm256_set1_epi32(T[i]); //将T广播到每个lane中
        __m256i index = _mm256_setr_epi32(
            i+ 0 * 64,
            i+ 1 * 64,
            i+ 2 * 64,
            i+ 3 * 64,
            0, 0, 0, 0
        ); //索引向量，用于从W和W1中提取四条消息对应的字
        __m256i vW = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(W[0]),
            index,
            4
        );
        __m256i vW1 = _mm256_i32gather_epi32(
            reinterpret_cast<const int*>(W1[0]),
            index,
            4
        ); //按索引取出消息字
        // 3.4) 计算 SS1/SS2
        __m256i A_move = _mm256_or_si256(_mm256_slli_epi32(A, 12),
            _mm256_srli_epi32(A, 20)); //对A做移位操作
        __m256i tmp = _mm256_add_epi32(_mm256_add_epi32(A_move, E), vT);
        __m256i SS1 = _mm256_or_si256(_mm256_slli_epi32(tmp, 7),
            _mm256_srli_epi32(tmp, 25));
        __m256i SS2 = _mm256_xor_si256(SS1, A_move); //计算原先的SS1和SS2
        __m256i FF = (i< 16 ? _mm256_xor_si256(_mm256_xor_si256(A, B), C): _mm256_or_si256(
                _mm256_or_si256(_mm256_and_si256(A, B), _mm256_and_si256(B, C)),
                _mm256_and_si256(A, C)
            ));
        __m256i GG = (i< 16? _mm256_xor_si256(_mm256_xor_si256(E, F), G): _mm256_or_si256(
                _mm256_and_si256(E, F),
                _mm256_andnot_si256(E, G)
            )); //构造并计算FF/GG
        //TT1/TT2计算
        __m256i TT1 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(FF, D), SS2), vW1);
        __m256i TT2 = _mm256_add_epi32(_mm256_add_epi32(_mm256_add_epi32(GG, H), SS1), vW);
        //更新 A~H寄存器
        __m256i Dnew = C;
        __m256i Cnew = _mm256_or_si256(_mm256_slli_epi32(B, 9),_mm256_srli_epi32(B, 23));
        __m256i Bnew = A;__m256i Anew = TT1;__m256i Hnew = G;
        __m256i Gnew = _mm256_or_si256(_mm256_slli_epi32(F, 19),_mm256_srli_epi32(F, 13));
        __m256i Fnew = E;
        __m256i t1 = _mm256_or_si256(_mm256_slli_epi32(TT2, 9),_mm256_srli_epi32(TT2, 23));
        __m256i t2 = _mm256_or_si256(_mm256_slli_epi32(TT2, 17),_mm256_srli_epi32(TT2, 15));
        __m256i Enew = _mm256_xor_si256(_mm256_xor_si256(TT2, t1), t2);
        A = Anew;  B = Bnew;  C = Cnew;  D = Dnew;
        E = Enew;  F = Fnew;  G = Gnew;  H = Hnew;
    }
    __m256i set[8] = { A, B, C, D, E, F, G, H }; //寄存器集合
    //双层循环更新h[n][m]
    h[0][0] ^= _mm256_extract_epi32(set[0], 0);
    h[1][0] ^= _mm256_extract_epi32(set[0], 1);
    h[2][0] ^= _mm256_extract_epi32(set[0], 2);
    h[3][0] ^= _mm256_extract_epi32(set[0], 3);
    alignas(32) uint32_t tmp[8];
    for (int j = 0; j < 8; ++j) 
    { //指令集不允许变量表达式，故单独计算h后写入
        _mm256_store_si256(reinterpret_cast<__m256i*>(tmp), set[j]);
        for (int i = 0; i < 4; ++i) 
        {
            h[i][j] ^= tmp[i];
        }
    }
    cout << "sm3_iter4()函数运行正常" << endl;
}
void sm3(const void* data, size_t len, uint8_t* hash) 
{
    const uint8_t* data_ = static_cast<const uint8_t*>(data);
    constexpr size_t size = 64;
    uint32_t h[8] = { //初始化IV
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    //处理整块,和实现时差不多
    size_t nums = len / size;
    for(size_t i = 0; i < nums; ++i) {
        const uint8_t* lane = data_ + i * size;
        //复制到4条流
        const uint8_t* tmp[4] = { lane,lane,lane,lane  };
        //初始化h
        uint32_t h4[4][8];
        for(int i = 0; i < 4; ++i) {
            memcpy(h4[i], h, sizeof(h));
        }
        sm3_iter4(tmp, h4);
        // 取第 0 条结果回写到 h
        memcpy(h, h4[0], sizeof(h));
    }
    //处理不足一整块的数据
    uint8_t buf[size];
    size_t num = len % size;
    memcpy(buf, data_ + nums * size, num);
    buf[num] = 0x80;
    num++;
    if (num == size) { //刚好填满一块，直接处理
        const uint8_t* tmp[4] = { buf, buf, buf, buf};
        uint32_t h4[4][8];
        for (int m = 0; m < 4; ++m)
        {
            memcpy(h4[m], h, sizeof(h));
        }
        sm3_iter4(tmp,h4);
        memcpy(h, h4[0], sizeof(h));
        num = 0;
    }
    //填充0x00，直到剩余 8 字节用于写长度
    while (num < size - 8) {
        buf[num] = 0x00;
        num++;
    }
    uint64_t bitlen = len * 8;
    for(int i = 7; i >= 0; --i) 
    {
        buf[num] = static_cast<uint8_t>(bitlen >> (i * 8));
        num++;
    }
    if(num==size) //处理最后一块
    {
        const uint8_t* tmp[4] = { buf, buf, buf, buf };
        uint32_t h4[4][8];
        for (int m = 0; m < 4; ++m) memcpy(h4[m], h, sizeof(h));
        sm3_iter4(tmp, h4);
        memcpy(h, h4[0], sizeof(h));
    }
    for(int i = 0; i < 8; ++i) { //四个流同时输出
        hash[i * 4 + 0] = static_cast<uint8_t>(h[i] >> 24);
        hash[i * 4 + 1] = static_cast<uint8_t>(h[i] >> 16);
        hash[i * 4 + 2] = static_cast<uint8_t>(h[i] >> 8);
        hash[i * 4 + 3] = static_cast<uint8_t>(h[i]);
    }
    cout << "sm3()函数运行正常" << endl;
}
int main()
{
    uint8_t hash[32];//用于存放结果
    string message = "SDUzxj";//设定的测试加密内容
    LARGE_INTEGER Freq;
    LARGE_INTEGER Start;
    LARGE_INTEGER End;
    QueryPerformanceFrequency(&Freq);//微秒级计时
    QueryPerformanceCounter(&Start);
    sm3(message.data(), message.length(), hash);
    QueryPerformanceCounter(&End);
    double time = (((End.QuadPart - Start.QuadPart)*1.0) / Freq.QuadPart);
    cout << "加密用时:" << time << "ms" << endl;
    cout << "\n";
    return 0;
}
