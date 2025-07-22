#include <iostream>
#include <cstring>
#include <iomanip> //流操作库
#include <windows.h>
#include <cinttypes>
uint32_t T[64]; //全局化常量表T
using namespace std;
void sm3_iter(const uint8_t* data, uint32_t h[]) { //SM3迭代函数
    auto move =[](uint32_t x, size_t i)
        {return  (x >> (32 - i)) | (x << i);}; //左循环移位
    for (size_t i = 0; i < 16; ++i)
    {
        T[i] = 0x79CC4519;
    }
    for (size_t i = 16; i < 64; ++i)
    {
        T[i] = 0x7A879D8A;//常量初始化
    }
    uint32_t W[68]; //字节分组
    for (size_t i = 0; i < 16; ++i) {
        W[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16)
            | (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    } //512 bits消息块分为16×32 bits
    for (size_t i = 16; i < 68; ++i) { //SM3消息扩展组件
        uint32_t tmp = W[i - 16] ^ W[i - 9] ^ move(W[i - 3], 15);
        tmp = tmp ^ move(tmp, 15) ^ move(tmp, 23);
        W[i] = tmp ^ move(W[i - 13], 7) ^ W[i - 6];
    }
    uint32_t W1[64]; //处理分组
    for (size_t i = 0; i < 64; ++i) { W1[i] = W[i] ^ W[i + 4]; }
    //寄存器初始化
    uint32_t A = h[0], B = h[1], C = h[2], D = h[3];
    uint32_t E = h[4], F = h[5], G = h[6], H = h[7];
    for (size_t i = 0; i < 16; ++i) { //前16轮压缩
        uint32_t SS1 = move(move(A, 12) + E + move(T[i], i), 7);
        uint32_t SS2 = SS1 ^ move(A, 12);
        uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[i];
        uint32_t TT2 = (E ^ F ^ G) + H + SS1 + W[i];
        D = C; C = move(B, 9); B = A; A = TT1;
        H = G; G = move(F, 19); F = E; E = TT2 ^ move(TT2, 9) ^ move(TT2, 17);
    }
    for (size_t i = 16; i < 64; ++i) {//后48轮压缩
        uint32_t SS1 = move(move(A, 12) + E + move(T[i], i), 7);
        uint32_t SS2 = SS1 ^ move(A, 12);
        uint32_t TT1 = ((A & B) | (B & C) | (A & C)) + D + SS2 + W1[i];
        uint32_t TT2 = ((E & F) | ((~E) & G)) + H + SS1 + W[i];
        D = C; C = move(B, 9); B = A; A = TT1;
        H = G; G = move(F, 19); F = E; E = TT2 ^ move(TT2, 9) ^ move(TT2, 17);
    }
    //压缩结果与输入状态异或，更新中间状态
    h[0] ^= A; h[1] ^= B; h[2] ^= C; h[3] ^= D;
    h[4] ^= E; h[5] ^= F; h[6] ^= G; h[7] ^= H; 
}
void sm3(const void* data, size_t len, uint8_t* hash) //hash加密函数
{
    const uint8_t* tmp = static_cast<const uint8_t*>(data);
    constexpr size_t size = 64; //定义块大小
    uint32_t IV[8] = { //初始化IV
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
    size_t nums = len / size; //计算块数量
    for (size_t i = 0; i < nums; ++i) {
        sm3_iter(tmp + i * size, IV);
    }
    uint8_t buf[size]; //初始化一个缓冲区
    size_t num = len % size; //处理不足一块大小的数据
    memcpy(buf, tmp + nums * size, num) ;//复制剩余数据
    buf[num] = 0x80;
    num++;
    while (num == size) { //刚好够一块则进行压缩
        sm3_iter(buf, IV);
        num = 0;
        continue;
    }
    while (num<size-8) {
        buf[num] = 0x00; //填充0x00
        num++;
        if (num == size) {
            sm3_iter(buf, IV);
            num = 0;
        }
    }
    uint64_t last = len*8; //写入最后8个字节
    for (int i = 0; i <= 7; i++) {
        buf[num] = uint8_t(last >> ((7-i) * 8));
        num++;
    }
    sm3_iter(buf, IV); //压缩剩下的块
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = uint8_t(IV[i] >> 24);
        hash[i * 4 + 1] = uint8_t(IV[i] >> 16);
        hash[i * 4 + 2] = uint8_t(IV[i] >> 8);
        hash[i * 4 + 3] = uint8_t(IV[i]);
    }
}
int main()
{
    uint8_t result[32];//用于存放结果
    string message = "SDUzxj";//设定的测试加密内容
    LARGE_INTEGER Freq; //API高精度计时器，微秒级
    LARGE_INTEGER Start;
    LARGE_INTEGER End;
    QueryPerformanceFrequency(&Freq);
    QueryPerformanceCounter(&Start);
    sm3(message.data(), message.length(), result); //计算SM3哈希摘要
    QueryPerformanceCounter(&End);
    double time = (((End.QuadPart - Start.QuadPart) * 1000.0) / Freq.QuadPart);
    cout << "加密结果：" << hex << setfill('0');//切换至十六进制输出流
    for (int i = 0; i < 32; i++) 
    {
        cout << setw(2) << (static_cast<int>(result[i]) & 0xFF);//打印结果
    }
    cout <<"\n";
    cout <<"加密用时:"<<time<<"ms"<<endl;
    return 0;
}