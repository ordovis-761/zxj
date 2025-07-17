#include <iostream>  
#include <vector>   
#include <iomanip>   
#include <string>   
#include <sstream>  
using namespace std;
//SM3��׼IV
const string IV = "7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e";
uint32_t to_32(const string& s) {
    return static_cast<uint32_t>(stoul(s, nullptr, 16));
}//8λhex�ַ���ת32λ�޷�������
// �� uint32_t ���Ϊ 8 λ hex�����㲹��
string to_hex8(uint32_t x) {
    stringstream ss;
    ss << hex << setw(8) << setfill('0') << (x & 0xFFFFFFFF);
    return ss.str();
}//תΪ8λhex������
uint32_t move(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}// ѭ������
uint32_t T(int j) {
    return (j <= 15)?0x79cc4519u:0x7a879d8au;
}// SM3����T
uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    if (j <= 15) return X^Y^Z;
    return (X & Y)|(X & Z)|(Y & Z);
}// ��������FF,ʹ�ô���15���ö���������
uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    if (j <= 15) return X^Y^Z;
    return (X & Y) | ((~X) & Z);
}// ��������GG��ʹ�ô���15��������ѡ��
uint32_t P0(uint32_t x) {
    return x^move(x, 9)^move(x, 17);
}
uint32_t P1(uint32_t x) {
    return x^move(x, 15)^move(x, 23);
}// �û�����P0/P1
string zero_fill(const string& hexstr, int n) {
    if ((int)hexstr.size() >= n) return hexstr;
    return string(n - hexstr.size(), '0') + hexstr;
}// �����ⳤ�ȵĶ������ַ�����4bit/hex������䵽 n λ
vector<uint32_t> extend(const string& block) {
    vector<uint32_t> W(68), W2(64);
    for (int i = 0; i < 16; i++) {
        W[i] = to_32(block.substr(8 * i, 8));
    }
    for (int j = 16; j < 68; j++) {
        uint32_t t = P1(W[j - 16] ^ W[j - 9] ^ move(W[j - 3], 15))
            ^ move(W[j - 13], 7)
            ^ W[j - 6];
        W[j] = t;
    }
    for (int j = 0; j < 64; j++) {
        W2[j] = W[j] ^ W[j + 4];
    }
    W.insert(W.end(), W2.begin(), W2.end());
    return W;
}// SM3��Ϣ��չ
string CF(const string& Vhex, const string& Bhex) {
    vector<uint32_t> V(8);
    for (int i = 0; i < 8; i++) {
        V[i] = to_32(Vhex.substr(8 * i, 8));
    } 
    vector<uint32_t> W = extend(Bhex);//��Ϣ��չ
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {//64�ֵ���
        uint32_t SS1 = move((move(A, 12) + E + move(T(j), j)) % 0x100000000u, 7);
        uint32_t SS2 = SS1 ^ move(A, 12);
        uint32_t TT1 = (FF(A, B, C, j) + D + SS2 + W[j + 68]) % 0x100000000u;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) % 0x100000000u;
        D = C;
        C = move(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = move(F, 19);
        F = E;
        E = P0(TT2);
    }
    string output; //ƴ�����
    for (int i = 0; i < 8; i++) {
        uint32_t Vi = V[i]^(i == 0 ? A : i == 1 ? B : i == 2 ? C : i == 3 ? D : i == 4 ? E : i == 5 ? F : i == 6 ? G : H);
        output += to_hex8(Vi);
    }
    return output;
}// SM3ѹ������
string SM3(const string& hexmsg) {
    string V = IV;
    int l = hexmsg.size() * 4;
    int k = ((448 - (l + 1)) % 512 + 512) % 512;
    int pad_nibbles = (k + 1) / 4;//��Ϣ���
    string m = hexmsg + "8" + string(pad_nibbles - 1, '0');
    char buf[17]; //16 λʮ����������+1��'\0'
    snprintf(buf, sizeof(buf), "%016x", l);
    m+= buf;
    int n = m.size() / 128;
    //cout << "�м�״̬��" << CF(V, hexmsg);
    for (int i = 0; i < n; i++) {
        string B = m.substr(128 * i, 128);
        V = CF(V, B);
    }
    return V;
}// SM3 ������������hex�ַ���
string SM3_lea(const string& testmsg, int num_block, const string& addmsg) {
    int l_orig = num_block * 512;
    int l2 = addmsg.size() * 4;
    int l_total = l_orig + l2;
    int k = ((448 - (l_total + 1)) % 512 + 512) % 512;
    int pad_nibbles = (k + 1) / 4;//��ͬ���
    string m2 = addmsg + "8" + string(pad_nibbles - 1, '0');
    //����α���
    char buf[17];                          
    snprintf(buf, sizeof(buf), "%016x", l_total);
    m2 += buf;
    int n = m2.size() / 128;
    string V = testmsg;
    for (int i = 0; i < n; i++) {
        string B = m2.substr(128 * i, 128);
        V = CF(V, B);
    }
    return V;
}// ������չ�����汾,����num_block(Ϊ1)���м���Ϣ
int main() {
    const int num_block = 1;
    //�ٶ���֪�м�״̬
    const string testmsg = "924039d1e63baa3ebda2ec9b11c2524950453040f9e78ecf2365b00916475e97";
    const string addmsg = "07172025";//׷����Ϣ
    string plain_ext = "7654612"+string(119,'0')+"18";//�Ϸ������512bits��
    string original_hex = plain_ext + addmsg;
    //string sm3t = SM3(plain_ext);//��ȡ�м�״̬
    string sm3_ori = SM3(original_hex);//ԭʼ��ϣֵ
    string sm3_ext = SM3_lea(testmsg, num_block, addmsg);//��չ������ϣֵ
    cout << "ԭʼ���ܹ�ϣֵ�� "<<sm3_ori<< "\n";
    cout << "��չ������ϣֵ�� "<<sm3_ext<< "\n";
    return 0;
}