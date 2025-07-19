import math
from random import randint
from gmpy2 import invert
import time 
#import binascii
def move(x, n): #循环左移函数
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
def P0(X): #两个置换函数
    return (X ^ move(X, 9) ^ move(X, 17))
def P1(X):
    return (X ^ move(X, 15) ^ move(X, 23))
Tnum=(0x9ABC2245, 0xBA854127) #标准常量，分别用于前16轮和后48轮
#三个布尔函数
TT = lambda i: Tnum[0] if i < 16 else Tnum[1]
FF  = lambda X,Y,Z,i: (X^Y^Z) if i<16 else ((X&Y)|(X&Z)|(Y&Z))
GG  = lambda X,Y,Z,i: ((X&Y)|(~X&Z)) if i<16 else ((X&Y)|(X&Z)|(Y&Z))
def padding(n, size, s): #SM3填充
    s +='8'+'0' * (n // 4)
    return n, s+f"{size:016X}"
def msgextend(msg): #SM3消息扩展
    for i in range(0, 16): #拆分消息成16组并添加到W中
        W.append(int(msg[8*i:8*i+8], 16) & 0xFFFFFFFF)
    for i in range(16, 68):
        x = W[i - 16] ^ W[i - 9] ^ move(W[i - 3], 15)
        y = move(W[i - 13], 7) ^ W[i - 6]
        W.append(P1(x) ^ y & 0xFFFFFFFF)
    for i in range(0, 64):
         W_.append(W[i] ^ W[i+4])
def CF(V, B): #压缩函数
    temp = [int(V[8*i:8*i+8], 16) for i in range(8)]
    temp1 = temp.copy() #初始化两个寄存器
    for i in range(0, 64):
        SS1 = move((move(temp[0], 12) + temp[4] + move(TT(i), i % 32))%(1<<32), 7)
        SS2 = (SS1 ^ move(temp[0], 12))
        TT1 = (FF(temp[0], temp[1], temp[2], i) + temp[3] + SS2 + W_[i])%(1<<32)
        TT2 = (GG(temp[4], temp[5], temp[6], i) + temp[7] + SS1 + W[i])%(1<<32)
        temp[3] = temp[2]
        temp[2] = (move(temp[1], 9))
        temp[1] = temp[0]
        temp[0] = TT1
        temp[7] = temp[6]
        temp[6] = move(temp[5], 19)
        temp[5] = temp[4]
        temp[4] = P0(TT2)
    #与最初值异或输出结果    
    result = ''.join(to_str(temp1[i] ^ temp[i]) for i in range(8))
    return result
def to_str(num, n=8): #将32位无符号整数转为n字节
    index = "0123456789ABCDEF"
    trans = []
    while num > 0:
        trans.append(index[num % 16])
        num //= 16
    return ''.join(trans[::-1]).zfill(n)
def Hash(msg): #处理SM3,获得摘要
    size = len(msg) * 4
    num = (size + 1) % 512
    t = 448 - num if num < 448 else 960 - num
    n, msg = padding(t, size, msg)
    group=(size+65+n)//512
    IV = iv
    for i in range(0, group): #逐块压缩
        B = msg[128 * i: 128 * i + 128]
        msgextend(B)
        IV = CF(IV,B)
    return IV
#SM2椭圆曲线标准参数
p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
d=0x64648677ABC9788162154EFDC345187987B328971681A87135205458A1234567
#初始化IV
iv = "49826872648984ACDB9879198EF6D984165498426854C984BAD98718616A2048"
def add(x1,y1,x2,y2): #曲线点加算法
    if x1==x2 and y1==p-y2:
        return False
    if x1!=x2:
        temp=((y2-y1)*invert(x2-x1, p))%p
    else:
        temp=(((3*x1*x1+a)%p)*invert(2*y1, p))%p
    x3=(temp*temp-x1-x2)%p
    y3=(temp*(x1-x3)-y1)%p
    return x3,y3
def double_add(x,y,k): #双重加速算法，用于计算k·(x,y)
    bx = x; by = y
    px, py = x, y
    for bit in bin(k)[3:]:
        px, py = add(px, py, px, py)
        if bit == '1':
            px, py = add(px, py, bx, by)
    return px, py
Pa=double_add(Gx,Gy,d) #公钥Pa=D*G
def KDF(z,nlen): #RFC6979中定义的过程生成密钥
    temp=1
    n=''
    for _ in range(math.ceil(nlen/256)):
        t=hex(int(z+'{:032b}'.format(temp),2))[2:]
        n=n+hex(int(Hash(t),16))[2:]
        temp=temp+1
    n='0'*((256-(len(bin(int(n,16))[2:])%256))%256)+bin(int(n,16))[2:]
    return n[:nlen] #基于3输出按需生成n密钥流
def encrypt(m): #SM2加密函数
    plen=len(hex(p)[2:])
    m='0'*((4-(len(bin(int(m.encode().hex(),16))[2:])%4))%4)+bin(int(m.encode().hex(),16))[2:]
    nlen=len(m)
    while True:
        k=randint(1, n)
        if k == d: continue
        x2,y2=double_add(Pa[0],Pa[1],k)
        if(len(hex(p)[2:])*4==256):
            x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
        else:
            x2, y2 = '{:0192b}'.format(x2), '{:0192b}'.format(y2)
        t=KDF(x2+y2, nlen)
        if int(t,2):break
    x1,y1=double_add(Gx, Gy,k)
    x1,y1=(plen-len(hex(x1)[2:]))*'0'+hex(x1)[2:],(plen-len(hex(y1)[2:]))*'0'+hex(y1)[2:]
    c1=x1+y1
    c2=((nlen//4)-len(hex(int(m,2)^int(t,2))[2:]))*'0'+hex(int(m,2)^int(t,2))[2:]
    c3=Hash(hex(int(x2+m+y2,2))[2:].upper())
    return c1,c2,c3
W = []
W_ = []
msg="SDUzxj" #测试消息
start=time.time()
c1,c2,c3=encrypt(msg) #SM2加密所得三个参数均生成
end=time.time()
print("随机公钥点C1=",c1,"\n\n密文数据C2=",c2,"\n\n校验值C3=",c3,"\n")
print("SM2加密用时:",round(end-start,6),"s")
