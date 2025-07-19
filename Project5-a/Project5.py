from random import randint
import math
from gmpy2 import invert
import binascii
#置换函数
def P0(X):
    return (X ^ LS(X, 9) ^ LS(X, 17))
def P1(X):
    return (X ^ LS(X, 15) ^ LS(X, 23))
def LS(x, n):   #逻辑左移函数，将数值 x 逻辑左移 n 位，并返回结果。
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
def Ti(i):      #获取常量 Ti 的函数，根据传入的索引 i 返回对应的常量值。
    if i < 16:
        return T[0]
    else:
        return T[1]
def Fi(X, Y, Z, i):
    if 0 <= i <= 15:
        return (X ^ Y ^ Z)
    else:
        return ((X & Y) | (X & Z) | (Y & Z))
def Gi(X, Y, Z, i):
    if 0 <= i <= 15:
        return ((X & Y) | (~X & Z))
    else:
        return ((X & Y) | (X & Z) | (Y & Z))
def padding(n, size, s):
    s += '8'
    s += '0' * (n // 4)
    s += hex(size)[2:].zfill(16).upper()
    return n, s
def Extend(B):
    # 将 B 拆分成 16 个 32 位整数，并添加到列表 W 中
    for i in range(0, 16):
        hex_value = B[(8 * i):(8 * i) + 8]
        value = int(hex_value, 16) % (1 << 32)
        W.append(value)
    # 使用 P1 和 LS 函数对 W 进行生成额外的 52 个 32 位整数，并添加到列表 W 中
    for i in range(16, 68):
        x = W[i - 16] ^ W[i - 9] ^ LS(W[i - 3], 15)
        y = LS(W[i - 13], 7) ^ W[i - 6]
        value = int(hex(P1(x) ^ y), 16) % (1 << 32)
        W.append(value)
    # 对 W 中的元素进行异或操作生成新的 64 个 32 位整数，并添加到列表 W_ 中
    for i in range(0, 64):
        value = W[i] ^ W[i + 4]
        W_.append(value)
def unsignedint_to_str(num, k=8):
    index = "0123456789ABCDEF"
    result = []
    while num > 0:
        result.append(index[num % 16])
        num //= 16
    return ''.join(result[::-1]).zfill(k)
def update(V, Bi):
    temp = []
    temp1 = []
    for i in range(0, 8):
        t="0x"+V[8 * i: (8 * i) + 8]
        temp.append(int(t,16))
        temp1.append(temp[i])
    for i in range(0, 64):
        SS1 = LS((LS(temp[0], 12) + temp[4] + LS(Ti(i), i % 32))%(1<<32), 7)
        SS2 = (SS1 ^ LS(temp[0], 12))
        t=(Fi(temp[0], temp[1], temp[2], i)+temp[3])%((1<<32))
        TT1 = (Fi(temp[0], temp[1], temp[2], i) + temp[3] + SS2 + W_[i])%(1<<32)
        TT2 = (Gi(temp[4], temp[5], temp[6], i) + temp[7] + SS1 + W[i])%(1<<32)
        temp[3] = temp[2]
        temp[2] = (LS(temp[1], 9))
        temp[1] = temp[0]
        temp[0] = TT1
        temp[7] = temp[6]
        temp[6] = LS(temp[5], 19)
        temp[5] = temp[4]
        temp[4] = P0(TT2)
    result = ""
    for i in range(0, 8):
        result += unsignedint_to_str(temp1[i] ^ temp[i])
    return result.upper()
def Hash(m):
    size = len(m) * 4
    num = (size + 1) % 512
    t = 448 - num if num < 448 else 960 - num
    k, m = padding(t, size, m)
    group_number = (size + 65 + k) // 512
    IV = iv
    for i in range(0, group_number):
        B = m[128 * i: 128 * i + 128]
        Extend(B)
        IV = update(IV, B)
        W.clear()
        W_.clear()

    # 最终结果为更新后的初始向量 IV
    temp = IV
    return temp
p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx=0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy=0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
d=0x64648677ABC9788162154EFDC345187987B328971681A87135205458A1234567
def add(x1,y1,x2,y2):
    if x1==x2 and y1==p-y2:
        return False
    if x1!=x2:
        lamda=((y2-y1)*invert(x2-x1, p))%p
    else:
        lamda=(((3*x1*x1+a)%p)*invert(2*y1, p))%p
    x3=(lamda*lamda-x1-x2)%p
    y3=(lamda*(x1-x3)-y1)%p
    return x3,y3
def mul_add(x,y,k):
    k=bin(k)[2:]
    px,py=x,y
    for i in range(1,len(k)):
        px,py=add(px, py, px, py)
        if k[i]=='1':
            px,py=add(px, py, x, y)
    return (px,py)
#函数KDF使用了RFC6979中定义的过程来生成密钥
def KDF(z,klen):
    ct=1
    k=''
    for i in range(math.ceil(klen/256)):
        t=hex(int(z+'{:032b}'.format(ct),2))[2:]
        k=k+hex(int(Hash(t),16))[2:]
        ct=ct+1
    # 将 k 转换为二进制字符串，并在开头补充足够的零，使其长度为 256 的倍数
    k='0'*((256-(len(bin(int(k,16))[2:])%256))%256)+bin(int(k,16))[2:]
    return k[:klen]
def encrypt(m):
    plen=len(hex(p)[2:])
    m='0'*((4-(len(bin(int(m.encode().hex(),16))[2:])%4))%4)+bin(int(m.encode().hex(),16))[2:]
    klen=len(m)
    while True:
        k=0x649871687549876519874ABDFE9849AEDFA65498798235425120564AED654077
        while k==d:
            k=randint(1, n)
        x2,y2=mul_add(Pa[0],Pa[1],k)
        if(len(hex(p)[2:])*4==256):
            x2,y2='{:0256b}'.format(x2),'{:0256b}'.format(y2)
        else:
            x2, y2 = '{:0192b}'.format(x2), '{:0192b}'.format(y2)
        t=KDF(x2+y2, klen)
        if int(t,2)!=0:
            break
    x1,y1=mul_add(Gx, Gy,k)
    x1,y1=(plen-len(hex(x1)[2:]))*'0'+hex(x1)[2:],(plen-len(hex(y1)[2:]))*'0'+hex(y1)[2:]
    c1=x1+y1
    c2=((klen//4)-len(hex(int(m,2)^int(t,2))[2:]))*'0'+hex(int(m,2)^int(t,2))[2:]
    c3=Hash(hex(int(x2+m+y2,2))[2:].upper())
    return c1,c2,c3
def decrypt(c1,c2,c3):
    x1,y1=int(c1[:len(c1)//2],16),int(c1[len(c1)//2:],16)
    if pow(y1,2,p)!=(pow(x1,3,p)+a*x1+b)%p:
        return False
    x2,y2=mul_add(x1, y1, d)
    if (len(hex(p)[2:]) * 4 == 256):
        x2, y2 = '{:0256b}'.format(x2), '{:0256b}'.format(y2)
    else:
        x2, y2 = '{:0192b}'.format(x2), '{:0192b}'.format(y2)
    klen=len(c2)*4
    t=KDF(x2+y2, klen)
    if int(t,2)==0:
        return False
    m='0'*(klen-len(bin(int(c2,16)^int(t,2))[2:]))+bin(int(c2,16)^int(t,2))[2:]
    u=Hash(hex(int(x2+m+y2,2))[2:])
    if u!=c3:
        return False
    return hex(int(m,2))[2:]
iv = "49826872648984ACDB9879198EF6D984165498426854C984BAD98718616A2048"
T = (0x9ABC2245, 0xBA854127)
W = []
W_ = []
Pa=mul_add(Gx,Gy,d)
m="SDUzxj"
c1,c2,c3=encrypt(m)
print("c1=",c1,"\nc2=",c2,"\nc3=",c3)
m2=decrypt(c1,c2,c3)
m2=binascii.a2b_hex(m2)
print("解密结果：",m2)