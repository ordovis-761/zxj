import math
from math import gcd
import hashlib
def generate(m, n): #从m生成一个椭圆曲线签名所需的整数e
    tmp = hashlib.sha256(m.encode()).digest()
    return int.from_bytes(tmp, 'big') % n
def mul_inv(a, m): #计算a在模m下的乘法逆元
    if math.gcd(a, m) != 1:
        return None
    return pow(a, -1, m)
def add(m, n): #曲线上的点加算法
    temp = []
    if (m == 0):
        return n
    if (n == 0):
        return m
    if (m != n):
        if (math.gcd(m[0]-n[0],p)!= 1 and math.gcd(m[0]-n[0],p)!= -1):
            return 0
        else:
            k = ((m[1] - n[1]) * mul_inv(m[0] - n[0], p))%p
    else: #斜率处理
        k = ((3*(m[0]*m[0])+a)*mul_inv(2*m[1], p))%p
    x = (k ** 2 - m[0] - n[0]) % p
    y = (k * (m[0] - x) - m[1]) % p
    temp.append(x)
    temp.append(y)
    return temp
def p_mul_n(n, p): #椭圆曲线标量乘法
    if n == 1:
        return p
    temp = p
    while (n >= 2):
        temp = add(temp, p)
        n = n - 1
    return temp
def ECDSA_sign(n,G,d,k,e): #ECDSA签名生成
    R = p_mul_n(k, G) #临时公钥R=k*G
    r = R[0] % n
    s = (mul_inv(k, n) * (e + d * r)) % n
    return r,s
def SCHN_sign(m, n, G, d,k): #Schnorr签名生成
    r = p_mul_n(k, G) #临时公钥计算
    e = hash(str(r[0]) + m) #挑战值计算
    s = (k + e * d) % n #签名计算
    return r,s,e
if __name__ == '__main__':
    #因为只是验证，所以参数尽可能小地选取
    a = 5
    b = 7
    p = 9
    G = [5, 1]
    n = 11
    k = 2 #选取小素数用于验证
    d1 = 3
    d2 = 5
    P = p_mul_n(d1, G)
    m1 = 'zxj761'
    m2 = "123456"
    e1 = generate(m1, n)
    e2 = generate(m2, n)

    print("测试信息公示：d1=",d1,"d2=",d2,"m1=",m1,"m2=",m2,"\n")
    print("一.泄露k会导致泄露d1：")
    r1,s1=ECDSA_sign(n,G,d1,k,e1)
    d_fir = (mul_inv(r1,n)*(k*s1-e1))%n
    if (d1 == d_fir):
        print("d1=",d1,"\nk=",k)
        print("验证成功\n")
    print("二.重用k会导致泄露d1：")
    r21,s21=ECDSA_sign(n,G,d1,k,e1)
    r22,s22=ECDSA_sign(n,G,d1,k,e2)
    inv = mul_inv((s21 - s22), n)
    k_sec = ( (e1 - e2) * inv ) % n
    d_sec = ( mul_inv(r1, n) * (k_sec * s1 - e1) ) % n
    if (d1 == d_sec):
        print("d1=",d1,"\nk=",k_sec)
        print("验证成功\n")
    print("三.两用户利用k，推测彼此私钥d：")
    r31,s31=ECDSA_sign(n,G,d1,k,e1)
    r32,s32=ECDSA_sign(n,G,d2,k,e2)
    inv  = mul_inv(s31 - s32, n)
    if inv!=None:
        k_thr = ((e1 - e2) * inv)%n
        d1_thr = (mul_inv(r31, n) * (k_thr * s31 - e1)) % n #恢复d1和d2
        d2_thr = (mul_inv(r32, n) * (k_thr * s32 - e2)) % n
    if (d1_thr==d2_thr):
        print("d1=",d1,"\nd2=",d2)
        print("验证成功\n")
    print("四.ECds1签名使用相同的d和k会导致泄露d1：")
    r41,s41 = ECDSA_sign(n,G,d1,k,e1)
    r42,s42,e2 = SCHN_sign(m1,n,G,d1,k)
    d_for = ((s42 * s41 - e1) * mul_inv((r41 + e2 * s41), n)) % n
    print("d1=",d1,"\nk=",k)
    if (d1 == d_for):
        print("验证成功\n")