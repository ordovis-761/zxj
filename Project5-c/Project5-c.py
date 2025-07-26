import math
import random
def mul_inv(a, m): #曲线乘法逆元计算
    if math.gcd(a, m) != 1:
        return None
    return pow(a, -1, m)
def add(m, n): #曲线点加算法，和上一个项目中的一致
    tmp = []
    if (m == 0):
        return n
    if (n == 0):
        return m #边界处理
    if (m != n):
        if (math.gcd(m[0] - n[0], p) != 1 and math.gcd(m[0] - n[0], p) != -1):
            return 0
        else: #斜率处理
            k = ((m[1] - n[1]) * mul_inv(m[0] - n[0], p)) % p
    else:
        k = ((3 * (m[0]*m[0]) + a) * mul_inv(2 * m[1], p)) % p
    x = (k*k- m[0] - n[0]) % p
    y = (k * (m[0] - x) - m[1]) % p
    tmp.append(x)
    tmp.append(y)
    return tmp
def p_mul_n(n, p): #曲线标量乘法
    if n == 1:
        return p
    tmp = p
    while (n >= 2):
        tmp = add(tmp, p)
        n = n - 1
    return tmp
def ECDSA_sign(m, n, G, d,k): #ECDSA签名算法
    R = p_mul_n(k, G)
    r = R[0] % n
    e = hash(m) #摘要采用哈希生成
    s = (mul_inv(k, n) * (e + d * r)) % n
    return r, s
def ECDSA_ver(m, n, G, r, s, P): #ECDSA签名验证算法
    e = hash(m)
    w = mul_inv(s, n) #本质为一种逆过程
    try:
        w = add(p_mul_n((e * w) % n, G), p_mul_n((r * w) % n, P))
        res = (w != 0) and (w[0] % n == r)
        return res
    except:
        print("模逆计算错误，请重试！")
def ver_no_m(e, n, G, r, s, P): #未验证m的验证算法版本，用于测验伪造签名的有效性
    w = mul_inv(s, n)
    v1 = (e * w) % n
    v2 = (r * w) % n
    w = add(p_mul_n(v1, G), p_mul_n(v2, P))
    if (w == 0):
        print('失败')
        return False
    else:
        if (w[0] % n == r):
            print('通过')
            return True
def pretend(n, G, P): #satoshi无消息签名算法
    u = random.randint(1, n - 1)
    v = random.randint(1, n - 1)
    R = add(p_mul_n(u, G), p_mul_n(v, P))[0]
    e1 = (R * u * mul_inv(v, n)) % n
    s1 = (R * mul_inv(v, n)) % n
    ver_no_m(e1, n, G, R, s1, P)
a = 2
b = 3 #两个曲线参数
p = 17 #有限域大小
G = [6, 9] #基点
n = 19 #曲线阶数
k = 3
d = 5 #模拟私钥
P = p_mul_n(d, G) #标量乘法计算公钥
m1 = 'zxj761'
m2 = "SDU2025" #测试用消息
r,s=ECDSA_sign(m1,n,G,d,k)
print("签名结果为:",r,s)
print("验证结果为",ECDSA_ver(m1, n, G, r, s, P),"\n") #签名正常验证，确保结果的有效性
print("伪装结果为：")
pretend(n,G,P) #无消息签名伪造攻击实施
