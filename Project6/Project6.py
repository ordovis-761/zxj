import random, hashlib
from math import gcd
p = 2**255 - 19 #标准DH群参数
g = 5
def Hash(u, p_text): #使用SHA256代替Argon2进行模拟
    h_bytes = hashlib.sha256(f"{u}:{p_text}".encode()).digest()
    k = h_bytes[:2] #截取两字节作为k
    h_int = int.from_bytes(h_bytes, "big") % (p-1) #完成整体哈希映射到群
    h = pow(g, h_int, p)
    return k, h
username,password="zxj","123456" #模拟客户端输入
server = [ #模拟服务端存储的信息
    ("bob","123456"),
    ("alice","819682"),
    #("zxj", "123456")
]
#第一步，客户端选取秘钥skc，计算后发送盲化值(k,v)
while True:
    skc = random.randrange(1, p-1)
    if gcd(skc, p-1) == 1:
        break
k, h = Hash(username, password)
v = pow(h, skc, p)
#第二步，服务器选取秘钥 b，做二次盲化
b = random.randint(1, p-1)
v_1 = pow(v, b, p)
buckets = {} #对信息库每条(ui, pi)计算h_i^b
for ui, pi in server:
    ki, hi = Hash(ui, pi)
    wi = pow(hi, b, p)
    buckets.setdefault(ki, set()).add(wi)
#第三步，服务器返回给客户端对应集合S
S = buckets.get(k, set())
#第四步，客户端收到信息后反盲化并确认信息是否泄露
a_inv = pow(skc, -1, p-1)
h_b = pow(v_1, a_inv, p)
ifleak = (h_b in S)
intersection = [h_b] if ifleak else [] #发生泄露时返回盲化交集
print("Intersection值:", intersection)
#确认泄露状态
print(f"客户端用户名：{username}","\n信息是否泄露:",ifleak)