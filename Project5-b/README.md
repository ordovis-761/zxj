## Project 5(b): 关于签名算法误用的poc验证
本人对第一、二、三、七项进行了验证，其内容分别为 (1)泄露k会导致泄露密钥d (2)重用k会导致泄露密钥d (3)两用户利用k，推测彼此私钥d (4)ECDSA签名和Schnor签名使用相同的d和k会导致泄露密钥d

下面给出四个签名误用的数学原理推导。

### 数学推导
#### (一)泄露k会导致泄露d
ECDSA签名对(m,r,s)有 $r=(k \cdot G)_{x} \mod n$ , $s=k^{-1}(e+dr) \mod n$ ;如果计算 $e=Hash(m)$ ,攻击者知晓了k，则有

$s=k^{-1}(e+dr) \Rightarrow e+dr=ks \Rightarrow d=r^{-1}(ks-e)$

由此可由k计算出对应d
#### (二)重用k会导致泄露d
假设对两条消息m1和m2用同一k进行签名，即 $s_{1}=k^{-1}(e_{1}+dr)$ , $s_{2}=k^{-1}(e_{2}+dr)$

两式相减可以得到 $k= \frac {e_{1}-e_{2}}{s_{1}-s_{2}}$ ；代入到原式即有 $d= \frac {s_{1}k-e_{1}}{r}$

由此，重用k将使得攻击者可以计算出d
#### (三)两用户共用同一个k使得其彼此可以互相推算私钥
假设用户A和B分别持有私钥d1,d2以及消息m1,m2，我们有签名信息 $s_{1}=k^{-1}(e_{1}+d_{1}r)$ 和 $s_{2}=k^{-1}(e_{2}+d_{2}r)$

两边同乘k并相减，得到 $(s_{1}-s_{2})k=(e_{1}-e_{2})+(d_{a}-d_{2})r$

进而可以 得到d1和d2的关系 $d_{1}-d_{2}=[(s_{1}-s_{2})k-(e_{1}-e_{2})]r^{-1}$

之后根据自身的d就能推测出对方的d

#### (四)同一对(d,k)在两种算法中混用导致d泄露
本实践以ECDSA和SCHNORR为例，在ECDSA中有 $s_{E}=k^{-1}(e+dr)$ ,在SCHNORR中有 $s_{S}=k+e^{s}d$

由于 $r,s_{E},s_{S}$ 已知，故可以推导出

$e+dr=(s_{S}-e^{s}d)s_{E} \Rightarrow d(r+e^{s}s_{E})=s_{S}s_{E}-e \Rightarrow d= \frac {s_{S}s_{E}-e}{r+e_{s}s_{E}}$
### 结果分析
使用python中hashlib库以及math库，我们按照上述数学推导进行复现即可证明四个签名误用造成的密钥泄露现象均存在：
<img width="794" height="594" alt="result" src="https://github.com/user-attachments/assets/4b4ca1bf-3f60-4ef6-8c3a-e2a008a9608e" />


