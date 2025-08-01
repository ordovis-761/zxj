## Project 1(a): SM4的软件实现与优化
### 原理
本任务本人尝试使用T-table实现SM4的CBC模式加密的基础优化实现。SM4的加密流程大致可以概括为32轮迭代(密钥扩展)和1次反序变换，而T-table的引入可以将S-Box和线性变换合并成236项的T表，使得后续每轮原来冗杂的的计算只需一次查表和若干次异或操作即可完成。

32轮迭代流程可以分为合成置换(又可以细分为非线性变换与线性变换)和消息扩展(可细分为与系统参数异或，置换，固定CK取值)，而一次反序是将迭代最后得到的四个字进行反序赋给密文，即 

$(RES_{0},RES_{1},RES_{2},RES_{3})$ = $(X_{35},X_{34},X_{33},X_{32})$ 。
### 代码思路
由于已经有了完整的加密流程，SM4的基本实现非常简单。我们设置好标准S-Box和固定主密钥MK后，按序实现左循环移位，线性变换和非线性变换三个基本函数，之后以这三个基本函数依次构建扩展函数、加密函数(此处使用T-table加速32轮迭代)即可。

为了使得加密更具安全性，初始化向量IV采用随机生成模式，这通过random库中的mt19937 gen()函数和uniform_int_distribution<int> dist()函数实现。之后，在main函数中添加高精度计时器和CBC模式设定模块即可。
### 结果分析
由于IV随机，故每次加密的结果都不一致，此处为随机一次测试的结果，测试所用明文字符串为"SDUzxj"：
<img width="666" height="187" alt="origin-res" src="https://github.com/user-attachments/assets/42f60fb5-8235-463a-b1dd-a99397ebe734" />

## Project 1(b): SM4-GCM工作模式的软件优化实现
### 原理
Galois/Counter Mode是一种同时提认证分组加密模式。它将计数器模式(CTR)和基于伽罗氏域的多项式哈希结合起来，能够在高速软件或硬件中高效地实现。其在代码实现中的阿核心组成为CTR加密和GHASH验证。

其在加密实现中的流程可以大致概括为派生、加密、认证。
### 代码思路
代码中已有基本注释，此处对大体思路进行说明。

复用之前已经实现的含T-table的SM4软件实现的各类函数，在其基础上构建计数器模式CTR，用于在给定初始块 $J_{0}$ 的情况下异或计算 $C_{i}=P_{i} \bigoplus S_{i}, S_{i}=E_{k}(J_{i})$ 。

之后实现伽罗氏域下的多项式函数GHASH()函数，本次任务使用 $GF(2^{128})$ 的本原多项式，之后加密后赋值给子密钥，完成伽罗氏域下的乘法，最终得到结果。

最后实现一个认证函数，其对IV派生的J₀ 再次加密，与 GHASH 结果异或后得到一个认证标签，但在本次任务中由于没有实现解密，故这一项很简略。
### 结果分析
<img width="611" height="229" alt="opti-res" src="https://github.com/user-attachments/assets/1d70c34c-ac75-4ea5-a63a-a61ec58f1de1" />

由加密结果可以看到，GCM工作模式下的SM4加密速度较仅使用T-table速度有着明显提升(由于IV随机，故加密结果与普通实现中的不一致)。

