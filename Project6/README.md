## Project 6: Google Password Checkup协议的复现
### 实践任务
参照论文复现下述协议。
<img width="663" height="360" alt="assignment" src="https://github.com/user-attachments/assets/f83de0fb-4362-4655-8b32-5eac7ca3ffd0" />

### 原理

Google Password Checkup使用了一种检测用户名/密码对是否泄露的单一元素协议，其与集合交集加和(Private Intersection‑Sum)协议同属一个类型，二者均基于DH的盲化交互实现。该协议的主要功能为基于盲化计算生成Intersection值并返回给客户端，客户端便能以此识别出泄露的信息集合。

在本次任务中，我们在DH基础上，选用SHA-256模拟在该协议下客户端和服务端的交互流程，交互流程的数学表示为：

1、客户端随机生成私钥skc，调用算法(本实践中为SHA-256)根据自身的用户名和密码生成参数h，之后截取h中前两字节作为参数k，计算盲化值 $v=h^{a}$ 。

2、服务端收到客户端发送的(k,v)组合后，根据同样算法计算自身存储的用户信息的盲化值并构建为集合S，之后二次盲化每一个 $v_{i}$ ,即 $v_{i}=(h_{i})^{b}$ 。

3、服务端传递集合S和而二次盲化值给客户端。

4、客户端使用自身私钥skc反盲化 $h^{b}=(h^{ab})^{a^{-1}}$ ，之后检查 $h^{b}$ 是否在S中即可确认自身信息是否泄露。

### 代码思路
本实践项目选用python完成，代码文件中已进行基本的注释。

选取合适的DH参数后，我们构建加密所需的SHA-256算法，此时客户端和服务端交互所需的密码学方面算法便基本完成。之后以列表形式模拟客户端和服务端存储信息的状态。

之后便遵照流程完成四个交互部分的复现即可，其中随机私钥的选取使用python中random库的randint()和randrange()函数。

最后为便于结果的直观化，我们打印客户端信息(如果存在于服务端)的Intersection值并给出泄露状态。

### 结果分析
<img width="768" height="174" alt="true_leak" src="https://github.com/user-attachments/assets/6dcf637c-86de-4de4-b721-ad8cc266c0a4" />
<img width="756" height="147" alt="false_leak" src="https://github.com/user-attachments/assets/c4b417e5-a979-49d7-9d8b-3eb80263e28e" />
由图所示，用户可以由结果判断用户信息是否存在于服务器(用户信息是否存在在代码中以注释与否方式进行模拟)中并能判定信息是否泄露，这证明我们编写的程序能基本复现所要求复现的协议。
