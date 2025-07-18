## Project 4(c): 基于RFC6962构建Merkle树并构建叶子的存在性和不存在性证明 
### 实践原理
Merkle树是一种哈希树的数据结构，用于验证和确保大型数据集中的数据的完整性。它是由计算机科学家Ralph Merkle在1979年首次提出的。RFC6962定义了一种特定类型的Merkle树，称为"Certificate Transparency"（CT）Merkle树。 RFC6962旨在解决数字证书领域中的安全问题，例如SSL/TLS证书的伪造和滥用。CT Merkle树通过将数字证书存储在一个可公开和公证的日志中来增强证书的透明度和可验证性。
