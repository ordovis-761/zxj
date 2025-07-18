import hashlib
def tree_build(leaves): 
    tree = []
    if len(leaves) == 0:
        return None #没有叶节点则返回空值
    if len(leaves) == 1:
        return leaves[0]
    if len(leaves)%2 == 1: #叶节点数目为奇数则添加其到表末尾
        leaves.append(leaves[-1])
    for i in range(0, len(leaves), 2):
        left = leaves[i]
        right = leaves[i + 1]
        node = hashlib.sha256(left + right).digest()
        #父节点hash为左右子节点hash拼接后的sha256值
        tree.append(node)
    return tree_build(tree) #递归构建merkle树
def doproof(index, leaves): #存在和不存在性证明函数
    proof = []
    leaf_index = index
    tree_size = len(leaves)
    while tree_size > 1:
        bro_index = leaf_index + 1 if leaf_index % 2 == 0 else leaf_index - 1
        if bro_index < tree_size:
            proof.append(leaves[bro_index])
        leaf_index = leaf_index//2
        tree_size = (tree_size+1)//2 #调整树的属性值
    return proof
def root_build(leaves): #封装函数构建merkle树
    tree = tree_build(leaves)
    return tree
#10w叶节点生成
leave=[hashlib.sha256(b"Leaf " + str(i).encode()).digest() for i in range(1, 100001)]
merkle = root_build(leave) #计算根哈希
print("Merkle树根哈希值: ",merkle.hex(),"\n")
in_index1 = 7 #存在性证明,数值在节点范围靠前位置
proof = doproof(in_index1, leave)
print("叶子节点的存在性证明1",in_index1,"节点:", [r.hex() for r in proof],"\n")
in_index2 = 761 #存在性证明,数值在节点范围内的另一位置
proof = doproof(in_index2, leave)
print("叶子节点的存在性证明2",in_index2,"节点:", [r.hex() for r in proof],"\n")
ex_index = 100007  #不存在性证明,数值超出构建的节点范围
proof = doproof(ex_index, leave)
print("叶子节点的不存在性证明",ex_index,"节点:", [r.hex() for r in proof])