import cv2 #opencv图像处理库接口
import numpy as np
def load_image(path): #图像加载函数 
    img = cv2.imread(path) #读取彩色图像
    return img
def tobits(text): #字符串转化为二进制表示，每个字符以8 bits表示
    bits = []
    for char in text:
        b = bin(ord(char))[2:].rjust(8, '0') #填充
        bits.extend([int(bit) for bit in b])
    return bits
def totext(bits): #比特串转化为字符串
    word = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break #不足8位则终止
        val = int(''.join(str(b) for b in byte), 2)
        if val == 0:
            break
        word.append(chr(val))
    return ''.join(word)
def embed_wm(img, text): #水印嵌入函数
    height, width = img.shape[:2]
    max_bits = height*width #原始图像包含比特数
    bits = tobits(text)
    length = len(bits)
    #比特串前8位存处水印长度信息
    length_bits = [int(b) for b in bin(length)[2:].rjust(8, '0')]
    full_bits = length_bits + bits #组合长度信息
    all_bits = np.pad(full_bits, (0, max_bits - len(full_bits))) #完整比特流
    b, g, r = cv2.split(img.copy()) #分离三原色通道
    flat = b.flatten()
    #设置水印比特到像素信息的低位
    flat = (flat & 0xFE) | np.array(all_bits, dtype=np.uint8)
    b1 = flat.reshape((height, width))
    return cv2.merge([b1, g, r])
def extract_wm(img,img_type=None): #水印提取函数，可以传入图像变化模式
    if img_type == 'flip_h': #处理翻转图像
        img = cv2.flip(img, 1)
    b = img[:, :, 0].flatten()
    bits = [int(bit) for bit in (b & 1)]
    length = int(''.join(str(bit) for bit in bits[:8]), 2)
    text_bits = bits[8:8+length]
    text = totext(text_bits)
    return text, bits[:length]
image=load_image('origin.png')
wm="zxj761" #嵌入的文本型水印
wm_img = embed_wm(image, wm) #水印嵌入
cv2.imwrite('watermarked.png', wm_img)
extract_res1, _ = extract_wm(wm_img) #提取水印
print(f'正常图像中的文本水印 = {extract_res1}')
wm_img_flip = cv2.flip(wm_img, 1) #翻转鲁棒性测试
cv2.imwrite('flip_wm.png', wm_img_flip) #生成图像
extract_res2, _=extract_wm(wm_img_flip, img_type='flip_h')
print(f'翻转图像中的文本水印 = {extract_res2}')
