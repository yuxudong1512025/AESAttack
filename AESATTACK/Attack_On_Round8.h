#pragma once
#include"pch.h"
#include"AES.h"

class Attack_On8 :public AES {
public:

	u8 *plaintxt;
	u8 *fault_list;
	u8 *ciphertxt_list_up;
	u8 *ciphertxt_list_down;
	int countn;
	u32 trueKey;
	
	/*
	第八轮攻击主要思路：故障注入到state8的一个字节，扩展到最后是4字节
	所以要安排注入位置，这里不挑选注入位置了，固定注入位置为Sak8[0],扩散到Smod9[0,7,10,13]到C[0,7,10,13]
	所以顺序变为：
	1 生成roundn篇随机明文plaintxt   16*countn byte
	2 生成roundn个随机故障fault_list  countn byte
	3 加密进行到第8轮结束
	4 在第8轮的结束状态上增加故障i（0-255）
	5 继续完成9轮10轮加密，保留正确的密钥key(uint=4byte）
	6 将密文的[0,7,10,13]位存入密文集合ciphertxt_list countn*4 byte
		00,07,10,17,20,27,....,ncountn-0,ncountn-7;

	7 二分猜测使用组数（int）导入cuda计算预测key值，观察和正确的是否一样
	*/

};