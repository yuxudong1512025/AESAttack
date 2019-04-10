#pragma once
#include"pch.h"
#include"AES.h"
#include"guessNode.h"

using namespace std;

class Attack_On8_mega :public AES {
public:

	u8 *plaintxt;
	u8 fault;
	u8 *ciphertxt_list_up;
	u8 *ciphertxt_list_down;
	int countn;
	///answer模块数据结构//////////
	u32 trueKey;
	bool key_inlist;
	int testkeycount;

	guessNode *guess0, *guess1;
	//////////////////////////////
	/*
	第八轮攻击魔改版主要思路：令一个Sak8字节固定为e（0-255未知）
	故障扩散至对应4字节的Ciphertxt.一个固定的Sak8=一个固定的Smod9
	使用attackOn7的方法 将4字节分成（0,1）（2,3）分别求状态然后碰撞

	执行顺序：
	1 生成随机明文countn组，以及一个随机故障fault
	2 加密进行到第8轮，选定Sak8[0]=fault
	3 继续加密至第10轮结束
	4 记录第十轮结束的roundkey[0,7,10,13]构成truekey
	5 将countn组的密文ciphertxt[0,7]存入ciphertxt_list_up [10,13]存入ciphertxt_list_down
	////开始破解/////

	6 随机256*256的key组成前半边的guess0，再组成后半边的guess1  256*256*countn,一个key对应countn的结构体
	7 分别进行排序 从小到大，从第一个到第countn个
	8 两组交替遍历找到完全相同的存入guessKey
	9 检查并输出countn，guessKey列表的大小，以及trueKey是否在guessKey列表里
	10 最终结论，当countn到达多少程度的时候guesskey内仅包含trueKey

	*/  //具体见论文Attack On Round 7
//////////////以下为method////////////////////////////////////////

	Attack_On8_mega(int n, u32 trueKey, guessNode *guess0, guessNode *guess1);
	Attack_On8_mega(int n);
	Attack_On8_mega(){}
	~Attack_On8_mega();
	void set(int n, u32 trueKey, guessNode *gu0, guessNode *gu1);


	void setRandPlaintxtAndFault(u32 seed = time(NULL));
	void encryption_to8(u8 in[16], int n);
	void encryption_to10(u8 in[16], int n);
	void setguess(u8 type0, u8 type1,int mode);
	void getguessKey();
	void test();
	void initial();
};