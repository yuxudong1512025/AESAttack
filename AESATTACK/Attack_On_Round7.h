#pragma once
#include"pch.h"
#include"AES.h"
#include "guessNode.h"
#include"Attack_On_Round8_Changed.h"

class Attack_On7 :public AES {
public:

	u8 *plaintxt;
	u8 fault[4];
	vector<u8 >ciphertxt_list_up[4];
	vector<u8 >ciphertxt_list_down[4];

	int countn;
	int countM;
	vector< string >similarbitlist;

	double injectsuccess;

	guessNode *guess0[4];
	guessNode *guess1[4];

	Attack_On8_mega brench[4];

	u32 trueKey[4];
	/*
	第⑦轮攻击主要思路：同第八轮碰撞攻击改版，执行4次相同且独立的操作
	新增概率相似度u16 按位获取相似度

	执行顺序：
	1 生成随机明文countn组，以及4个随机故障fault
	2 根据组数n,判断数m,决定C(n,m)的similarbit列表
	3 加密进行到第7轮
	4 rand（）roll点决定是否需要将[0,5,10,15]设为fault
	5 继续加密至第10轮结束
	6 记录第十轮结束的roundkey[0,7,10,13]=truekey[0]
	7 将countn组的密文ciphertxt[0,7]存入ciphertxt_list_up [10,13]存入ciphertxt_list_down*4
	////开始破解/////

	6 随机256*256的key组成前半边的guess0，再组成后半边的guess1  256*256*countn,一个key对应countn的结构体
	7 分别进行排序 从小到大，从第一个到第countn个
	8 两组交替遍历找到完全相同的存入guessKey
	9 检查并输出countn，guessKey列表的大小，以及trueKey是否在guessKey列表里
	10 最终结论，当countn到达多少程度的时候guesskey内仅包含trueKey

	*/  
	//////////////以下为method////////////////////////////////////////
	Attack_On7(int n,int m,double success);//c(n,m)
	~Attack_On7();

	void dfs_findSimilarString();
	void dfs(string &a, int i, int Cnt);

	void setRandPlaintxtAndFault(u32 seed = time(NULL));
	void encryption_to7(u8 in[16], int n);
	void inject(u8 in[16]);
	void encryption_to10(u8 in[16], int n);


	void setguess(int mode,int p);
	void setbrench(string mode,int p);


	double gettestkeycount_log2();
	void test();
};