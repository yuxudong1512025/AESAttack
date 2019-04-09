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
	�ڢ��ֹ�����Ҫ˼·��ͬ�ڰ�����ײ�����İ棬ִ��4����ͬ�Ҷ����Ĳ���
	�����������ƶ�u16 ��λ��ȡ���ƶ�

	ִ��˳��
	1 �����������countn�飬�Լ�4���������fault
	2 ��������n,�ж���m,����C(n,m)��similarbit�б�
	3 ���ܽ��е���7��
	4 rand����roll������Ƿ���Ҫ��[0,5,10,15]��Ϊfault
	5 ������������10�ֽ���
	6 ��¼��ʮ�ֽ�����roundkey[0,7,10,13]=truekey[0]
	7 ��countn�������ciphertxt[0,7]����ciphertxt_list_up [10,13]����ciphertxt_list_down*4
	////��ʼ�ƽ�/////

	6 ���256*256��key���ǰ��ߵ�guess0������ɺ��ߵ�guess1  256*256*countn,һ��key��Ӧcountn�Ľṹ��
	7 �ֱ�������� ��С���󣬴ӵ�һ������countn��
	8 ���齻������ҵ���ȫ��ͬ�Ĵ���guessKey
	9 ��鲢���countn��guessKey�б�Ĵ�С���Լ�trueKey�Ƿ���guessKey�б���
	10 ���ս��ۣ���countn������ٳ̶ȵ�ʱ��guesskey�ڽ�����trueKey

	*/  
	//////////////����Ϊmethod////////////////////////////////////////
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