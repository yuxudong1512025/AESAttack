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
	///answerģ�����ݽṹ//////////
	u32 trueKey;
	bool key_inlist;
	int testkeycount;

	guessNode *guess0, *guess1;
	//////////////////////////////
	/*
	�ڰ��ֹ���ħ�İ���Ҫ˼·����һ��Sak8�ֽڹ̶�Ϊe��0-255δ֪��
	������ɢ����Ӧ4�ֽڵ�Ciphertxt.һ���̶���Sak8=һ���̶���Smod9
	ʹ��attackOn7�ķ��� ��4�ֽڷֳɣ�0,1����2,3���ֱ���״̬Ȼ����ײ

	ִ��˳��
	1 �����������countn�飬�Լ�һ���������fault
	2 ���ܽ��е���8�֣�ѡ��Sak8[0]=fault
	3 ������������10�ֽ���
	4 ��¼��ʮ�ֽ�����roundkey[0,7,10,13]����truekey
	5 ��countn�������ciphertxt[0,7]����ciphertxt_list_up [10,13]����ciphertxt_list_down
	////��ʼ�ƽ�/////

	6 ���256*256��key���ǰ��ߵ�guess0������ɺ��ߵ�guess1  256*256*countn,һ��key��Ӧcountn�Ľṹ��
	7 �ֱ�������� ��С���󣬴ӵ�һ������countn��
	8 ���齻������ҵ���ȫ��ͬ�Ĵ���guessKey
	9 ��鲢���countn��guessKey�б�Ĵ�С���Լ�trueKey�Ƿ���guessKey�б���
	10 ���ս��ۣ���countn������ٳ̶ȵ�ʱ��guesskey�ڽ�����trueKey

	*/  //���������Attack On Round 7
//////////////����Ϊmethod////////////////////////////////////////

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