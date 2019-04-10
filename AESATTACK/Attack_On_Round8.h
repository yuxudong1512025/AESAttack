#pragma once
#include"pch.h"
#include"AES.h"

extern "C"
u32 getKey(u8*ciphertxt0, u8*ciphertxt1, int Countn, const u32 &trueKey);

class Attack_On8 :public AES {
public:

	u8 *plaintxt;
	int faultmode;
//	u8 *fault_list;
	u8 *ciphertxt_list_up;
	u8 *ciphertxt_list_down;
	int countn;
	u32 trueKey;
	
	/*
	�ڰ��ֹ�����Ҫ˼·������ע�뵽state8��һ���ֽڣ���չ�������4�ֽ�
	����Ҫ����ע��λ�ã����ﲻ��ѡע��λ���ˣ��̶�ע��λ��ΪSak8[0],��ɢ��Smod9[0,7,10,13]��C[0,7,10,13]
	����˳���Ϊ��
	1 ����roundnƪ�������plaintxt   16*countn byte
	2 ����roundn���������fault_list  countn byte
	3 ���ܽ��е���8�ֽ���
	4 �ڵ�8�ֵĽ���״̬�����ӹ���i��0-255��
	5 �������9��10�ּ��ܣ�������ȷ����Կkey(uint=4byte��
	6 �����ĵ�[0,7,10,13]λ�������ļ���ciphertxt_list countn*4 byte
		00,07,10,17,20,27,....,ncountn-0,ncountn-7;

	7 ���ֲ²�ʹ��������int������cuda����Ԥ��keyֵ���۲����ȷ���Ƿ�һ��
	*/
	////////////function////////////////////////////////////
	Attack_On8(int n, int mode=0);
	Attack_On8(){
		set_Key();
	}
	~Attack_On8();
	void reset(int n, int mode = 0);
	void setRandPlaintxtAndFault(u32 seed = time(NULL));
	void encryption_to8(u8 in[16], int n);
	void inject(u8 in[16], int n, u32 seed = time(NULL));
	void encryption_to10(u8 in[16], int n);
	void test();
};