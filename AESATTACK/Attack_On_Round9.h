#pragma once
#include"pch.h"
#include"AES.h"

enum method
{
	likeHood,
	hmWeight
};

class Attack_On9 :public AES {
private:
	static const int Inv_ShiftRows[16];
	
public:
	u8 distribution[256][256];//[fault][faultbyte] = probability of occurrence
	u8 *plaintxt_list;
	u8 *faultciphertxt_list;
	int countn;
	int inject_position;
	int fault_position;
	u8 *faultlist;
	u8 truekey;
	Attack_On9();
	/*
		�������ַ��������������
		plaintxt_list            �洢�������һ��countn��  size=16*countn*1 �� byte
		faultlist                �洢countn��������ɵ�0-255�Ĺ��ϼ�¼��Ӧcountn�����ĵ�������� size=countn*1 �� byte
		faultciphertxt_list      �洢countn���������� size=countn*1 �� byte
		countn                   ��������
		inject_position		     ע�����λ��
		fault_position           ����Ӱ��λ��     
		���1���˽���Ϸֲ���
			���ɹ��Ϸֲ��ɱ����㼫����Ȼ����

		���2�����˽���Ϸֲ���
			����

		�ھ��ֹ�������
		1 �������countn�����Ĵ���plaintxt_list
		2 �������countn��fault������ģ��1,2,3������ע��λ��inject_position ��ȡInv_SRλ�� fault_position
		3 ���ܽ��е���9�ֽ������м�̬State9
		4 ��countn��State9��inject_positionλ�õ�byteȡ�����Ӧfault���в��� ����faultciphertxt_list
		5 ģ���ʮ�ּ��ܣ���ʵ��һ��SB��AK�������õ�fault_position��ȡWK10��byte��˳�㱣������ȷ��key
		6 �����ַ���������ȷ��key
		7 ����1ʹ��distribution�����maxLH
		8 ����2ֱ����minHW

	*/
/////////////////////����Ϊfunction////////////////////////////////////
	Attack_On9(int countn);
	~Attack_On9();
	void setInject(int n);

	void getDistribution();

	void setRandPlaintxt(u32 seed = time(NULL));
	void setRandFault(int mode,u32 seed = time(NULL));
	void encryption_to9(u8 in[16],int n);
	void encryption_to10();

	double LikeHood(u8 fckey,int n);
	int getbit(u8 a);
	int HMweight(u8 fckey, int n);
	u8 getMaxLH(int n);
	u8 getMinHw(int n);
	void test(int mode, method a);
};