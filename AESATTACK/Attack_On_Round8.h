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

};