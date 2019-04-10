#include "pch.h"
#include "Attack_On_Round8.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"

extern "C"
u32 getKey(u8*ciphertxt0, u8*ciphertxt1, int Countn, const u32 &trueKey);

Attack_On8::Attack_On8(int n, int mode)
{
	set_Key();
	countn = n;
	faultmode = mode;
	plaintxt = (u8*)malloc(countn * 16 * sizeof(u8));
	ciphertxt_list_up = (u8*)malloc(countn * 2 * sizeof(u8));
	ciphertxt_list_down = (u8*)malloc(countn * 2 * sizeof(u8));
}

Attack_On8::~Attack_On8()
{
	//if (plaintxt != NULL)free(plaintxt);
	/*if (ciphertxt_list_up != NULL)free(ciphertxt_list_up);
	if (ciphertxt_list_down != NULL)free(ciphertxt_list_down);*/
}

void Attack_On8::reset(int n, int mode)
{
	countn = n;
	faultmode = mode;
	if(plaintxt==NULL) plaintxt = (u8*)malloc(countn * 16 * sizeof(u8));
	else memset(plaintxt, 0, sizeof(plaintxt));
	
	if (ciphertxt_list_up == NULL)ciphertxt_list_up = (u8*)malloc(countn * 2 * sizeof(u8));
	else memset(ciphertxt_list_up, 0, sizeof(ciphertxt_list_up));

	if (ciphertxt_list_down == NULL)ciphertxt_list_down = (u8*)malloc(countn * 2 * sizeof(u8));
	else memset(ciphertxt_list_down, 0, sizeof(ciphertxt_list_down));
}

void Attack_On8::setRandPlaintxtAndFault(u32 seed)
{
	srand(seed);
	for (int i = 0; i < 16 * countn; i++)
		plaintxt[i] = rand() % 256;
}

void Attack_On8::encryption_to8(u8 in[16], int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < Nr - 1; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}
}

void Attack_On8::inject(u8 in[16], int n, u32 seed)
{
	srand(seed);
	switch (faultmode)
	{
	case 0: {
		in[0] = 0;
		break;
	}
	case 1: {
		int temp = rand() * 1007 % 100;
		if (temp >= 50)in[0] = 0;
		else in[0]= rand() * 1007 % 256;
		break;
	}
	case 2: {
		in[0] = rand() * 1007 % 256;
		break;
	}
	default:
		break;
	}
}

void Attack_On8::encryption_to10(u8 in[16], int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 9 + i];
	SubBytes(in);
	ShiftRows(in);
	MixColumns(in);
	AddRoundKey(in, key);
	//////////////////test///////////////////////////
	//byte ci[4];
	//for(int i=0;i<4;i++)ci[i]=in[4*i];
	//u8 temp=InvMixColumns_singlecol(ci,0);
	//printf("%x ",temp);
	//printf("S8 %x %x %x %x\n",in[0], in[4], in[8], in[12] );
	//////////第九轮加密/////////////////////////////
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 10 + i];
	SubBytes(in);
	ShiftRows(in);
	//printf("after shiftrow %x %x %x %x\n", in[0], in[7], in[10], in[13]);
	AddRoundKey(in, key);
	/*printf("after AK %x %x %x %x\n", in[0], in[7], in[10], in[13]);*/
	//////////第十轮加密/////////////////////////////
	ciphertxt_list_up[2 * n] = in[0];
	ciphertxt_list_up[2 * n + 1] = in[7];
	ciphertxt_list_down[2 * n] = in[10];
	ciphertxt_list_down[2 * n + 1] = in[13];
	//故障注入在[0]位，扩散4位到[0,7,10,13];
	//printf("%x %x %x %x\n", in[0], in[7], in[10], in[13]);
	trueKey = (key[0] & 0xFF000000) | ((key[3] & 0x00FF0000)) | (key[2] & 0x0000FF00) | ((key[1] & 0x000000FF));
}

void Attack_On8::test()
{
	
	setRandPlaintxtAndFault();
	for (int i = 0; i < countn; i++) {
		encryption_to8(plaintxt + i * 16, i);
		inject(plaintxt + i * 16, i);
		encryption_to10(plaintxt + i * 16, i);
		//printf("%d: %x %x %x %x\n",i, ciphertxt_list_up[2 * i], ciphertxt_list_up[2 * i + 1], ciphertxt_list_down[2 * i], ciphertxt_list_down[2 * i + 1]);
	}
	u32 guesskey = getKey(ciphertxt_list_up, ciphertxt_list_down, countn,trueKey);
	if (guesskey != trueKey) {
		printf("使用了  %d  组故障密文，用SEI预测的key为 %x 实际key为 %x 未预测中", countn, guesskey, trueKey);
	}else printf("使用了  %d  组故障密文，用SEI预测的key为 %x 实际key为 %x 预测中", countn, guesskey, trueKey);
}
