#include "pch.h"
#include "Attack_On_Round8_Changed.h"

Attack_On8_mega::Attack_On8_mega(int n, u32 trueKey, guessNode * gu0, guessNode * gu1)
{
	countn = n;
	key_inlist = false;
	testkeycount = 0;
	guess0 = (guessNode *)malloc(65536 * sizeof(guessNode));
	guess1 = (guessNode *)malloc(65536 * sizeof(guessNode));

	this->trueKey = trueKey;
	for (int i = 0; i < n - 1; i++) {
		this->guess0[i] = gu0[i];
		this->guess1[i] = gu1[i];
	}
}

Attack_On8_mega::Attack_On8_mega(int n)
{
	countn = n;
	key_inlist = false;
	testkeycount = 0;
	plaintxt = (u8*)malloc(n*16*sizeof(u8));
	ciphertxt_list_up = (u8*)malloc(n * 2 * sizeof(u8));;
	ciphertxt_list_down = (u8*)malloc(n * 2 * sizeof(u8));;
	guess0 = (guessNode *)malloc(65536 * sizeof(guessNode));
	guess1 = (guessNode *)malloc(65536 * sizeof(guessNode));
}

Attack_On8_mega::~Attack_On8_mega()
{
	if (plaintxt != NULL) {
		free(plaintxt);
		plaintxt = NULL;
	}
	if (ciphertxt_list_up != NULL) {
		free(ciphertxt_list_up);
		ciphertxt_list_up = NULL;
	}
	if (ciphertxt_list_down != NULL) {
		free(ciphertxt_list_down);
		ciphertxt_list_down = NULL;
	}
	if (guess0 != NULL) {
		free(guess0);
		guess0 = NULL;
	}
	if (guess1 != NULL) {
		free(guess0);
		guess1 = NULL;
	}

}

void Attack_On8_mega::set(int n, u32 trueKey, guessNode * gu0, guessNode * gu1)
{
	this->trueKey = trueKey;
	countn = n;
	key_inlist = false;
	testkeycount = 0;
	guess0 = (guessNode *)malloc(65536 * sizeof(guessNode));
	guess1 = (guessNode *)malloc(65536 * sizeof(guessNode));

	for (int i = 0; i < 65536; i++) {
		*(guess0 + i) = *(gu0 + i);
		*(guess1 + i) = *(gu1 + i);
	}
}

void Attack_On8_mega::setRandPlaintxtAndFault(u32 seed)
{
	srand(seed);
	for (int i = 0; i < 16 * countn; i++)
		plaintxt[i] = rand() % 256;
	fault = rand() % 256;
}

void Attack_On8_mega::encryption_to8(u8 in[16], int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < Nr-1; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}
	in[0] = fault;

}

void Attack_On8_mega::encryption_to10(u8 in[16], int n)
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
	//u8 keyk[4];
	//for (int i = 0; i < 4; i++) {
	//	keyk[i] = trueKey >> (24 - 8 * i);
	//}
	//printf("%x %x %x %x = %x\n", keyk[0], keyk[1], keyk[2], keyk[3], trueKey);
	//for (int i = 0; i < countn; i++) {
	//	u8 ci[4];
	//	ci[0] = InvSubByte(keyk[0] ^ in[0]);
	//	ci[1] = InvSubByte(keyk[1] ^ in[7]);
	//	ci[2] = InvSubByte(keyk[2] ^ in[10]);
	//	ci[3] = InvSubByte(keyk[3] ^ in[13]);
	//	printf("%x %x %x %x\n", ci[0], ci[1], ci[2], ci[3]);
	//	u8 ans = InvMixColumns_singlecol(ci, 0);
	//	printf("%x\n", ans);
	//}printf("\n");

}

void Attack_On8_mega::setguess(u8 type0, u8 type1,int mode)
{
	u8 *cipher = NULL;
	guessNode *it = NULL;
	u8 left, right;
	if (mode == 0) {
		cipher = ciphertxt_list_up;
		it = guess0;
		left = (trueKey >> 24);
		right= (trueKey >> 16);
	}
	else {
		cipher = ciphertxt_list_down;
		it = guess1;
		left = (trueKey >> 8);
		right = trueKey ;
	}

	
	for (u32 i = 0; i < 256; i++) {
		for (u32 j = 0; j < 256; j++) {
			u8 temp, temp1;
			u8 *list = (u8 *)malloc(countn * sizeof(u8));
			for (int k = 0;k < countn; k++) {
			
				temp = Inv_S_Box[i ^ cipher[2 * k]];
				temp1 = Inv_S_Box[j ^ cipher[2 * k + 1]];

				list[k] = GFMul(temp, type0) ^ GFMul(temp1, type1);
				//if(i==0&&j==0)printf("%x %x %x %x %x\n", GFMul(temp, type0), GFMul(temp1, type1), list[k], temp, temp1);
				if (k != 0)list[k] = list[k]^list[0];

				//if (i == left && j == right) {
				//	printf("%x ",list[k]);
				//}
			}

			it[i * 256 + j].set(countn, i * 256 + j, list);
			free(list);
		}
	}
	;/*printf("\n");*/
}

void Attack_On8_mega::getguessKey()
{
	guess0 = guessNode::sort(guess0,  65536);
	guess1 = guessNode::sort(guess1, 65536);
	u32 i =0, j = 0;
	while (i < 65536 && j < 65536) {
		if (guess0[i] == guess1[j]) {
			//当list有大量重复的话，这里有问题
			u32 tempi = i, tempj = j;
			while (guess0[i + 1] == guess0[i] && (i + 1 < 65536))i++;
			while (guess1[j + 1] == guess1[j] && (j + 1 < 65536))j++;
			for(int p=tempi;p<=i;p++)
				for (int q = tempj; q <= j; q++) {
					testkeycount++;
					u32 temp = ((u32)(guess0[p].guessKey) << 16) + guess1[q].guessKey;
					if (temp == trueKey) key_inlist = true;
				}
			i++; j++;
			//printf("%x =？ %x\n", temp, trueKey);
		}
		else if ((guess0[i] < guess1[j])) {
			i++;
		}else j++;
	}
}

void Attack_On8_mega::test()
{
	set_Key();
	setRandPlaintxtAndFault();
	for (int i = 0; i < countn; i++) {
		encryption_to8(plaintxt + i * 16, i);
		encryption_to10(plaintxt + i * 16, i);
		//printf("%d: %x %x %x %x\n",i, ciphertxt_list_up[2 * i], ciphertxt_list_up[2 * i + 1], ciphertxt_list_down[2 * i], ciphertxt_list_down[2 * i + 1]);
	}
	//u8 keyk[4];
	//for (int i = 0; i < 4; i++) {
	//	keyk[i] = trueKey >> (24 - 8 * i);
	//}
	//printf("key: %x %x %x %x = %x\n", keyk[0], keyk[1], keyk[2], keyk[3], trueKey);
	//for (int i = 0; i < countn; i++) {
	//	u8 ci[4];
	//	ci[0] = InvSubByte(keyk[0] ^ ciphertxt_list_up[2 * i]);
	//	ci[1] = InvSubByte(keyk[1] ^ ciphertxt_list_up[2 * i + 1]);
	//	ci[2] = InvSubByte(keyk[2] ^ ciphertxt_list_down[2 * i]);
	//	ci[3] = InvSubByte(keyk[3] ^ ciphertxt_list_down[2 * i + 1]);
	//	printf("%x %x %x %x\n", ci[0], ci[1], ci[2], ci[3]);
	//	u8 ans = InvMixColumns_singlecol(ci, 0);
	//	printf("%x\n", ans);
	//}printf("\n");

	setguess(0x0e, 0x0b, 0);//youwenti
	setguess(0x0d, 0x09, 1);
	getguessKey();
	if (key_inlist == true) {
		cout << "使用 " << countn << " 组明文,猜测key列表有 " << testkeycount << "个 其中包含正确的key" << endl;
	}else cout << "使用 " << countn << " 组明文,猜测key列表有 " << testkeycount << "个 其中不包含正确的key" << endl;
}

void Attack_On8_mega::initial()
{
	key_inlist=false;
	testkeycount=0;
	if (guess0 != NULL)free(guess0);
	if (guess1 != NULL)free(guess1);
}

