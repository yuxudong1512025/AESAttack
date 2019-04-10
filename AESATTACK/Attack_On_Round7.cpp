#include "pch.h"
#include "Attack_On_Round7.h"
#include"guessNode.h"

double Attack_On7::gettestkeycount_log2()
{
	double temp = 0;
	for (int i = 0; i < 4; i++) {
		temp += log((double)brench[i].testkeycount);
	}
	return temp;
}

void Attack_On7::test()
{
	set_Key();
	setRandPlaintxtAndFault();
	for (int i = 0; i < countn; i++) {
		encryption_to7(plaintxt + i * 16, i);
		inject(plaintxt + i * 16);
		encryption_to10(plaintxt + i * 16, i);

	}
	for (int i = 0; i < 4; i++) {
		setguess(0, i);
		setguess(1, i);

		//setbrench("11111", i);
		//brench[i].getguessKey();

	}

	for (int i = 0; i < similarbitlist.size(); i++) {
		string mode = similarbitlist[i];
		for (int j = 0; j < 4; j++) {
			setbrench(mode,j);
			brench[j].getguessKey();
		}
		cout << "使用匹配串：" << mode << endl;
		bool flag = brench[0].key_inlist& brench[1].key_inlist& brench[2].key_inlist& brench[3].key_inlist;
		if (flag == true) {
			cout << "使用 " << countn << " 组明文,猜测key列表有 " << brench[0].testkeycount << "*" << brench[1].testkeycount << "*" << brench[2].testkeycount << "*" << brench[3].testkeycount << "个 其中包含正确的key" << endl;
		}
		else cout << "使用 " << countn << " 组明文,猜测key列表有 " << brench[0].testkeycount << "*" << brench[1].testkeycount << "*" << brench[2].testkeycount << "*" << brench[3].testkeycount << "个 其中不包含正确的key" << endl;
		for (int j = 0; j < 4; j++) {
			
		}
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
	/*for (int i = 0; i < similarbitlist.size(); i++) {
		string mode = similarbitlist[i];
		for (int j = 0; j < 4; j++) {
			settempguess(mode, j);
			getguessKey(j);
		}
		bool inlist = true;
		for(int j = 0; j < 4; j++) {
			inlist = inlist & key_inlist[i];
		}
		if (inlist == true) {
			cout << "使用 " << countn << " 组明文,猜测key列表有 " << testkeycount[0] << "*"<< testkeycount[1] << "*"<< testkeycount[2] << "*"<< testkeycount[3] << "个 其中包含正确的key" << endl;
		}
		else cout << "使用 " << countn << " 组明文,猜测key列表有 " << testkeycount[0] << "*" << testkeycount[1] << "*" << testkeycount[2] << "*" << testkeycount[3] << "个 其中不包含正确的key" << endl;

	}*/
	


	
}

Attack_On7::Attack_On7(int n, int m, double success)
{
	countn = n; countM = m; injectsuccess = success;
	plaintxt = (u8 *)malloc(sizeof(u8) * 16 * n);
	for (int i = 0; i < 4; i++) {
		ciphertxt_list_up[i].clear();
		ciphertxt_list_down[i].clear();
	}
	for (int i = 0; i < 4; i++) {
		guess0[i] = (guessNode *)malloc(sizeof(guessNode) * 65536);
		guess1[i] = (guessNode *)malloc(sizeof(guessNode) * 65536);
		
	}
	similarbitlist.clear();
	dfs_findSimilarString();
}

Attack_On7::~Attack_On7()
{
	if (plaintxt != NULL) {
		free(plaintxt);
		plaintxt = NULL;
	}
	for (int i = 0; i < 4; i++) {
		if (guess0[i] != NULL)free(guess0[i]);
		if (guess1[i] != NULL)free(guess1[i]);
	}
}

void Attack_On7::dfs_findSimilarString()
{
	string a;
	a.resize(countn);
	for (int i = 0; i < countn; i++)a[i] = '0';
	dfs(a, 0, countM);
}

void Attack_On7::dfs(string & a,int i,int Cnt)
{
	if (Cnt == 0) {
		similarbitlist.push_back(a);
		return;
	}
	if (i + Cnt < countn) {
		dfs(a, i + 1, Cnt);
	}
		a[i] = '1';
		dfs(a, i + 1, Cnt-1);
		a[i] = '0';
}

void Attack_On7::setRandPlaintxtAndFault(u32 seed)
{
	srand(seed);
	for(int i=0;i<countn*16;i++){
		plaintxt[i] = rand() * 1000 % 256;
	}
	for (int i = 0; i < 4; i++) {
		fault[i] = rand() * 1000 % 256;
	}
}

void Attack_On7::encryption_to7(u8 in[16], int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < Nr - 2; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}
}

void Attack_On7::inject(u8 in[16])
{
	int success = rand() * 1007 % 100; 
	
	if(success<injectsuccess*100){
		in[0]=fault[0]; 
		in[5] = fault[1]; 
		in[10] = fault[2]; 
		in[15] = fault[3];
	}
}

void Attack_On7::encryption_to10(u8 in[16], int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 8 + i];
	SubBytes(in);
	ShiftRows(in);
	MixColumns(in);
	AddRoundKey(in, key);
	//////////////////////////////////////////////
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 9 + i];
	SubBytes(in);
	ShiftRows(in);

	printf("after shiftrow %x %x %x %x\n", in[0], in[7], in[10], in[13]);

	MixColumns(in);
	AddRoundKey(in, key);
	//////////////////test////////Smod9////////////
	//byte ci[4],temp[4];
	//for (int i = 0; i < 4; i++) {
	//	ci[0] = in[i], ci[1] = in[i + 4], ci[2] = in[i + 8], ci[3] = in[i + 12];
	//	if(i==0)temp[i] = InvMixColumns_singlecol(ci, i);
	//	else temp[i] = InvMixColumns_singlecol(ci, 4-i);
	//}
	//printf("S9 %x %x %x %x\n", temp[0], temp[1], temp[2], temp[3]);
	//////////第九轮加密/////////////////////////////
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * 10 + i];
	SubBytes(in);
	ShiftRows(in);
	//printf("after shiftrow %x %x %x %x\n", in[0], in[7], in[10], in[13]);
	AddRoundKey(in, key);
	/*printf("after AK %x %x %x %x\n", in[0], in[7], in[10], in[13]);*/
	//////////第十轮加密/////////////////////////////

	//////////Smod9[0]//////////////////////////////
	ciphertxt_list_up[0].push_back(in[0]);
	ciphertxt_list_up[0].push_back(in[7]);
	ciphertxt_list_down[0].push_back(in[10]);
	ciphertxt_list_down[0].push_back(in[13]);
	//////////Smod9[7]//////////////////////////////
	ciphertxt_list_up[1].push_back(in[3]);
	ciphertxt_list_up[1].push_back(in[6]);
	ciphertxt_list_down[1].push_back(in[9]);
	ciphertxt_list_down[1].push_back(in[12]);
	///////////Smod9[10]///////////////////////////////
	ciphertxt_list_up[2].push_back(in[2]);
	ciphertxt_list_up[2].push_back(in[5]);
	ciphertxt_list_down[2].push_back(in[8]);
	ciphertxt_list_down[2].push_back(in[15]);
	///////////Smod9[13]//////////////////////
	ciphertxt_list_up[3].push_back(in[1]);
	ciphertxt_list_up[3].push_back(in[4]);
	ciphertxt_list_down[3].push_back(in[11]);
	ciphertxt_list_down[3].push_back(in[14]);
	//故障注入在[0]位，扩散4位到[0,7,10,13];
	//printf("%x %x %x %x\n", in[0], in[7], in[10], in[13]);




	trueKey[0] = (key[0] & 0xFF000000) | ((key[3] & 0x00FF0000)) | (key[2] & 0x0000FF00) | ((key[1] & 0x000000FF));
	trueKey[1] = (key[3] & 0xFF000000) | ((key[2] & 0x00FF0000)) | (key[1] & 0x0000FF00) | ((key[0] & 0x000000FF));
	trueKey[2] = (key[2] & 0xFF000000) | ((key[1] & 0x00FF0000)) | (key[0] & 0x0000FF00) | ((key[3] & 0x000000FF));
	trueKey[3] = (key[1] & 0xFF000000) | ((key[0] & 0x00FF0000)) | (key[3] & 0x0000FF00) | ((key[2] & 0x000000FF));
	
	


}

void Attack_On7::setguess(int mode, int p)//i=0-3 表示Smod9[0,7,10,13]
{
	guessNode *it;
	vector<u8 >*cipher;
	if (mode == 0) {
		cipher = ciphertxt_list_up;
		it = guess0[p];
	}
	else {
		cipher = ciphertxt_list_down;
		it = guess1[p];
	}

		u8 *list=NULL;
		u8 temp[2];
		int cnt = 0;
		for (u32 i = 0; i < 256; i++) {
			for (u32 j = 0; j < 256; j++) {
				list=(u8*)malloc(sizeof(u8)*countn);
				for (int k = 0; k < countn; k++) {
					u8 c1 = cipher[p][2 * k], c2 = cipher[p][2 * k + 1];
					temp[0] = InvSubByte(i ^ c1);
					temp[1] = InvSubByte(j ^ c2);

					list[k]=(InvMixColumns_single_half(temp, p, mode));// 生成的列的第i个，mode决定是前半还是后半
				}
				it[(u16)(i << 8) + j].set1(countn, (u16)(i << 8) + j, list);
				free(list);
			}
		}
}
void Attack_On7::setbrench(string mode, int p)
{
	guessNode *gn0, *gn1;
	gn0 = (guessNode *)malloc(65536 * sizeof(guessNode));
	gn1 = (guessNode *)malloc(65536 * sizeof(guessNode));
	for (int i = 0; i < 65536; i++) {
		gn0[i].copy(guess0[p][i], mode,countM - 1);
		gn1[i].copy(guess1[p][i], mode,countM - 1);
	}
	
	brench[p].set(countM - 1, trueKey[p], gn0, gn1);
	
	free(gn0);
	free(gn1);
}
//
//void Attack_On7::settempguess(string mode, int i)
//{
//	temp0[i].clear();
//	for (int j = 0; j< guess0[i].size(); j++) {
//		temp0[i][j].copy(guess0[i][j], mode);
//	}
//
//	temp1[i].clear();
//	for (int j = 0; j < guess1[i].size(); j++) {
//		temp1[i][j].copy(guess1[i][j], mode);
//	}
//}
//
//void Attack_On7::getguessKey(int p)
//{
//	 guessNode::sort(temp0[p], 0, 65536);
//	 guessNode::sort(temp1[p], 0, 65536);
//	u32 i =0, j = 0;
//	while (i < 65536 && j < 65536) {
//		if (temp0[p][i] == temp1[p][j]) {
//			//当list有大量重复的话，这里有问题
//			u32 tempi = i, tempj = j;
//			while (temp0[p][i + 1] == temp0[p][i] && (i + 1 < 65536))i++;
//			while (temp1[p][j + 1] == temp1[p][j] && (j + 1 < 65536))j++;
//			for(int z=tempi;z<=i;z++)
//				for (int q = tempj; q <= j; q++) {
//					testkeycount[i]++;
//					u32 temp = ((u32)(temp0[p][z].guessKey) << 16) + guess1[p][q].guessKey;
//					if (temp == trueKey[p]) key_inlist[p] = true;
//				}
//			i++; j++;
//			//printf("%x =？ %x\n", temp, trueKey);
//		}
//		else if ((temp0[p][i] < temp1[p][j])) {
//			i++;
//		}else j++;
//	}
//}
//	
//
