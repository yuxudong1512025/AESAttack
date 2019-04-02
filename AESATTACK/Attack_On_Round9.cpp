#include "pch.h"
#include "Attack_On_Round9.h"

const int Attack_On9::Inv_ShiftRows[16] = { 0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12 };

Attack_On9::Attack_On9()
{
	getDistribution();
}

Attack_On9::Attack_On9(int countn)
{	
	this->countn = countn;
	plaintxt_list = (u8 *)malloc(16 * countn * sizeof(u8));
	faultlist = (u8 *)malloc(countn * sizeof(u8));
	faultciphertxt_list = (u8 *)malloc(countn * sizeof(u8));
	getDistribution();
}

Attack_On9::~Attack_On9()
{
	if (plaintxt_list != NULL)free(plaintxt_list);
	if (faultciphertxt_list != NULL)free(faultciphertxt_list);
	if(faultlist != NULL)free(faultlist);
	plaintxt_list = NULL;
	faultciphertxt_list = NULL;
	faultlist=NULL;
}

void Attack_On9::setInject(int n)
{
	inject_position = n;
	fault_position = Inv_ShiftRows[n];
}

void Attack_On9::getDistribution()
{
	memset(distribution, 0, sizeof(distribution));
	for (int i = 0; i < 255; i++)
		for (int j = 0; j < 255; j++)
			distribution[i][i&j]++;
}

void Attack_On9::setRandPlaintxt(u32 seed)
{
	srand(seed);
	for (int i = 0; i < countn * 16; i++) {
		*(plaintxt_list+i)= u8(rand() % 256);
	}
}

void Attack_On9::setRandFault(int mode, u32 seed)
{
	srand(seed);
	switch (mode)
	{
	case 1:
		for (int i = 0; i < countn; i++)
			*(faultlist + i) = u8(0);
		break;
	case 2:
		for (int i = 0; i < countn; i++)
			if(rand()%2==0)
				*(faultlist + i) = u8(0);
			else 
				*(faultlist + i) = u8(rand() * 1007 % 256);
		break;
	case 3:
		for (int i = 0; i < countn; i++) {
			*(faultlist + i) = u8(rand()*1007%256);
		}
		break;
	default:
		cout << "请选择正确模式（1-3）" << endl;
		int n;
		cin >> n;
		setRandFault(n, time(NULL));
		break;
	}
	//for (int i = 0; i < countn; i++)
	//	cout << (int)*(faultlist + i) << " ";
	//cout << endl;

}

void Attack_On9::encryption_to9(u8 in[16],int n)
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(in, key);

	for (int round = 1; round < Nr; ++round)
	{
		SubBytes(in);
		ShiftRows(in);
		MixColumns(in);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(in, key);
	}
	faultciphertxt_list[n] = in[inject_position]&faultlist[n];
	//cout << (int)in[inject_position] << " ";
}

void Attack_On9::encryption_to10()
{
	int wpostion = fault_position / 4;
	int inposition= fault_position % 4;
	u32 temp = w[40 + wpostion];
	truekey = temp >> (8 * (3-inposition));

	u8 temp1;
	for (int i = 0; i < countn; i++) {
		temp1 = faultciphertxt_list[i];
		temp1 = SubByte(temp1);
		faultciphertxt_list[i] = temp1 ^ truekey;
	}
}

double Attack_On9::LikeHood(u8 fckey,int n)
{
	if (n > countn) {
		cout << "n 不能大于" << countn;
		return 0.0;
	}
	double ans = 0;
	for (int i = 0; i <= n; i++) {
		u8 temp = faultciphertxt_list[i];
		temp = InvSubByte(temp^fckey);
		if (distribution[faultlist[i]][temp] == 0)return 0;
		else  ans += log(distribution[faultlist[i]][temp]);
	}
	return ans;
}

int Attack_On9::getbit(u8 a)
{
	int i = 0;
	while (a) {
		if (a % 2)i++;
		a /= 2;
	}
	return i;
}

int Attack_On9::HMweight(u8 fckey, int n)
{
	if (n > countn) {
		cout << "n 不能大于" << countn;
		return 0.0;
	}
	int ans = 0;
	for (int i = 0; i <= n; i++) {
		u8 temp = faultciphertxt_list[i];
		temp = InvSubByte(temp^fckey);
		ans += getbit(temp);
	}
	return ans;
}

u8 Attack_On9::getMaxLH(int n)
{
	u8 maxkey=0;
	double value = 0.0;
	for (int i = 0; i < 256; i++) {
		double temp = LikeHood(i, n);
		if (value < temp) {
			value = temp;
			maxkey = i;
		}
	}
	return maxkey;
}

u8 Attack_On9::getMinHw(int n)
{
	u8 maxkey=0;
	int minvalue = 99999999;
	for (int i = 0; i < 256; i++) {
		int temp = HMweight(i, n);
		if (minvalue > temp) {
			minvalue = temp;
			maxkey = i;
		}
	}
	return maxkey;
}

void Attack_On9::test(int mode, method a)
{
	set_Key();	

	if (a==method::likeHood) {
		for (int i = 0; i < countn; i++) {
			setRandPlaintxt();
			setRandFault(mode);
			for (int i = 0; i < countn; i++) {
				encryption_to9(plaintxt_list + i * 16, i);
			}
			encryption_to10();

			u8 maxkey = getMaxLH(i);
			//cout << "testans key=" << (int)maxkey<<endl;
			cout << "use " << i + 1 << "couples find key= " << (int)maxkey << ",truekey=" << (int)truekey << endl;

			if (maxkey == truekey) {
				cout << "find true key using " << i+1 << " couples plaintxt" << endl;
				
			}
		}
	}
	else if (a == method::hmWeight) {
		for (int i = 0; i < countn; i++) {
			setRandPlaintxt();
			setRandFault(mode);
			for (int i = 0; i < countn; i++) {
				encryption_to9(plaintxt_list + i * 16, i);
			}
			encryption_to10();

			u8 maxkey = getMinHw(i);
			cout << "use " << i + 1 << "couples find key= " <<(int) maxkey << ",truekey=" << (int)truekey << endl;
			if (maxkey == truekey) {
				cout << "find true key using " << i+1 << " couples plaintxt"<<endl;
			}
		}
	}
}

