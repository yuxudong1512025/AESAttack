#include "pch.h"
#include "normal_encryption_test.h"

void NormalAES::setplaintxt(u8 * a)
{
	plaintxt = a;
}

u8 * NormalAES::getplaintxt()
{
	return plaintxt;
}

void NormalAES::setciphertxt(u8 * a)
{
	ciphertxt = a;
}

u8 * NormalAES::getciphertxt()
{
	return ciphertxt;
}

void NormalAES::encryption()
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(plaintxt, key);

	for (int round = 1; round < Nr; ++round)
	{
		SubBytes(plaintxt);
		ShiftRows(plaintxt);
		MixColumns(plaintxt);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(plaintxt, key);
	}

	SubBytes(plaintxt);
	ShiftRows(plaintxt);
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * Nr + i];
	AddRoundKey(plaintxt, key);

	ciphertxt = plaintxt;
	plaintxt = NULL;
}

void NormalAES::decryption()
{
	u32 key[4];
	for (int i = 0; i < 4; ++i)
		key[i] = w[4 * Nr + i];
	AddRoundKey(ciphertxt, key);

	for (int round = Nr - 1; round > 0; --round)
	{
		InvShiftRows(ciphertxt);
		InvSubBytes(ciphertxt);
		for (int i = 0; i < 4; ++i)
			key[i] = w[4 * round + i];
		AddRoundKey(ciphertxt, key);
		InvMixColumns(ciphertxt);
	}

	InvShiftRows(ciphertxt);
	InvSubBytes(ciphertxt);
	for (int i = 0; i < 4; ++i)
		key[i] = w[i];
	AddRoundKey(ciphertxt, key);

	plaintxt = ciphertxt;
	ciphertxt = NULL;
}

/*void test() {

	NormalAES a;
	u8 *plaintxt = (u8*)malloc(sizeof(u8) * 17);
	scanf_s("%s", plaintxt);
	a.setplaintxt(plaintxt);
	printf("plaintxt= %s\n", a.getplaintxt());
	a.set_Key();
	printf_s("key= %s\n", a.get_Key());

	a.encryption();
	printf_s("ciphertxt= %s\n", a.getciphertxt());

	NormalAES b;
	b.set_Key(a.get_Key());
	b.setciphertxt(a.getciphertxt());
	b.decryption();
	printf("plaintxt= %s\n", b.getplaintxt());

}*/