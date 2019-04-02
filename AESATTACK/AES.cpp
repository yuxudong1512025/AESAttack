#include "pch.h"
#include "AES.h"

void AES::set_Key(u8 * value)
{
	for (int i = 0; i < 16; i++)
		key[i] = value[i];
	KeyExpansion();
}

void AES::set_Key(u32 seed)
{
	srand(seed);
	for (int i = 0; i < 16; i++)
		key[i] = u8(rand() * 1000 % 256);
	KeyExpansion();
}

void AES::SubBytes(u8 mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		mtx[i] = S_Box[mtx[i]];
	}
}

u8 AES::SubByte(u8 mtx)
{
	return S_Box[mtx];
}

void AES::ShiftRows(u8 mtx[4 * 4])
{
	// 第二行循环左移一位
	u8 temp = mtx[4];
	for (int i = 0; i < 3; ++i)
		mtx[i + 4] = mtx[i + 5];
	mtx[7] = temp;
	// 第三行循环左移两位
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 第四行循环左移三位
	temp = mtx[15];
	for (int i = 3; i > 0; --i)
		mtx[i + 12] = mtx[i + 11];
	mtx[12] = temp;
}

void AES::MixColumns(u8 mtx[4 * 4])
{
	u8 arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x02, arr[0]) ^ GFMul(0x03, arr[1]) ^ arr[2] ^ arr[3];
		mtx[i + 4] = arr[0] ^ GFMul(0x02, arr[1]) ^ GFMul(0x03, arr[2]) ^ arr[3];
		mtx[i + 8] = arr[0] ^ arr[1] ^ GFMul(0x02, arr[2]) ^ GFMul(0x03, arr[3]);
		mtx[i + 12] = GFMul(0x03, arr[0]) ^ arr[1] ^ arr[2] ^ GFMul(0x02, arr[3]);
	}
}

void AES::AddRoundKey(u8 mtx[4 * 4], u32 k[4])
{
	for (int i = 0; i < 4; ++i)
	{
		u8 k4 = k[i];
		u8 k3 = k[i] >> 8;
		u8 k2 = k[i] >> 16;
		u8 k1 = k[i] >> 24;

		mtx[i] = mtx[i] ^k1;
		mtx[i + 4] = mtx[i + 4] ^ k2;
		mtx[i + 8] = mtx[i + 8] ^ k3;
		mtx[i + 12] = mtx[i + 12] ^ k4;
	}
}

void AES::InvSubBytes(u8 mtx[4 * 4])
{
	for (int i = 0; i < 16; ++i)
	{
		mtx[i] = Inv_S_Box[mtx[i]];
	}
}

void AES::InvShiftRows(u8 mtx[4 * 4])
{
	// 第二行循环右移一位
	u8 temp = mtx[7];
	for (int i = 3; i > 0; --i)
		mtx[i + 4] = mtx[i + 3];
	mtx[4] = temp;
	// 第三行循环右移两位
	for (int i = 0; i < 2; ++i)
	{
		temp = mtx[i + 8];
		mtx[i + 8] = mtx[i + 10];
		mtx[i + 10] = temp;
	}
	// 第四行循环右移三位
	temp = mtx[12];
	for (int i = 0; i < 3; ++i)
		mtx[i + 12] = mtx[i + 13];
	mtx[15] = temp;
}

void AES::InvMixColumns(u8 mtx[4 * 4])
{
	u8 arr[4];
	for (int i = 0; i < 4; ++i)
	{
		for (int j = 0; j < 4; ++j)
			arr[j] = mtx[i + j * 4];

		mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
		mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
		mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
		mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
	}
}

u8 AES::InvSubByte(u8 mtx)
{
	return Inv_S_Box[mtx];
}

u8 AES::InvMixColumns_singlecol(u8 mtx[4], int i)
{
	switch (i) {
	case 0:return GFMul(0x0e, mtx[0]) ^ GFMul(0x0b, mtx[1]) ^ GFMul(0x0d, mtx[2]) ^ GFMul(0x09, mtx[3]);
	case 1:return GFMul(0x09, mtx[0]) ^ GFMul(0x0e, mtx[1]) ^ GFMul(0x0b, mtx[2]) ^ GFMul(0x0d, mtx[3]);
	case 2:return GFMul(0x0d, mtx[0]) ^ GFMul(0x09, mtx[1]) ^ GFMul(0x0e, mtx[2]) ^ GFMul(0x0b, mtx[3]);
	case 3:return GFMul(0x0b, mtx[0]) ^ GFMul(0x0d, mtx[1]) ^ GFMul(0x09, mtx[2]) ^ GFMul(0x0e, mtx[3]);
	default:return u8(-1);
	}
}

void AES::KeyExpansion()
{
	u32 temp;
	int i = 0;
	// w[]的前4个就是输入的key
	while (i < Nk)
	{
		w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
		++i;
	}

	i = Nk;

	while (i < 4 * (Nr + 1))
	{
		temp = w[i - 1]; // 记录前一个word
		if (i % Nk == 0) {
			temp = RotWord(temp);
			w[i] = w[i - Nk] ^ SubWord(temp) ^ Rcon[i / Nk - 1];
		}
		else
			w[i] = w[i - Nk] ^ temp;
		++i;
	}
}

u8 AES::GFMul(u8 a, u8 b)
{
	u8 p = 0;
	u8 hi_bit_set;
	for (int counter = 0; counter < 8; counter++) {
		if ((b & u8(1)) != 0) {
			p ^= a;
		}
		hi_bit_set = (u8)(a & u8(0x80));
		a <<= 1;
		if (hi_bit_set != 0) {
			a ^= 0x1b; /* x^8 + x^4 + x^3 + x + 1 */
		}
		b >>= 1;
	}
	return p;
}

u32 AES::SubWord(u32 & sw)
{
	u32 temp=0;
	for (int i = 0; i < 4; i ++)
	{
		u8 tmp = sw >> (i * 8);
		u8 val = S_Box[tmp];
		temp = temp | (val << (i * 8));
	}
	return temp;
}

u32 AES::RotWord(u32 & rw)
{
	u32 high = rw << 8;
	u32 low = rw >> 24;
	return high | low;
}

u32 AES::Word(u8 & k1, u8 & k2, u8 & k3, u8 & k4){
	u32 t1 = k1;
	u32 t2 = k2;
	u32 t3 = k3;
	u32 t4 = k4;

	return u32((t1 << 0)+ (t2 << 8)+ (t3 << 16)+ (t4 << 24));
}






const u32 AES::Rcon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };
const u8 AES::S_Box[256] = {
	 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76 ,
	 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0 ,
	 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15 ,
	 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75 ,
	 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84 ,
	 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF ,
	 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8 ,
	 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2 ,
	 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73 ,
	 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB ,
	 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79 ,
	 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08 ,
	 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A ,
	 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E ,
	 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF ,
	 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 
};
const u8 AES::Inv_S_Box[256] = {
	 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB ,
	 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB ,
	 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E ,
	 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25 ,
	 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92 ,
	 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84 ,
	 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06 ,
	 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B ,
	 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73 ,
	 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E ,
	 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B ,
	 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4 ,
	 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F ,
	 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF ,
	 0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61 ,
	 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D 
};
