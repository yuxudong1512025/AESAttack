#pragma once
using namespace std;





class AES {

private:
	u8 key[16];



	u32 SubWord(u32& sw);//对输入u32中的每一个字节进行S-盒变换
	u32 RotWord(u32& rw);// 按字节 循环左移一位
	u32 Word(u8& k1, u8& k2, u8& k3, u8& k4);//将4个 u8 转换为一个 u32.

protected:
	u32 w[44];

public:
	static const int Nr = 10;  // AES-128需要 10 轮加密
	static const int Nk = 4;   // Nk 表示输入密钥的 word 个数
	static const u32 Rcon[10];
	static const u8 S_Box[256];//sbox随类编译产生
	static const u8 Inv_S_Box[256];
	u8 GFMul(u8 a, u8 b);//有限域上的乘法 GF(2^8)

	AES() {

	}
	u8 *get_Key() {
		return key;
	}
	void set_Key(u8 *value);
	void set_Key(u32 seed=time(NULL));
	////////////////////加密用的正变换/////////////////////////////////
	void SubBytes(u8 mtx[4 * 4]);
	u8  SubByte(u8 mtx);
	void ShiftRows(u8 mtx[4 * 4]);
	void MixColumns(u8 mtx[4 * 4]);
	void AddRoundKey(u8 mtx[4 * 4], u32 k[4]);
	/////////////////////破解用的逆变换////////////////////////
	void InvSubBytes(u8 mtx[4 * 4]);
	void InvShiftRows(u8 mtx[4 * 4]);
	void InvMixColumns(u8 mtx[4 * 4]);
	u8 InvSubByte(u8 mtx);
	u8 InvMixColumns_singlecol(u8 mtx[4], int i);
	///////////////////密钥扩展/////////////////////////////////////
	void KeyExpansion();


};