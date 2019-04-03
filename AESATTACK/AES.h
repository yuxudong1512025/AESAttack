#pragma once
using namespace std;





class AES {

private:
	u8 key[16];



	u32 SubWord(u32& sw);//������u32�е�ÿһ���ֽڽ���S-�б任
	u32 RotWord(u32& rw);// ���ֽ� ѭ������һλ
	u32 Word(u8& k1, u8& k2, u8& k3, u8& k4);//��4�� u8 ת��Ϊһ�� u32.

protected:
	u32 w[44];

public:
	static const int Nr = 10;  // AES-128��Ҫ 10 �ּ���
	static const int Nk = 4;   // Nk ��ʾ������Կ�� word ����
	static const u32 Rcon[10];
	static const u8 S_Box[256];//sbox����������
	static const u8 Inv_S_Box[256];
	u8 GFMul(u8 a, u8 b);//�������ϵĳ˷� GF(2^8)

	AES() {

	}
	u8 *get_Key() {
		return key;
	}
	void set_Key(u8 *value);
	void set_Key(u32 seed=time(NULL));
	////////////////////�����õ����任/////////////////////////////////
	void SubBytes(u8 mtx[4 * 4]);
	u8  SubByte(u8 mtx);
	void ShiftRows(u8 mtx[4 * 4]);
	void MixColumns(u8 mtx[4 * 4]);
	void AddRoundKey(u8 mtx[4 * 4], u32 k[4]);
	/////////////////////�ƽ��õ���任////////////////////////
	void InvSubBytes(u8 mtx[4 * 4]);
	void InvShiftRows(u8 mtx[4 * 4]);
	void InvMixColumns(u8 mtx[4 * 4]);
	u8 InvSubByte(u8 mtx);
	u8 InvMixColumns_singlecol(u8 mtx[4], int i);
	///////////////////��Կ��չ/////////////////////////////////////
	void KeyExpansion();


};