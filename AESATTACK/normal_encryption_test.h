#pragma once
#include"AES.h"
#include"pch.h"

class NormalAES :public AES {
private:
	u8 *ciphertxt;
	u8 *plaintxt;
public:
	void setplaintxt(u8 * a);
	u8 *getplaintxt();

	void setciphertxt(u8 * a);
	u8 *getciphertxt();

	void encryption();
	void decryption();
};