#pragma once
#include"pch.h"
#include"AES.h"

enum method
{
	likeHood,
	hmWeight
};

class Attack_On9 :public AES {
private:
	static const int Inv_ShiftRows[16];
	
public:
	u8 distribution[256][256];//[fault][faultbyte] = probability of occurrence
	u8 *plaintxt_list;
	u8 *faultciphertxt_list;
	int countn;
	int inject_position;
	int fault_position;
	u8 *faultlist;
	u8 truekey;
	Attack_On9();
	/*
		考虑两种方法处理两种情况
		plaintxt_list            存储随机明文一共countn组  size=16*countn*1 个 byte
		faultlist                存储countn个随机生成的0-255的故障记录对应countn组密文的随机故障 size=countn*1 个 byte
		faultciphertxt_list      存储countn个故障密文 size=countn*1 个 byte
		countn                   明文组数
		inject_position		     注入故障位置
		fault_position           故障影响位置     
		情况1：了解故障分布律
			生成故障分布律表，计算极大似然估计

		情况2：不了解故障分布律
			计算

		第九轮攻击设想
		1 随机生成countn组密文存入plaintxt_list
		2 随机生成countn个fault（根据模型1,2,3）设置注入位置inject_position 获取Inv_SR位置 fault_position
		3 加密进行到第9轮结束的中间态State9
		4 将countn组State9的inject_position位置的byte取出与对应fault进行操作 存入faultciphertxt_list
		5 模拟第十轮加密：其实就一个SB和AK（这里用到fault_position获取WK10的byte）顺便保存下正确的key
		6 用两种方法反推正确的key
		7 方法1使用distribution表计算maxLH
		8 方法2直接算minHW

	*/
/////////////////////以下为function////////////////////////////////////
	Attack_On9(int countn);
	~Attack_On9();
	void setInject(int n);

	void getDistribution();

	void setRandPlaintxt(u32 seed = time(NULL));
	void setRandFault(int mode,u32 seed = time(NULL));
	void encryption_to9(u8 in[16],int n);
	void encryption_to10();

	double LikeHood(u8 fckey,int n);
	int getbit(u8 a);
	int HMweight(u8 fckey, int n);
	u8 getMaxLH(int n);
	u8 getMinHw(int n);
	void test(int mode, method a);
};