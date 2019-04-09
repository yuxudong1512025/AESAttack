#pragma once
#include "pch.h"
#include<string>
class guessNode
{

public:

	int countn;
	u16 guessKey;
	u8 *guesslist;

	guessNode();
	 ~guessNode();
	 guessNode(int n, u16 k, u8 *list);
	 guessNode(const guessNode &a, string mode);


	 bool operator < (const guessNode &b);
	 bool  operator == (const guessNode &b);


	 void set(int n, u16 k, u8 *list);
	 void set1(int n, u16 k, u8 *list);
	 void copy(const guessNode &a, string mode,int n);
	 void  to_string();


	 static guessNode*  sort(guessNode *a, int countn);

};


