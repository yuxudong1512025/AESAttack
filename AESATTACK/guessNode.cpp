#include "pch.h"
#include"guessNode.h"


bool guessNode::operator < (const guessNode &b) {
	for (int i = 0; i < countn - 1; i++) {
		if (guesslist[i] == b.guesslist[i])
			continue;
		else return guesslist[i] < b.guesslist[i];
	}
	return guesslist[countn - 1] < b.guesslist[countn - 1];
}
bool  guessNode::operator == (const guessNode &b) {
	for (int i = 0; i < countn - 1; i++) {
		if (guesslist[i] == b.guesslist[i])
			continue;
		else return false;
	}
	return true;
}
guessNode::guessNode(int n, u16 k, u8 *list) :countn(n), guessKey(k) {
	guesslist = (u8*)malloc(n * sizeof(u8));
	for (int i = 0; i < n; i++)guesslist[i] = *(list + i);
}
guessNode::~guessNode() {
	if (guesslist != NULL)
		free(guesslist);
	guesslist = NULL;
}
guessNode::guessNode() {
	guesslist = NULL;
}
void guessNode::set(int n, u16 k, u8 *list) {
	countn = n, guessKey = k;
	guesslist = (u8*)malloc(n * sizeof(u8));
	for (int i = 0; i < n-1; i++)guesslist[i] = *(list + i + 1);
}
void guessNode::set1(int n, u16 k, u8 *list) {
	countn = n, guessKey = k;
	guesslist = (u8*)malloc(n * sizeof(u8));
	for (int i = 0; i < n; i++)guesslist[i] = *(list + i);
}

guessNode* guessNode::sort(guessNode *a, int countn) {
	if (countn == 1) {
		guessNode *temp = (guessNode *)malloc(countn * sizeof(guessNode));
		*temp = *a;
		return temp;
	}
	guessNode *temp = (guessNode *)malloc(countn * sizeof(guessNode));
	guessNode *left = sort(a, countn / 2);
	guessNode *right = sort(a + countn / 2, countn / 2);
	int i = 0, j = 0, t = 0;
	while (i < countn / 2 && j < countn / 2) {
		if (left[i] < right[j])temp[t++] = left[i++];
		else temp[t++] = right[j++];
	}
	while (i < countn / 2)temp[t++] = left[i++];
	while (j < countn / 2)temp[t++] = right[j++];

	free(left);
	free(right);
	return temp;
}
void  guessNode::to_string() {
	printf("key= %x\t", guessKey);
	printf("list={");
	for (int i = 0; i < countn ; i++)
		printf("%x ", *(guesslist + i));
	printf("}\n");
}

guessNode::guessNode(const guessNode &a, string mode) {
	int temp = 0;
	u8 record = 0;
	for (int i = 0; i < mode.length(); i++) {
		if (mode[i] == '1') {
			if (temp == 0) {
				record = a.guesslist[i];
			}
			else guesslist[temp-1]=a.guesslist[i] ^ record;
			temp++;
		}
	}
	guessKey = a.guessKey;
	countn = temp - 1;
}//根据01模式串拷贝

void guessNode::copy(const guessNode &a, string mode,int n) {
	guesslist=(u8*)malloc(n * sizeof(u8));
	int temp = 0;
	u8 record = 0;
	for (int i = 0; i < mode.length(); i++) {
		if (mode[i] == '1') {
			if (temp == 0) {
				record = a.guesslist[i];
			}
			else guesslist[temp-1] = a.guesslist[i] ^ record;
			temp++;
		}
	}
	guessKey = a.guessKey;
	countn = n;
}//根据01模式串拷贝