#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include"pch.h"
#include"AES.h"

using namespace std;
#define  CHECK(call){\
	const cudaError_t error = call;\
	if (error != cudaSuccess) {\
		printf_s("Error: %s:%d, ", __FILE__, __LINE__);\
		printf_s("code:%d, reason: %s\n", error, cudaGetErrorString(error));\
		exit(-10 * error);\
	}\
}\


__device__ inline u8 GFMul(u8 a, u8 b)
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





u8 Inv_S_Box[256] = {
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

/*考虑ciphertxt的组织形式
	ciphertxt0=	00,07,10,17,20,27,....,ncountn-0,ncountn-7;
	temp=sbox[(0-256)^00]
	temp1=sbox[(0-256)^07]

*/

__global__ void uncode(u8* InvSbox, u8 * cipher, u8 *record, int Countn, u8 info1, u8 info2) {//blocks=256,threads=256,cipher=2*countn个byte 分上半组和下半组 0,7/10,13
	u8 idx = threadIdx.x;
	u8 bdx = blockIdx.x;
	u32 it = (idx * 256 + bdx);
	u8 temp, temp1;
	for (int i = 0; i < Countn; i++) {
		temp = InvSbox[idx ^ cipher[2 * i]];
		temp1 = InvSbox[bdx ^ cipher[2 * i + 1]];
		record[i * 65536 + it] = GFMul(temp, info1) ^ GFMul(temp1, info2);
	}
}

#define doublef(x) (u32)(x*x)
//sei公式编写，求平方和，求

__global__ void getMaxSEI(u32 *maxSEI, u32 *maxKey, u32 *testkey,u32 *testSEI,int id) {//<<<(16384,1),(1024,1)>>>======<<<(256,1)(256,1)>>>
	const u32 tid = threadIdx.x;
	const u32 it = tid + blockIdx.x*blockDim.x;
	for (int stride = blockDim.x *gridDim.x / 2; stride > 0; stride = stride >> 1) {
		if (it + stride < stride * 2 && maxSEI[it] <= maxSEI[it + stride]) {
			maxSEI[it] = maxSEI[it + stride];
			maxKey[it] = maxKey[it + stride];
		}
		__syncthreads();
	}
	__syncthreads();

	if (it == 0) {
		testkey[id] = maxKey[it];
		testSEI[id] = maxSEI[it];
	}
}

__global__ void  kernel(u8 *record0, u8 *record1, int Countn, u32 *maxSEI, u32 *maxKey,u8 *Count, int id) {//65536*256*256*1
	u32 idx = threadIdx.x;
	u32 right = (blockIdx.x*blockDim.x) + threadIdx.x;
	u32 left = id;
	u32 key = (left << 16) + right;

	u8 temp1, temp2;
	for (int i = 0; i < 256; i++)Count[i] = 0;
	for (int i = 0; i < Countn; i++) {
		temp1 = record0[i * 65536 + left];
		temp2 = record1[i * 65536 + right];
		Count[(temp1^temp2) * 65536 + right ] ++;
	}
	u32 temp = 0;
	for (int i = 0; i < 256; i ++) {
		temp += doublef(Count[i * 65536 + right]);

	}
	maxKey[right] = key;
	maxSEI[right] = temp;
}



extern "C"
u32 getKey(u8*ciphertxt0, u8*ciphertxt1, int Countn, const u32 &trueKey) {

	FILE *fp = fopen("a.txt", "a+");
	//get device information
	int dev = 0;
	cudaDeviceProp deviceProp;
	CHECK(cudaGetDeviceProperties(&deviceProp, dev));
	printf_s("using device %d : %s \n", dev, deviceProp.name);
	CHECK(cudaSetDevice(dev));

	int roundn = 65536;
	int blocks = 1 << 8;
	int threads = 1 << 8;
	int btn = blocks * threads;
	int nu8 = btn * Countn * sizeof(u8);
	//	printf_s("Matrix size:nx %d ny %d\n", nx, ny);

	dim3 block(blocks, 1);
	dim3 grid(threads, 1);
	///////////////////////////////////////////////////////
	u16 left = trueKey >> 16, right = (u16)trueKey;
	//fprintf(fp, "key=%x-%x\n", left, right);
	//for (int i = 0; i < Countn; i++) {
	//	fprintf(fp,"%x %x %x %x\n", ciphertxt0[2 * i], ciphertxt0[2 * i + 1], ciphertxt1[2 * i], ciphertxt1[2 * i + 1]);
	//}
	///////////////////////////////////////////////////////
	//printf_s("%d", nu8 * 2 + Countn * 4 + 16 * 16);

	u8 *cipher1, *cipher2, *InvSbox;

	CHECK(cudaMalloc((void **)&InvSbox, 256 * sizeof(u8)));
	CHECK(cudaMalloc((void **)&cipher1, Countn * 2 * sizeof(u8)));
	CHECK(cudaMalloc((void **)&cipher2, Countn * 2 * sizeof(u8)));
	CHECK(cudaMemcpy(cipher1, ciphertxt0, Countn * 2 * sizeof(u8), cudaMemcpyHostToDevice));
	CHECK(cudaMemcpy(cipher2, ciphertxt1, Countn * 2 * sizeof(u8), cudaMemcpyHostToDevice));
	CHECK(cudaMemcpy(InvSbox, Inv_S_Box, 256 * sizeof(u8), cudaMemcpyHostToDevice));

	u8 *Record0, *Record1;


	CHECK(cudaMalloc((void **)&Record0, nu8));
	CHECK(cudaMalloc((void **)&Record1, nu8));
	u8 mode0 = 0x0e, mode1 = 0x0b;
	uncode << <grid, block >> > (InvSbox, cipher1, Record0, Countn, mode0, mode1);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况

	mode0 = 0x0d;  mode1 = 0x09;
	uncode << <grid, block >> > (InvSbox, cipher2, Record1, Countn, mode0, mode1);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况

	//u8 *hostRecord0, *hostRecord1;
	//hostRecord0 = (u8 *)malloc(nu8);
	//hostRecord1 = (u8 *)malloc(nu8);

	//CHECK(cudaMemcpy(hostRecord0, Record0, nu8, cudaMemcpyDeviceToHost));
	//CHECK(cudaMemcpy(hostRecord1, Record1, nu8, cudaMemcpyDeviceToHost));


	//for (int j = 0; j < Countn; j++) {
	//	fprintf(fp,"%x-%x ", hostRecord0[j*65536+left], hostRecord1[j * 65536+right]);
	//	fprintf(fp, "%x ", hostRecord0[j * 65536 + left]^hostRecord1[j * 65536 + right]);
	//}fprintf(fp,"\n");




	dim3 block2(blocks, 1);
	dim3 grid2(blocks, 1);

	nu8 = blocks * blocks * sizeof(u32);
	u32 *maxSEI, *maxKey, *testSEI, *testkey;
	u8 *Count;

	CHECK(cudaMalloc((void **)&maxSEI, nu8));
	CHECK(cudaMalloc((void **)&maxKey, nu8));
	CHECK(cudaMalloc((void **)&testSEI, nu8));
	CHECK(cudaMalloc((void **)&testkey, nu8));
	CHECK(cudaMalloc((void **)&Count, blocks* blocks* blocks * sizeof(u8)));

	for (int i = 0; i < 65536; i++) {
		CHECK(cudaMemset(Count, 0, blocks* blocks* blocks * sizeof(u8)));
		kernel << <grid2, block2 >> > (Record0, Record1, Countn, maxSEI, maxKey,Count,i);
		getMaxSEI << <grid2, block2 >> > (maxSEI, maxKey, testkey, testSEI,i);
	}
	


	u32 *SEIlist = (u32 *)malloc(nu8);
	u32 *KEYlist = (u32 *)malloc(nu8);
	CHECK(cudaMemcpy(SEIlist, testSEI, nu8, cudaMemcpyDeviceToHost));
	CHECK(cudaMemcpy(KEYlist, testkey, nu8, cudaMemcpyDeviceToHost));


	u32 ans = 0, sei = 0;
	for (int i = 0; i < 65536; i++) {
		if (sei < SEIlist[i]) {
			sei = SEIlist[i];
			ans = KEYlist[i];
		}
	}
	printf("%d--%x\n", sei, ans);
	printf("success\n");
	CHECK(cudaFree(Record0));
	CHECK(cudaFree(Record1));
	CHECK(cudaFree(cipher1));
	CHECK(cudaFree(cipher2));
	CHECK(cudaFree(maxSEI));
	CHECK(cudaFree(maxKey));
	CHECK(cudaFree(Count));
	CHECK(cudaFree(testkey));
	CHECK(cudaFree(testSEI));
	free(SEIlist);
	free(KEYlist);
	return ans;
}