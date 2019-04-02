#include "cuda.h"
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include"pch.h"

using namespace std;
#define  CHECK(call){\
	const cudaError_t error = call;\
	if (error != cudaSuccess) {\
		printf_s("Error: %s:%d, ", __FILE__, __LINE__);\
		printf_s("code:%d, reason: %s\n", error, cudaGetErrorString(error));\
		exit(-10 * error);\
	}\
}\


__device__  inline u8 XTIME(u8 x) {
	return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}
__device__  inline u8 multiply(u8 a, u8 b) {
	u8 temp[8] = { a };
	u8 tempmultiply = 0x00;
	u32 i = 0;
	for (i = 1; i < 8; i++) {
		temp[i] = XTIME(temp[i - 1]);
	}
	tempmultiply = (b & 0x01) * a;
	for (i = 1; i <= 7; i++) {
		tempmultiply ^= (((b >> i) & 0x01) * temp[i]);
	}
	return tempmultiply;
}



__constant__ u8 sbox[256];

const u8 S_Box[256] = {
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

/*考虑ciphertxt的组织形式
	ciphertxt0=	00,07,10,17,20,27,....,ncountn-0,ncountn-7;
	temp=sbox[(0-256)^00]
	temp1=sbox[(0-256)^07]

*/

__global__ void uncode(u8 * cipher, u8 *record, int Countn, u8 info1, u8 info2) {//blocks=256,threads=256,cipher=2*countn个byte 分上半组和下半组 0,7/10,13
	u8 idx = threadIdx.x;
	u8 bdx = blockIdx.x;
	u32 it = (idx + bdx * blockDim.x);
	u8 temp, temp1;
	for (int i = 0; i < Countn; i ++ ) {
		temp = sbox[idx ^ cipher[2 * i]];
		temp1 = sbox[bdx ^ cipher[2 * i + 1]];
		record[i * Countn + it] = multiply(temp, info1) ^ multiply(temp1, info2);
	}
}

#define doublef(x) (x*x)
//sei公式编写，求平方和，求


__global__ void  kernel(u8 *record0, u8 *record1, int Countn, float *maxSEI, u32 *maxKey) {//65536*256*256*1
	u32 idx = threadIdx.x;
	u32 right = (blockIdx.y*blockDim.x) + threadIdx.x;
	u32 left = blockIdx.x;
	u32 key = (left << 16) + right;
	__shared__ u32 partialMax[256];
	__shared__ u32 partialKey[256];
	u8 temp1, temp2;
	int Count[256];//256*4=1kb
	for (int i = 0; i < Countn; i++) {
		temp1 = record0[i*Countn + left];
		temp2 = record1[i*Countn + right];
		Count[(temp1^temp2)] += 1;
	}
	u32 temp = 0;
	for (int i = 0; i < 256; i += 32) {
		temp += doublef(Count[i]) + doublef(Count[i + 1]) + doublef(Count[i + 2]) + doublef(Count[i + 3]) + doublef(Count[i + 4]) + doublef(Count[i + 5]) + doublef(Count[i + 6]) + doublef(Count[i + 7]);
		temp += doublef(Count[i + 8]) + doublef(Count[i + 9]) + doublef(Count[i + 10]) + doublef(Count[i + 11]) + doublef(Count[i + 12]) + doublef(Count[i + 13]) + doublef(Count[i + 14]) + doublef(Count[i + 15]);
		temp += doublef(Count[i + 16]) + doublef(Count[i + 16]) + doublef(Count[i + 17]) + doublef(Count[i + 18]) + doublef(Count[i + 20]) + doublef(Count[i + 21]) + doublef(Count[i + 22]) + doublef(Count[i + 23]);
		temp += doublef(Count[i + 24]) + doublef(Count[i + 25]) + doublef(Count[i + 26]) + doublef(Count[i + 27]) + doublef(Count[i + 28]) + doublef(Count[i + 29]) + doublef(Count[i + 30]) + doublef(Count[i + 31]);

	}

	partialKey[idx] = key;
	partialMax[idx] = temp;
	//printf("%d %d key=%d ,sei=%f key=%d\n", idx, 1, key, sei, key);
	__syncthreads();

	for (int stride = blockDim.x / 2; stride > 0; stride = stride >> 1) {
		if (idx < stride&&partialMax[idx] < partialMax[idx + stride]) {
			partialMax[idx] = partialMax[idx + stride];
			partialKey[idx] = partialKey[idx + stride];
		}
		__syncthreads();
	}


	if (idx == 0) {
		*(maxSEI + blockIdx.y + blockDim.x*blockIdx.x) = partialMax[idx];
		*(maxKey + blockIdx.y + blockDim.x*blockIdx.x) = partialKey[idx];
	}

}

__host__ void randcipher(u8 *cipher, int Countn) {
	for (int i = 0; i < Countn * 4; i++)
		*(cipher + i) = rand() * 1000 % 256;
}
extern "C"
u32 getKey(u8*ciphertxt0, u8*ciphertxt1,int Countn) {
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



	//printf_s("%d", nu8 * 2 + Countn * 4 + 16 * 16);

	u8 *cipher1,*cipher2;
	cudaMalloc((void **)&cipher1, Countn * 2 * sizeof(u8));
	cudaMalloc((void **)&cipher2, Countn * 2 * sizeof(u8));
	cudaMemcpy(cipher1, ciphertxt0, Countn * 2 * sizeof(u8), cudaMemcpyHostToDevice);
	cudaMemcpy(cipher2, ciphertxt1, Countn * 2 * sizeof(u8), cudaMemcpyHostToDevice);

	cudaMemcpy(sbox, S_Box, 16 * 16 * sizeof(u8), cudaMemcpyHostToDevice);

	u8 *Record0, *Record1;


	cudaMalloc((void **)&Record0, nu8);
	cudaMalloc((void **)&Record1, nu8);
	u8 mode0 = 0x0e, mode1 = 0x0b;
	uncode << <grid, block >> > (cipher1, Record0, Countn, mode0, mode1);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况

	mode0 = 0x0d;  mode1 = 0x09;
	uncode << <grid, block >> > (cipher2, Record1, Countn, mode0, mode1);
	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况

	dim3 block2(blocks, 1);
	dim3 grid2(roundn, blocks);

	nu8 = blocks * blocks*blocks * sizeof(u32);
	float *maxSEI;
	u32 *maxKey;


	cudaMalloc((void **)&maxSEI, nu8);
	cudaMalloc((void **)&maxKey, nu8);

	kernel << <grid2, block2 >> > (Record0, Record1, Countn, maxSEI, maxKey);


	CHECK(cudaDeviceSynchronize());//检查cuda设备同步情况


	printf("success\n");
	cudaFree(Record0);
	cudaFree(Record1);
	cudaFree(cipher1);
	cudaFree(cipher2);
	cudaFree(maxSEI);
	cudaFree(maxKey);

	return 0;
}