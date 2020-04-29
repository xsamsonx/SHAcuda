#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <random>
#include <chrono>
#include <cmath>
#include <thread>
#include <iomanip>
#include <string>
#include <cassert>
#include "main.h"

#include "sha256.cuh"


#define BLOCK_SIZE 256

static uint64_t noncex = 0;

__device__ int my_strlen(char *str) {
	int i = 0;
	while (str[i++] != '\0');
	i--;
	return i;
}

__device__ void swap(unsigned char& a, unsigned char& b) {

	char tmp = a;
	a = b;
	b = tmp;
}

__device__ void reverse(unsigned char* s, size_t n) {

	size_t count = n / 2;
	size_t head = 0, tail = n;
	while (count--) {
		swap(s[head++], s[--tail]);
	}
}

__device__  int decode_char(char ch) {

	if (ch >= '1' && ch <= '9')
		return ch - '1';

	if (ch >= 'A' && ch <= 'H')
		return ch - 'A' + 9;

	if (ch >= 'J' && ch <= 'N')
		return ch - 'J' + 17;

	if (ch >= 'P' && ch <= 'Z')
		return ch - 'P' + 22;

	if (ch >= 'a' && ch <= 'k')
		return ch - 'a' + 33;

	if (ch >= 'm' && ch <= 'Z')
		return ch - 'm' + 44;

	return -1;
}
__device__ const char* Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
__device__ const int MaxLength = 44 + 1;
__device__ size_t encode(uint64_t id_num, unsigned char* output, size_t output_len) {
	if (output == 0)
		return 0;

	if (output_len < MaxLength)
		return 0;

	size_t output_wpos = 0;

	uint64_t num;
	int remainder;

	while (id_num > 0) {

		num = id_num / 58;
		remainder = id_num % 58;

		if (output_wpos < output_len) {
			output[output_wpos++] = Chars[remainder];
		}
		else {
			output[0] = '\0';
			return 0;
		}

		id_num = num;
	}

	output[output_wpos] = '\0';
	reverse(output, output_wpos);

	return output_wpos;
}

extern __shared__ char array[];
__global__ void sha256_kernel(const char* in_input_string, size_t in_input_string_size, uint64_t noncex_offset) {

	char* in = (char*) &array[0];
	if (threadIdx.x == 0) {
		memcpy(in, in_input_string, in_input_string_size + 1);
	}

	__syncthreads();

	int idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint64_t nonce = noncex_offset + idx;

	size_t const minArray = static_cast<size_t>(ceil((in_input_string_size + 1) / 8.f) * 8);

	uintptr_t sha_addr = threadIdx.x * (64) + minArray;
	uintptr_t nonce_addr = sha_addr + 32;

	unsigned char* sha = (unsigned char*)&array[sha_addr];
	unsigned char* out = (unsigned char*)&array[nonce_addr];
	memset(out, 0, 32);


	size_t out_size = 0;
	size_t size = encode(uint64_t(nonce), out, (int)&out_size);

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, out, size);

	sha256_update(&ctx, (unsigned char *)in, in_input_string_size);
	sha256_final(&ctx, sha);
	if (sha[31] == 0xff) {
		printf("%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x\n",
			sha[0], sha[1], sha[2], sha[3], sha[4], sha[5], sha[6], sha[7], sha[8], sha[9], sha[10], sha[11], sha[12], sha[13], sha[14], sha[15],
			sha[16], sha[17], sha[18], sha[19], sha[20], sha[21], sha[22], sha[23], sha[24], sha[25], sha[26], sha[27], sha[28], sha[29], sha[30], sha[31]);
	}
}

void pre_sha256() {
	checkCudaErrors(cudaMemcpyToSymbol(dev_k, host_k, sizeof(host_k), 0, cudaMemcpyHostToDevice));
}

int main() {

	std::string in = "member-ID";

	cudaSetDevice(0);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferShared);

	const size_t input_size = in.size();

	char *d_in = nullptr;

	cudaMalloc(&d_in, input_size + 1);
	cudaMemcpy(d_in, in.c_str(), input_size + 1, cudaMemcpyHostToDevice);

	pre_sha256();

	size_t dynamic_shared_size = (ceil((input_size + 1) / 8.f) * 8) + (64 * BLOCK_SIZE);

	noncex = 1;

	for (;;) {
		sha256_kernel << < 1440, 256, dynamic_shared_size >> > (d_in, input_size, noncex);

		cudaError_t err = cudaDeviceSynchronize();
		if (err != cudaSuccess) {
			throw std::runtime_error("Device error");
		}

		noncex += 737280;

	}
}
