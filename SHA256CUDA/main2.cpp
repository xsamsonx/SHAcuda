
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <iostream>
#include <cmath>
#include <thread>
#include <iomanip>
#include <string>
#include <cassert>
#include "main.h"
#include "sha256.cuh"

#define BLOCK_SIZE 256
#define SHA_PER_ITERATIONS 8'388'608
#define NUMBLOCKS (SHA_PER_ITERATIONS + BLOCK_SIZE - 1) / BLOCK_SIZE


char nonce[65];

void bignum_add_host(size_t idx, char* a, char* b) {
	int i = 0, alen, t;
	for (i = 0; a[i]; i++) {
		b[i] = a[i];
	}
	alen = i;
	char *s = nullptr;
	int k = 0, p;
	while (idx) {
		p = idx % 10;
		idx /= 10;
		s[k++] = p + '0';
	}
	p = 0;
	for (t = 0; t < k || t < alen; t++) {
		if (t < alen) p += b[t] - '0';
		if (t < k) p += s[t] - '0';
		b[t] = p % 10 + '0';
		p /= 10;
	}
	while (p) {
		b[t] = p % 10 + '0';
		p /= 10;
		t++;
	}
	b[t] = 0;
	return;
}

__device__ int EncodeBase58(char input, const int len, unsigned char result[]) {
	const char * const ALPHABET =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	/*const char ALPHABET_MAP[128] = {
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
		-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
		22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
		-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
		47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
	};*/
	unsigned char digits[64];
	int digitslen = 1;
	for (int i = 0; i < len; i++) {
		unsigned int carry = (unsigned int)input[i];
		for (int j = 0; j < digitslen; j++) {
			carry += (unsigned int)(digits[j]) << 8;
			digits[j] = (unsigned char)(carry % 58);
			carry /= 58;
		}
		while (carry > 0) {
			digits[digitslen++] = (unsigned char)(carry % 58);
			carry /= 58;
		}
	}
	int resultlen = 0;
	// leading zero bytes
	for (; resultlen < len && input[resultlen] == 0;)
		result[resultlen++] = '1';
	// reverse
	for (int i = 0; i < digitslen; i++)
		result[resultlen + i] = ALPHABET[digits[digitslen - 1 - i]];
	result[digitslen + resultlen] = 0;
	return digitslen + resultlen;
}

__device__ int my_strlen(unsigned char *str) {
	int i = 0;
	while (str[i++] != '\0');
	i--;
	return i;
}

/*__device__ char * my_strcpy(char *dest, const char *src) {
	int i = 0;
	do {
		dest[i] = src[i];
	} while (src[i++] != 0);
	return dest;
}*/

extern __shared__ char array[];
__global__ void sha256_kernel(const char* in_input_string, size_t in_input_string_size, char * nonce_offset) {

	// If this is the first thread of the block, init the input string in shared memory
	char* in = (char*) &array[0];
	if (threadIdx.x == 0) {
		memcpy(in, in_input_string, in_input_string_size + 1);
	}

	__syncthreads(); // Ensure the input string has been written in SMEM

	uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	char* nonce_out = idx + nonce_offset;

	// The first byte we can write because there is the input string at the begining	
	// Respects the memory padding of 8 bit (char).
	size_t const minArray = static_cast<size_t>(ceil((in_input_string_size + 1) / 8.f) * 8);
	
	uintptr_t sha_addr = threadIdx.x * (64) + minArray;
	uintptr_t nonce_addr = sha_addr + 32;

	unsigned char* sha = (unsigned char*)&array[sha_addr];
	unsigned char* out = (unsigned char*)&array[nonce_addr];
	memset(out, 0, 32);

	int size = my_strlen(out);

	EncodeBase58((char) nonce_out, (int) size, out);

	assert(size <= 32);

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, out, size);//Do i recieve the right size here?
	sha256_update(&ctx, (unsigned char *)in, in_input_string_size);
	sha256_final(&ctx, sha);

	if (sha[0] == 0x00) {
		printf("%u\n", nonce_out);//base58 conversion missing for print
	}
}

void pre_sha256() {
	checkCudaErrors(cudaMemcpyToSymbol(dev_k, host_k, sizeof(host_k), 0, cudaMemcpyHostToDevice));
}

int main() {

	cudaSetDevice(0);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferShared);

	std::string in;
	
	std::cout << " Nonce-Suffix : "; //for testing i use AAAA
	std::cin >> in;


	std::cout << " start at number : "; //for testing i use 1
	std::cin >> nonce;

	const size_t input_size = in.size();

	// Input string for the device
	char *d_in = nullptr;

	// Create the input string for the device
	cudaMalloc(&d_in, input_size + 1);
	cudaMemcpy(d_in, in.c_str(), input_size + 1, cudaMemcpyHostToDevice);


	pre_sha256();

	size_t dynamic_shared_size = (ceil((input_size + 1) / 8.f) * 8) + (64 * BLOCK_SIZE);
	int a = 0;
	
	for (a = 0; a < 2; a++) {
	//for (;;) {
		sha256_kernel << < NUMBLOCKS, BLOCK_SIZE, dynamic_shared_size >> > (d_in, input_size, nonce);

		cudaError_t err = cudaDeviceSynchronize();
		if (err != cudaSuccess) {
			throw std::runtime_error("Device error");
		}
		bignum_add_host(SHA_PER_ITERATIONS, nonce, nonce);
		//nonce += SHA_PER_ITERATIONS;
	}

}