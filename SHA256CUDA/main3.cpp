
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

__device__ int base58_encode(const char *in, size_t in_len, char *out, size_t *out_len) {

	static const char alphabet[] =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	if (!in_len) {
		*out_len = 0;
		return 0;
	}
	if (!(*out_len)) {
		*out_len = 0;
		return -1;
	}

	// leading zeroes
	size_t total = 0;
	for (size_t i = 0; i < in_len && !in[i]; ++i) {
		if (total == *out_len) {
			*out_len = 0;
			return -1;
		}
		out[total++] = alphabet[0];
	}
	in += total;
	in_len -= total;
	out += total;

	// encoding
	size_t idx = 0;
	for (size_t i = 0; i < in_len; ++i) {
		unsigned int carry = (unsigned char)in[i];
		for (size_t j = 0; j < idx; ++j) {
			carry += (unsigned int)out[j] << 8;
			out[j] = (unsigned char)(carry % 58);
			carry /= 58;
		}
		while (carry > 0) {
			if (total == *out_len) {
				*out_len = 0;
				return -1;
			}
			total++;
			out[idx++] = (unsigned char)(carry % 58);
			carry /= 58;
		}
	}

	// apply alphabet and reverse
	size_t c_idx = idx >> 1;
	for (size_t i = 0; i < c_idx; ++i) {
		char s = alphabet[(unsigned char)out[i]];
		out[i] = alphabet[(unsigned char)out[idx - (i + 1)]];
		out[idx - (i + 1)] = s;
	}
	if ((idx & 1)) {
		out[c_idx] = alphabet[(unsigned char)out[c_idx]];
	}
	*out_len = total;
	return 0;
}

__global__ void sha256_kernel(const char* in_input_string, size_t in_input_string_size, char * nonce_offset) {
	__shared__ char in [32];

	// If this is the first thread of the block, init the input string in shared memory
	if (threadIdx.x == 0) {
		memcpy(in, in_input_string, in_input_string_size);
	}

	__syncthreads(); // Ensure the input string has been written in SMEM

	uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	char* nonce_out = idx + nonce_offset;
	char* out = 0;
	
	static size_t out_len;
	static size_t in_len;

	in_len = sizeof(nonce_out);
	out_len = sizeof(out);

	base58_encode(nonce_out, in_len, out, &out_len);

	unsigned char sha[32];

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (unsigned char *)out, out_len);
	sha256_update(&ctx, (unsigned char *)in, in_input_string_size);
	sha256_final(&ctx, sha);

	if (sha[0] == 0x00) {
		printf("%s\n", out);//supposed to print nonce in base58 WITHOUT message "AAAA"
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
	
	for (a = 0; a < 2; a++) {//small loop to see if loop nonce-increment is working
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