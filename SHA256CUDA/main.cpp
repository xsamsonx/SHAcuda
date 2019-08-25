
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

#define SHOW_INTERVAL_MS 500
#define BLOCK_SIZE 256
#define SHA_PER_ITERATIONS 8'388'608
#define NUMBLOCKS (SHA_PER_ITERATIONS + BLOCK_SIZE - 1) / BLOCK_SIZE

// Output string by the device read by host
char *g_out = nullptr;
unsigned char *g_hash_out = nullptr;
int *g_found = nullptr;

static uint64_t nonce = 0;
static uint64_t user_nonce = 0;

// Does the same as sprintf(char*, "%d%s", int, const char*) but a bit faster
__device__ size_t nonce_to_str(uint64_t nonce, unsigned char* out) {
	uint64_t result = nonce;
	uint8_t remainder;
	size_t nonce_size = nonce == 0 ? 1 : floor(log10((double)nonce)) + 1;
	size_t i = nonce_size;
	while (result >= 10) {
		remainder = result % 10;
		result /= 10;
		out[--i] = remainder + '0';
	}

	out[0] = result + '0';
	i = nonce_size;
	out[i] = 0;
	return i;
}


extern __shared__ char array[];
__global__ void sha256_kernel(char* out_input_string_nonce, unsigned char* out_found_hash, int *out_found, const char* in_input_string, size_t in_input_string_size, uint64_t nonce_offset) {

	// If this is the first thread of the block, init the input string in shared memory
	char* in = (char*) &array[0];
	if (threadIdx.x == 0) {
		memcpy(in, in_input_string, in_input_string_size + 1);
	}

	__syncthreads(); // Ensure the input string has been written in SMEM

	uint64_t idx = blockIdx.x * blockDim.x + threadIdx.x;
	uint64_t nonce = idx + nonce_offset;

	// The first byte we can write because there is the input string at the begining	
	// Respects the memory padding of 8 bit (char).
	size_t const minArray = static_cast<size_t>(ceil((in_input_string_size + 1) / 8.f) * 8);
	
	uintptr_t sha_addr = threadIdx.x * (64) + minArray;
	uintptr_t nonce_addr = sha_addr + 32;

	unsigned char* sha = (unsigned char*)&array[sha_addr];
	unsigned char* out = (unsigned char*)&array[nonce_addr];
	memset(out, 0, 32);

	size_t size = nonce_to_str(nonce, out);

	assert(size <= 32);

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, out, size);
	sha256_update(&ctx, (unsigned char *)in, in_input_string_size);
	sha256_final(&ctx, sha);

	if (sha[0] == 0x00) {
		printf("%u\n", nonce);
	}
}

void pre_sha256() {
	checkCudaErrors(cudaMemcpyToSymbol(dev_k, host_k, sizeof(host_k), 0, cudaMemcpyHostToDevice));
}

int main() {

	cudaSetDevice(0);
	cudaDeviceSetCacheConfig(cudaFuncCachePreferShared);

	std::string in;
	
	std::cout << " Start : ";
	std::cin >> in;


	std::cout << "Nonce : ";
	std::cin >> user_nonce;

	const size_t input_size = in.size();

	// Input string for the device
	char *d_in = nullptr;

	// Create the input string for the device
	cudaMalloc(&d_in, input_size + 1);
	cudaMemcpy(d_in, in.c_str(), input_size + 1, cudaMemcpyHostToDevice);

	cudaMallocManaged(&g_out, input_size + 32 + 1);
	cudaMallocManaged(&g_hash_out, 32);
	cudaMallocManaged(&g_found, sizeof(int));
	*g_found = 0;

	nonce += user_nonce;

	pre_sha256();

	size_t dynamic_shared_size = (ceil((input_size + 1) / 8.f) * 8) + (64 * BLOCK_SIZE);

	for (;;) {
		sha256_kernel << < NUMBLOCKS, BLOCK_SIZE, dynamic_shared_size >> > (g_out, g_hash_out, g_found, d_in, input_size, nonce);

		cudaError_t err = cudaDeviceSynchronize();
		if (err != cudaSuccess) {
			throw std::runtime_error("Device error");
		}

		nonce += SHA_PER_ITERATIONS;
	}

	cudaFree(g_out);
	cudaFree(g_hash_out);
	cudaFree(g_found);

	cudaFree(d_in);

	cudaDeviceReset();
	return 0;
}