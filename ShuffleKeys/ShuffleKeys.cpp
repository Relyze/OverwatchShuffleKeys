#include <Windows.h>
#include <vector>
#include <iostream>
#include "Zydis/Zydis.h"
#include <unordered_map>
#include <set>
#include <map>
#include <process.h>	
#include "idadefs.h"
#include "scanner.h"

static FILE* file = NULL;
static ZyanU64 retcheck_failed_address = 0;
static void processJumpInstruction(ZydisDecoder& decoder, ZydisDecodedInstruction& instruction, ZydisDecodedOperand operands[], ZyanU64 baseAddress, ZyanUSize& offset, ZyanUSize functionSize, ZyanU8* shuffleKeysData) {
	ZyanU64 absolute_address;
	ZyanStatus status = ZydisCalcAbsoluteAddress(&instruction, &operands[0], baseAddress + offset, &absolute_address);
	if ZYAN_FAILED(status)
		return;

	ZyanUSize relative_offset = absolute_address - baseAddress;
	ZydisDecodedInstruction next_instruction;
	ZydisDecodedOperand next_operands[ZYDIS_MAX_OPERAND_COUNT];

	if (relative_offset > functionSize)
		return;

	// Follow the jump, and check for if it's the retcheck, if it is, then we patch it out.
	status = ZydisDecoderDecodeFull(&decoder, shuffleKeysData + relative_offset, functionSize - relative_offset, &next_instruction, next_operands);
	if ZYAN_FAILED(status) {
		offset += instruction.length;
		return;
	}

	bool retcheck_begin = next_instruction.mnemonic == ZYDIS_MNEMONIC_CMP && next_operands[0].mem.disp.value == -5 && (uint8_t)next_operands[1].imm.value.u == 0xE8;
	if (!retcheck_begin)
		return;

	ZyanUSize next_offset = relative_offset + next_instruction.length;
	status = ZydisDecoderDecodeFull(&decoder, shuffleKeysData + next_offset, functionSize - next_offset, &next_instruction, next_operands);
	if ZYAN_FAILED(status) {
		offset += instruction.length;
		return;
	}

	ZyanUSize first_jump_offset = -1;

	if (ZYDIS_MNEMONIC_JB <= next_instruction.mnemonic <= ZYDIS_MNEMONIC_JZ) {
		while (true) {
			if (next_offset >= functionSize)
				break;

			ZydisDecoderDecodeFull(&decoder, shuffleKeysData + next_offset, functionSize - next_offset, &next_instruction, next_operands);
			if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&next_instruction, &next_operands[0], baseAddress + next_offset, &absolute_address))) {
				ZyanUSize next_relative_offset = absolute_address - baseAddress;

				if (ZYDIS_MNEMONIC_JB <= next_instruction.mnemonic <= ZYDIS_MNEMONIC_JZ) {
					printf("[*] Looking for retcheck failed address candidates: 0x%llx\n", absolute_address - baseAddress);
					// If this is the first offset found, store it since it will be a jump to the retcheck failed case
					if (first_jump_offset == -1) {
						first_jump_offset = next_relative_offset;
						retcheck_failed_address = absolute_address;
						printf("[*] Found retcheck failed address: 0x%llx\n", absolute_address - baseAddress);
					}

					if (next_relative_offset != first_jump_offset && absolute_address != retcheck_failed_address) {
						
						ZydisEncoderRequest request;
						memset(&request, 0, sizeof(request));
						
						// Initialize the encoder request
						ZyanUSize encodedLength = ZYDIS_MAX_INSTRUCTION_LENGTH;

						// Define the new instruction data
						request.mnemonic = ZYDIS_MNEMONIC_JMP;
						request.branch_type = next_instruction.meta.branch_type;
						request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
						request.operand_count = 1;
						request.operands[0].type = next_operands[0].type;
						request.operands[0].imm.u = next_operands[0].imm.value.u;

						if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, shuffleKeysData + next_offset, &encodedLength)))
						{
							printf("[-] Failed to encode instruction\n");
							system("pause");
						}
						else
							printf("\t[+] Patched success jump\n");
						break; // We've found a jnz with a different offset, break out of the loop, since it should be the "retcheck passed" jump
					}
					else {
						for (int i = next_offset; i < next_offset + next_instruction.length; i++)
							shuffleKeysData[i] = 0x90; // NOP out the jump instructions for the retcheck failed case
						printf("\t[+] Nopped fail jump\n");
					}
				}
			}
			next_offset += next_instruction.length;
		}
	}
}

static void removeLeftOverFailureJumps(ZydisDecoder& decoder, ZydisDecodedInstruction& instruction, ZydisDecodedOperand operands[], ZyanU64 baseAddress, ZyanUSize& offset, ZyanUSize functionSize, ZyanU8* shuffleKeysData) {
	ZyanU64 absolute_address;
	ZyanStatus status = ZydisCalcAbsoluteAddress(&instruction, &operands[0], baseAddress + offset, &absolute_address);
	if ZYAN_FAILED(status)
		return;

	if (retcheck_failed_address && absolute_address == retcheck_failed_address) {
		printf("[*] Found additional jump to return address check fail...\n");
		for (int i = offset; i < offset + instruction.length; i++)
			shuffleKeysData[i] = 0x90;
		printf("[+] Nopped additional jump to return address check fail.\n");
	}
}

static ZyanU8* createShuffleKeys(uint32_t shuffleKeysRVA) {
	uint64_t startAddress = ImageBase + shuffleKeysRVA;
	uint64_t endAddress = ImageBase + shuffleKeysRVA + 0x500; // From looking, we probably dont need any instructions past 0x280 bytes, but just incase lets copy 0x500 bytes
	size_t functionSize = endAddress - startAddress + 1;

	// Allocate an RWX buffer and copy the function into so we can later modify it.
	// Note: We're allocating RWX memory, which is an easy detection vector, but for the sake of this example, we're going to do it anyways.
	// Allocating this buffer in an external is perfectly fine, but internally, this is a bad idea, since a warden module *will* find this eventually, unless you can figure out a way to circumvent their checks.
	ZyanU8* shuffleKeysData = (ZyanU8*)VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shuffleKeysData == NULL) {
		printf("[-] Failed to allocate memory\n");
		return nullptr;
	}
	memcpy(shuffleKeysData, (void*)startAddress, functionSize);

	// Initialize the decoder context
	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	// Declare the instruction and operand data structures
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]; // Added for new API
	ZyanUSize offset = 0;

	// Walk the function and patch out the various instructions we need to patch out or modify.
	// i.e. Return address check, lea instructions, et cetera.
	while (offset < functionSize) {
		ZyanStatus status = ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void*>(shuffleKeysData + offset), functionSize - offset, &instruction, operands);
		if (ZYAN_FAILED(status)) {
			offset += instruction.length;
			continue;
		}

		// This is a ghetto fix, but basically, they use "lea REGISTER, shufflekeys" to ensure that the shufflekeys address is the one in the game's memory, otherwise the key will be wrong once shuffled.
		// This is a measure to prevent us from directly copying the function.
		ZydisRegister reg = operands[0].reg.value;

		ZydisEncoderRequest request;
		memset(&request, 0, sizeof(request));

		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA) {
			// Initialize the encoder request
			ZyanUSize encodedLength = ZYDIS_MAX_INSTRUCTION_LENGTH;

			// Define the new instruction data
			request.mnemonic = ZYDIS_MNEMONIC_MOV;
			request.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
			request.operand_count = 2;
			request.operands[0].type = ZYDIS_OPERAND_TYPE_REGISTER;
			request.operands[0].reg.value = reg;
			request.operands[1].type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
			request.operands[1].imm.u = startAddress;

			if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&request, shuffleKeysData + offset, &encodedLength)))
			{
				printf("[-] Failed to encode instruction\n");
				system("pause");
			}
			else {
				offset += encodedLength;
				continue;
			}
		}

		if (ZYDIS_MNEMONIC_JB <= instruction.mnemonic <= ZYDIS_MNEMONIC_JZ)
			processJumpInstruction(decoder, instruction, operands, ImageBase, offset, functionSize, shuffleKeysData);

		offset += instruction.length;
	}

	offset = 0;
	while (offset < functionSize) {
		ZyanStatus status = ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void*>(shuffleKeysData + offset), functionSize - offset, &instruction, operands);
		if (ZYAN_FAILED(status)) {
			offset += instruction.length;
			continue;
		}

		if (ZYDIS_MNEMONIC_JB <= instruction.mnemonic <= ZYDIS_MNEMONIC_JZ)
			removeLeftOverFailureJumps(decoder, instruction, operands, ImageBase, offset, functionSize, shuffleKeysData);
		offset += instruction.length;
	}

	return shuffleKeysData;
}

static int mainThread(HMODULE hModule)
{
	std::string keys_signature = "C8 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? 48 8D ?? ?? ?? 48 B8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 ?? ?? ?? E8";
	uintptr_t first_key = arrayscan_module(keys_signature, ImageBase).at(0) + 0x3; // Address of the first key value.
	if (first_key <= 0x3) {
		printf("[-] Failed to find pattern\n"); // Should this ever be reached, you will want to find a new signature to scan for, and adjust the offsets that I've hardcoded manually.
		return 0;
	}
	uintptr_t second_key = first_key + 0x14; // Address of the second key value.
	uintptr_t shuffle_keys = first_key + 0x22; // Shufflekeys function call relative call; we'll use this to calculate the RVA of the function.

	uint64_t Key1 = *(uint64_t*)(first_key);
	uint64_t Key2 = *(uint64_t*)(second_key);
	uint32_t shuffleKeysRVA = shuffle_keys + 4 + *(uint32_t*)shuffle_keys - ImageBase; // Get the address of the next instruction after the call, and add the relative offset to the function, then subtract the ImageBase to get the function's RVA.

	ZyanU8* shuffleKeysData = createShuffleKeys(shuffleKeysRVA);
	
	printf("[+] Cloned ShuffleKeys	: %p\n", shuffleKeysData);
	printf("[*] Original ShuffleKeys: %llx\n", ImageBase + shuffleKeysRVA);
	printf("[*] ShuffleKeys Relative Virtual Address: %x\n", shuffleKeysRVA);

	printf("[*] Original First Key: %llx\n", Key1);
	printf("[*] Original Second Key: %llx\n", Key2);

	// Create our new shuffle keys function by copying the original function and modifying it.
	void(*fnShuffleKeys)(uint64_t*, uint64_t*) = reinterpret_cast<void(*)(uint64_t*, uint64_t*)>(shuffleKeysData);
	if(shuffleKeysData != nullptr)
		fnShuffleKeys(&Key2, &Key1);

	printf("[*] Shuffled First Key: %llx\n", Key1);
	printf("[*] Shuffled Second Key: %llx\n", Key2);

	return 0;
}

static BOOL WINAPI DllMain(const HMODULE hModule, const DWORD fdwReason, LPVOID lpReserved)
{

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		freopen_s(&file, "CONIN$", "rb", stdin);
		freopen_s(&file, "CONOUT$", "wb", stdout);

		DisableThreadLibraryCalls(hModule);
		_beginthread((_beginthread_proc_type)mainThread, 0, hModule);
	}
	return TRUE;
}