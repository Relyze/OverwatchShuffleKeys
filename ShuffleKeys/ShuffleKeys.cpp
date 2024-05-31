#include <Windows.h>
#include <vector>
#include <iostream>
#include "Zydis/Zydis.h"
#include <unordered_map>
#include <set>
#include <map>
#include <process.h>
#include "idadefs.h"
static FILE* file = NULL;

// Defined start and end offsets for better maintainability
#define SHUFFLE_KEYS_START 0xB6630
#define SHUFFLE_KEYS_END SHUFFLE_KEYS_START + 0x500 // idk, probably dont need any instructions past 280 bytes

ZyanU8* shuffleKeysData = nullptr;
static ZyanU64 retcheck_failed_address = 0;
uint64_t baseAddress = 0;
static void processJumpInstruction(ZydisDecoder& decoder, ZydisDecodedInstruction& instruction, ZydisDecodedOperand operands[], ZyanU64 baseAddress, ZyanUSize& offset, ZyanUSize functionSize) {
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
					printf("looking for retcheck failed address candidates: %llx\n", absolute_address - baseAddress);
					// If this is the first offset found, store it since it will be a jump to the retcheck failed case
					if (first_jump_offset == -1) {
						first_jump_offset = next_relative_offset;
						retcheck_failed_address = absolute_address;
						printf("found retcheck failed address: %llx\n", absolute_address - baseAddress);
					}

					if (next_relative_offset != first_jump_offset && absolute_address != retcheck_failed_address) {
						if (shuffleKeysData[next_offset] != 0x0F)
							shuffleKeysData[next_offset] = 0xEB;
						if (shuffleKeysData[next_offset] == 0x0F) // longer opcode
						{
							shuffleKeysData[next_offset] = 0x90;
							shuffleKeysData[next_offset + 1] = 0xE9;
						}
						printf("\tpatched success jump\n");
						break; // We've found a jnz with a different offset, break out of the loop, since it should be the "retcheck passed" jump
					}
					else {
						for (int i = next_offset; i < next_offset + next_instruction.length; i++)
							shuffleKeysData[i] = 0x90; // NOP out the jump instructions for the retcheck failed case
						printf("\tnopped fail jump\n");
					}
				}
			}
			next_offset += next_instruction.length;
		}
	}
}

static void removeLeftOverFailureJumps(ZydisDecoder& decoder, ZydisDecodedInstruction& instruction, ZydisDecodedOperand operands[], ZyanU64 baseAddress, ZyanUSize& offset, ZyanUSize functionSize) {
	ZyanU64 absolute_address;
	ZyanStatus status = ZydisCalcAbsoluteAddress(&instruction, &operands[0], baseAddress + offset, &absolute_address);
	if ZYAN_FAILED(status)
		return;

	if (retcheck_failed_address && absolute_address == retcheck_failed_address) {
		printf("found additional fail jump...\n");
		for (int i = offset; i < offset + instruction.length; i++)
			shuffleKeysData[i] = 0x90;
		printf("nopped additional fail jump.\n");
	}
}

static void createShuffleKeys() {
	baseAddress = *reinterpret_cast<uint64_t*>(__readgsqword(0x60) + 0x10);
	uint64_t startAddress = baseAddress + SHUFFLE_KEYS_START;
	uint64_t endAddress = baseAddress + SHUFFLE_KEYS_END;
	size_t functionSize = endAddress - startAddress + 1;

	shuffleKeysData = (ZyanU8*)VirtualAlloc(NULL, functionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (shuffleKeysData == NULL) {
		printf("Failed to allocate memory\n");
		return;
	}
	memcpy(shuffleKeysData, (void*)startAddress, functionSize);

	ZydisDecoder decoder;
	ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZyanUSize offset = 0;
	ZydisDecodedInstruction instruction;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]; // Added for new API

	while (offset < functionSize) {
		ZyanStatus status = ZydisDecoderDecodeFull(&decoder, reinterpret_cast<void*>(shuffleKeysData + offset), functionSize - offset, &instruction, operands);
		if (ZYAN_FAILED(status)) {
			offset += instruction.length;
			continue;
		}

		// This is a ghetto fix, but basically, they use "lea reg, shufflekeys" to ensure that the shufflekeys address is the one in the game, otherwise the key will be wrong once shuffled...
		ZydisRegister reg = operands[0].reg.value;
		if (instruction.mnemonic == ZYDIS_MNEMONIC_LEA) {
			ZyanU8 opcode;
			switch (reg) {
			case ZYDIS_REGISTER_RAX: opcode = 0xB8; break;
			case ZYDIS_REGISTER_RBX: opcode = 0xBB; break;
			case ZYDIS_REGISTER_RCX: opcode = 0xB9; break;
			case ZYDIS_REGISTER_RDX: opcode = 0xBA; break;
			case ZYDIS_REGISTER_RDI: opcode = 0xBF; break;
			case ZYDIS_REGISTER_RSI: opcode = 0xBE; break;
			case ZYDIS_REGISTER_RBP: opcode = 0xBD; break;
			case ZYDIS_REGISTER_RSP: opcode = 0xBC; break;
			default:
				break;
			}
			shuffleKeysData[offset] = 0x48;
			shuffleKeysData[offset + 1] = opcode;
			*(uint64_t*)(shuffleKeysData + offset + 2) = startAddress;
		}

		if (ZYDIS_MNEMONIC_JB <= instruction.mnemonic <= ZYDIS_MNEMONIC_JZ) {
			processJumpInstruction(decoder, instruction, operands, baseAddress, offset, functionSize);
		}
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
			removeLeftOverFailureJumps(decoder, instruction, operands, baseAddress, offset, functionSize);
		offset += instruction.length;
	}
}

static int mainThread(HMODULE hModule)
{
	createShuffleKeys();
	void(__fastcall * fnShuffleKeys)(uint64_t*, uint64_t*) = reinterpret_cast<void(__fastcall*)(uint64_t*, uint64_t*)>(shuffleKeysData);

	printf("our shufflekeys function: %p\n", shuffleKeysData);
	printf("ow shufflekeys: %llx\n", baseAddress + SHUFFLE_KEYS_START);

	// Hardcoded, but you could have this entire project dynamically update by finding the shuffle keys function address and the two keys.
	uint64_t Key1 = 0x73D2DD7AB3E2E0CE;
	uint64_t Key2 = 0x20405DAF8E8B8108;

	printf("Original Key1: %llx\n", Key1);
	printf("Original Key2: %llx\n", Key2);

	fnShuffleKeys(&Key2, &Key1);

	printf("Shuffled Key1: %llx\n", Key1);
	printf("Shuffled Key2: %llx\n", Key2);

	return 0;
}

BOOL WINAPI DllMain(const HMODULE hModule, const DWORD fdwReason, LPVOID lpReserved)
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