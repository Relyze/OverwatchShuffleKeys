#pragma once

#include <Windows.h>
#include <future>
#include <type_traits>
#include <winternl.h>
#include <TlHelp32.h>
#include <codecvt>
#include <locale>
#include <string>
#include <sstream>
#include <cstdint>
#include <vector>
#include <memory>
#include <iostream>
#include <stdexcept>  // Include the exception header

struct HandleData {
    unsigned long processId;
    HWND windowHandle;
};

template<typename type>
static std::vector<uintptr_t> arrayscan(const std::string& arrays, type start_address, size_t size) {
    std::vector<uintptr_t> result;
    std::vector<std::pair<uint8_t, bool>> splits;

    //splits
    char delimiter = ' ';
    std::stringstream ss(arrays);

    std::string temp;
    while (std::getline(ss, temp, delimiter)) {
        uint8_t value = 0xCC;
        bool mask = temp == "?" || temp == "??";
        if (!mask) {
            value = (uint8_t)strtol(temp.c_str(), nullptr, 16);
        }
        splits.push_back({ value, mask });
    }

    std::vector<uint32_t> allows = {
        PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
        PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY
    };
    uintptr_t start = (uintptr_t)start_address;
    uintptr_t end = start + size;
    while (start < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        VirtualQuery((const void*)start, &mbi, sizeof(mbi));
        if ((mbi.BaseAddress) &&
            (mbi.RegionSize) &&
            (mbi.State == MEM_COMMIT) &&
            (std::find(allows.begin(), allows.end(), mbi.Protect) != allows.end())) {
            for (uintptr_t n = (uintptr_t)mbi.BaseAddress; n < (uintptr_t)mbi.BaseAddress + mbi.RegionSize - splits.size(); n++) {
                if (std::equal(splits.begin(), splits.end(), (uint8_t*)n, [](const auto& find, uint8_t original) {
                    return find.second || find.first == original;
                    })) {
                    result.push_back(n);
                }
            }
        }
        uintptr_t next_address = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        start = next_address > start ? next_address : end;
    }

    return result;
}

template<typename type>
static std::vector<uintptr_t> arrayscan_module(const std::string& arrays, type module_address) {
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_address;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)((uintptr_t)module_address + dos_header->e_lfanew);
    return arrayscan(arrays, module_address, nt_headers->OptionalHeader.SizeOfImage);
}

// Just a wrapper for memory arrays... Nothing fancy.
template<typename T>
class SafeDynamicArray {
private:
    T* data;
    size_t capacity;
    size_t size;
public:
    SafeDynamicArray(size_t initialCapacity = 10) : capacity(initialCapacity), size(0) {
        data = new T[initialCapacity];
    }

    ~SafeDynamicArray() {
        delete[] data;
    }

    void resize(size_t newCapacity) {
        T* newData = new T[newCapacity];
        for (size_t i = 0; i < size; ++i) {
            newData[i] = data[i];
        }
        delete[] data;
        data = newData;
        capacity = newCapacity;
    }

    void push_back(const T& value) {
        if (size == capacity) {
            // Expand the array
            size_t newCapacity = capacity * 2;
            resize(newCapacity);
        }
        data[size++] = value;
    }

    size_t getSize() const {
        return size;
    }

    T& operator[](size_t index) {
        if (index >= size) {
            throw std::out_of_range("Index out of range");
        }
        return data[index];
    }

    const T& operator[](size_t index) const {
        if (index >= size) {
            throw std::out_of_range("Index out of range");
        }
        return data[index];
    }
};

inline const uint64_t ImageBase = *reinterpret_cast<uint64_t*>(__readgsqword(0x60) + 0x10);
