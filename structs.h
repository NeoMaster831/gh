#pragma once
#include "pch.h"

using namespace std;

class ProcessExt {
public:
	HANDLE handle;
	DWORD pid;
	vector<MODULEENTRY32> modules;
	
	ProcessExt() {
		this->handle = nullptr;
		this->pid = 0;
	}

	void get_pid(string name) {
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
		PROCESSENTRY32 entry; entry.dwSize = sizeof(entry);
		for (bool valid = Process32First(snap, &entry); valid; valid = Process32Next(snap, &entry)) {
			if (!stricmp(name.c_str(), (const char*)entry.szExeFile)) {
				this->pid = entry.th32ProcessID;
			}
		}
	}

	void open() {
		this->handle = OpenProcess(PROCESS_ALL_ACCESS, 0, this->pid);
	}

	void get_modules() {
		this->modules.clear(); // Refresh
		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->pid);
		MODULEENTRY32 entry; entry.dwSize = sizeof(entry);
		for (bool valid = Module32First(snap, &entry); valid; valid = Module32Next(snap, &entry)) {
			this->modules.push_back(entry);
		}
	}

	// mem.cpp
	vector<BYTE> readn(uintptr_t wh, SIZE_T sz);
	
	template <class T>
	T read(uintptr_t wh);
	
	template <class T>
	void write(uintptr_t wh, T what);

	vector<BYTE> dump(uintptr_t start, uintptr_t end);
	
	uintptr_t _pat_basic(const BYTE* pat, const char* mask, uintptr_t start, SIZE_T sz);

	uintptr_t _pat_dump(const BYTE* pat, const char* mask, uintptr_t start, const BYTE* dump);

	uintptr_t pat_scan(const BYTE* pat, const char* mask, uintptr_t start, uintptr_t end, string mode);

};