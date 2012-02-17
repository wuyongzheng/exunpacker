#include <windows.h>
#include <psapi.h>
#include <stdio.h>

static char *name_protect (DWORD protect)
{
	static char buff[32];

	switch (protect & 0xff) {
		case 0x01: strcpy(buff, "NOA"); break;
		case 0x02: strcpy(buff, "R/O"); break;
		case 0x04: strcpy(buff, "R/W"); break;
		case 0x08: strcpy(buff, "W/C"); break;
		case 0x10: strcpy(buff, "EXE"); break;
		case 0x20: strcpy(buff, "X/R"); break;
		case 0x40: strcpy(buff, "XRW"); break;
		case 0x80: strcpy(buff, "XWC"); break;
		default: sprintf(buff, "0x%x", protect); return buff;
	}
	if (protect & 0xf00 == 0x100)
		strcat(buff, ",G");
	if (protect & 0xf00 == 0x100)
		strcat(buff, ",NC");
	if (protect & 0xf00 == 0x100)
		strcat(buff, ",WC");

	return buff;
}

static char *name_type (DWORD type)
{
	static char buff[32];
	switch (type) {
		case 0x1000000: return "IMG";
		case 0x40000: return "MAP";
		case 0x20000: return "PRV";
	}
	sprintf(buff, "0x%x", type);
	return buff;
}

static char *name_state (DWORD state)
{
	static char buff[32];
	switch (state) {
		case 0x1000: return "C";
		case 0x10000: return "F";
		case 0x2000: return "R";
	}
	sprintf(buff, "0x%x", state);
	return buff;
}

static void enum_maps (HANDLE process)
{
	static SYSTEM_INFO sysinfo;
	MEMORY_BASIC_INFORMATION meminfo;
	unsigned int nextbase;

	GetSystemInfo(&sysinfo);
//	printf("info: dwPageSize=%d, lpMinimumApplicationAddress=0x%08x, lpMaximumApplicationAddress=0x%08x\n",
//			sysinfo.dwPageSize, sysinfo.lpMinimumApplicationAddress, sysinfo.lpMaximumApplicationAddress);

	printf("baseaddr allobase   size   apt pro typ s\n");
	nextbase = (unsigned int)sysinfo.lpMinimumApplicationAddress;
	while (nextbase < (unsigned int)sysinfo.lpMaximumApplicationAddress) {
		if (VirtualQueryEx(process, (void *)nextbase, &meminfo, sizeof(meminfo)) != sizeof(meminfo)) {
			printf("error: VirtualQueryEx failed.\n");
			break;
		}

		if (meminfo.State != MEM_FREE) {
			printf("%08x %08x %8x %s %s %s %s\n",
					meminfo.BaseAddress, meminfo.AllocationBase, meminfo.RegionSize,
					name_protect(meminfo.AllocationProtect),
					meminfo.State == MEM_RESERVE ? "   " : name_protect(meminfo.Protect),
					name_type(meminfo.Type),
					name_state(meminfo.State));
		}
		nextbase = (unsigned int)meminfo.BaseAddress + (unsigned int)meminfo.RegionSize;
		if (nextbase < (unsigned int)meminfo.BaseAddress) // overflow
			break;
	}
	printf("baseaddr allobase   size   apt pro typ s\n");
	//printf("check MEMORY_BASIC_INFORMATION @ http://msdn.microsoft.com/en-us/library/windows/desktop/aa366775.aspx\n");
}

static void enum_modules (HANDLE process)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;
	int i;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded) == 0) {
		printf("error: EnumProcessModules() failed\n");
		return;
	}

	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		char filename[1024];
		char basename[512];
		MODULEINFO moduleinfo;

		if (GetModuleFileNameEx(process, hMods[i], filename, sizeof(filename)) == 0) {
			printf("error: GetModuleFileNameEx() failed\n");
			continue;
		}
		if (GetModuleBaseName(process, hMods[i], basename, sizeof(basename)) == 0) {
			printf("error: GetModuleBaseName() failed\n");
			continue;
		}
		if (GetModuleInformation(process, hMods[i], &moduleinfo, sizeof(moduleinfo)) == 0) {
			printf("error: GetModuleInformation() failed\n");
			continue;
		}
		printf("%p %p %p %6x %s %s\n",
				hMods[i],
				moduleinfo.lpBaseOfDll, moduleinfo.EntryPoint, moduleinfo.SizeOfImage,
				basename, filename);
	}
}

int main (int argc, char *argv[])
{
	HANDLE process;

	if (argc != 2 || atoi(argv[1]) == 0) {
		printf("Usage: %s pid\n", argv[0]);
		return 1;
	}

	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, atoi(argv[1]));
	if (process == NULL) {
		printf("error: OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, %d) failed\n", atoi(argv[1]));
		return 1;
	}

	enum_maps(process);
	enum_modules(process);

	CloseHandle(process);

	return 0;
}
