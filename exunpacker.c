#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define MAXMODULES 500
void *module_base[MAXMODULES];
int module_size[MAXMODULES];
int module_count = 0;

char *outprefix = "unpacker-";

static void dump_to_file (HANDLE process, void *base, int size)
{
	char outfile[64];
	char buffer[64 * 1024];
	int ptr = 0;
	FILE *outfp;

	_snprintf(outfile, sizeof(outfile), "%s%p.bin", outprefix, base);
	outfile[sizeof(outfile)-1] = '\0';
	outfp = fopen(outfile, "wb");

	while (ptr < size) {
		SIZE_T sizetoread = sizeof(buffer) < size - ptr ? sizeof(buffer) : size - ptr;
		SIZE_T sizeread;
		if (ReadProcessMemory(process, (char *)base + ptr, buffer, sizetoread, &sizeread) == 0) {
			printf("failed to read.\n");
			break;
		}
		if (sizetoread != sizeread) {
			printf("failed to read..\n");
			break;
		}
		fwrite(buffer, sizetoread, 1, outfp);
		ptr += sizetoread;
	}

	fclose(outfp);
}

static void enum_maps (HANDLE process)
{
	static SYSTEM_INFO sysinfo;
	MEMORY_BASIC_INFORMATION meminfo;
	unsigned int nextbase;

	GetSystemInfo(&sysinfo);

	nextbase = (unsigned int)sysinfo.lpMinimumApplicationAddress;
	while (nextbase < (unsigned int)sysinfo.lpMaximumApplicationAddress) {
		if (VirtualQueryEx(process, (void *)nextbase, &meminfo, sizeof(meminfo)) != sizeof(meminfo)) {
			printf("error: VirtualQueryEx failed.\n");
			break;
		}

		if (meminfo.State == MEM_COMMIT && meminfo.RegionSize > 0) {
			if (meminfo.Protect == PAGE_EXECUTE) {
				printf("%p %x is PAGE_EXECUTE. cannot dump.\n", meminfo.BaseAddress, meminfo.RegionSize);
			} else if (meminfo.Protect == PAGE_EXECUTE_READ ||
					meminfo.Protect == PAGE_EXECUTE_READWRITE ||
					meminfo.Protect == PAGE_EXECUTE_WRITECOPY) {
				int i;
				for (i = 0; i < module_count; i ++) {
					if (module_base[i] <= meminfo.BaseAddress &&
							(char *)module_base[i] + module_size[i] > meminfo.BaseAddress)
						break;
				}
				if (i == module_count) // not in known module list
					dump_to_file(process, meminfo.BaseAddress, meminfo.RegionSize);
			}
		}
		nextbase = (unsigned int)meminfo.BaseAddress + (unsigned int)meminfo.RegionSize;
		if (nextbase < (unsigned int)meminfo.BaseAddress) // overflow
			break;
	}
}

static void enum_modules (HANDLE process)
{
	HMODULE hMods[MAXMODULES];
	DWORD cbNeeded;
	int i;

	if (EnumProcessModules(process, hMods, sizeof(hMods), &cbNeeded) == 0) {
		printf("error: EnumProcessModules() failed\n");
		return;
	}

	for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
		char filename[1024];
		char basename[512];
		char *p;
		MODULEINFO moduleinfo;

		if (GetModuleFileNameEx(process, hMods[i], filename, sizeof(filename)) == 0) {
			printf("error: GetModuleFileNameEx() failed\n");
			continue;
		}
		for (p = filename; *p; p ++)
			if (*p >= 'A' && *p <= 'Z')
				*p += 'a' - 'A';
		if (GetModuleBaseName(process, hMods[i], basename, sizeof(basename)) == 0) {
			printf("error: GetModuleBaseName() failed\n");
			continue;
		}
		for (p = basename; *p; p ++)
			if (*p >= 'A' && *p <= 'Z')
				*p += 'a' - 'A';
		if (GetModuleInformation(process, hMods[i], &moduleinfo, sizeof(moduleinfo)) == 0) {
			printf("error: GetModuleInformation() failed\n");
			continue;
		}
		if (memcmp(filename, "c:\\windows\\system32\\", strlen("c:\\windows\\system32\\")) == 0 &&
				(unsigned int)moduleinfo.lpBaseOfDll >= 0x70000000u &&
				(unsigned int)moduleinfo.lpBaseOfDll <= 0x80000000u) {
			printf("unknown module %p %6x %s blacklisted\n",
					moduleinfo.lpBaseOfDll, moduleinfo.SizeOfImage, filename);
			module_base[module_count] = moduleinfo.lpBaseOfDll;
			module_size[module_count] = moduleinfo.SizeOfImage;
			module_count ++;
		} else {
			printf("  known module %p %6x %s not blacklisted\n",
					moduleinfo.lpBaseOfDll, moduleinfo.SizeOfImage, filename);
		}
		/*printf("%p %p %p %6x %s %s\n",
				hMods[i],
				moduleinfo.lpBaseOfDll, moduleinfo.EntryPoint, moduleinfo.SizeOfImage,
				basename, filename);*/
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

	enum_modules(process);
	enum_maps(process);

	CloseHandle(process);

	return 0;
}
