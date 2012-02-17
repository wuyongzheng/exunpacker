#include <windows.h>
#include <psapi.h>
#include <stdio.h>

#define MAXMODULES 500
void *module_base[MAXMODULES];
char *module_name[MAXMODULES];
char *module_path[MAXMODULES];
int module_size[MAXMODULES];
int module_count = 0;

char *outprefix = "unpacker";

static const char *protect_to_name (int protect)
{
	switch (protect & 0xff) {
		case 0x01: return "na";
		case 0x02: return "ro";
		case 0x10: return "ex";
		case 0x20: return "xr";
		case 0x40: return "xw";
		case 0x80: return "xc";
		default: return "nk";
	}
}

static void dump_to_file (HANDLE process, int protect, void *base, int size)
{
	char outfile[64];
	char buffer[64 * 1024];
	char *modname;
	int i;
	FILE *outfp;

	if (protect == PAGE_EXECUTE) {
		printf("%p %x is PAGE_EXECUTE. cannot dump.\n", base, size);
		return;
	}

	if (protect == PAGE_READONLY) // comment if want RO data.
		return;

	if (protect != PAGE_EXECUTE_READ &&
			protect != PAGE_EXECUTE_READWRITE &&
			protect != PAGE_EXECUTE_WRITECOPY)
		return;

	if ((unsigned int)base % 1024 != 0)
		printf("warning: base address %p not 4k alligned\n", base);

	for (i = 0, modname = "nomodule"; i < module_count; i ++) {
		if (module_base[i] <= base &&
				(char *)module_base[i] + module_size[i] > base) {
			modname = module_name[i];
			break;
		}
	}

	_snprintf(outfile, sizeof(outfile), "%s-%05x-%s-%s.bin",
			outprefix, (unsigned int)base >> 12, protect_to_name(protect), modname);
	printf("unpacking %d bytes to %s.\n", size, outfile);
	outfile[sizeof(outfile)-1] = '\0';
	outfp = fopen(outfile, "wb");

	for (i = 0; i < size; i += sizeof(buffer)) {
		SIZE_T sizetoread = sizeof(buffer) < size - i ? sizeof(buffer) : size - i;
		SIZE_T sizeread;
		if (ReadProcessMemory(process, (char *)base + i, buffer, sizetoread, &sizeread) == 0) {
			printf("failed to read.\n");
			break;
		}
		if (sizetoread != sizeread) {
			printf("failed to read..\n");
			break;
		}
		fwrite(buffer, sizetoread, 1, outfp);
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

		if (meminfo.State == MEM_COMMIT && meminfo.RegionSize > 0)
			dump_to_file(process, meminfo.Protect, meminfo.BaseAddress, meminfo.RegionSize);

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
		if (strchr(basename, '.') != NULL)
			strchr(basename, '.')[0] = '\0';
		for (p = basename; *p; p ++) {
			if (*p >= 'A' && *p <= 'Z')
				*p += 'a' - 'A';
			else if (*p >= 'a' && *p <= 'z')
				;
			else if (*p >= '0' && *p <= '9')
				;
			else
				*p = '_';
		}
		if (strlen(basename) > 8)
			basename[8] = '\0';
		if (strlen(basename) < 8)
			strcat(basename, "________" + strlen(basename));

		if (GetModuleInformation(process, hMods[i], &moduleinfo, sizeof(moduleinfo)) == 0) {
			printf("error: GetModuleInformation() failed\n");
			continue;
		}

		module_base[module_count] = moduleinfo.lpBaseOfDll;
		module_size[module_count] = moduleinfo.SizeOfImage;
		module_name[module_count] = strdup(basename);
		module_path[module_count] = strdup(filename);
		module_count ++;

		/*printf("%p %p %p %6x %s %s\n",
				hMods[i],
				moduleinfo.lpBaseOfDll, moduleinfo.EntryPoint, moduleinfo.SizeOfImage,
				basename, filename);*/
	}
}

int main (int argc, char *argv[])
{
	HANDLE process;
	DWORD pid;

	if (argc < 2) {
		printf("Usage: %s pid\n", argv[0]);
		return 1;
	}
	if (argc >= 3)
		outprefix = argv[2];

	pid = atoi(argv[1]);
	if (pid <= 0) {
		STARTUPINFO sinfo;
		PROCESS_INFORMATION pinfo;
		memset(&pinfo, 0, sizeof(pinfo));
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.cb = sizeof(sinfo);
		if (!CreateProcess(NULL, argv[1], NULL, NULL, FALSE, 0, NULL, NULL, &sinfo, &pinfo)) {
			printf("error: CreateProcess(%s) failed.\n", argv[1]);
			return 1;
		}
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
		pid = pinfo.dwProcessId;
		printf("Process %d created. sleep for 2 sec.\n", pid);
		Sleep(2000);
	}

	process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pid);
	if (process == NULL) {
		printf("error: OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, %d) failed. GetLastError()=0x%x\n", pid, GetLastError());
		return 1;
	}

	enum_modules(process);
	enum_maps(process);

	TerminateProcess(process, 0);
	CloseHandle(process);

	return 0;
}
