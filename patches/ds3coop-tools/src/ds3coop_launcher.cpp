// DS3 Co-op: свой лаунчер.
//
// Делает то же, что ds3sc_launcher.exe от автора мода: запускает
// DarkSoulsIII.exe и внедряет в него DLL. Отличие — можно указать несколько
// DLL сразу, поэтому рядом с модом грузится наш диагностический слой.
//
// Файлы автора не изменяются: мы просто запускаем игру иначе.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdio>
#include <string>
#include <vector>

namespace {

std::wstring ExeDir() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring s(path);
    const auto slash = s.find_last_of(L"\\/");
    if (slash != std::wstring::npos) s.resize(slash + 1);
    return s;
}

bool FileExists(const std::wstring& path) {
    const DWORD attr = GetFileAttributesW(path.c_str());
    return attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

// Классический способ внедрения: выделяем память в чужом процессе,
// кладём туда путь к DLL, запускаем LoadLibrary в удалённом потоке.
bool InjectDll(HANDLE process, const std::wstring& dll_path) {
    const std::size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    void* remote = VirtualAllocEx(process, nullptr, bytes,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return false;

    if (!WriteProcessMemory(process, remote, dll_path.c_str(), bytes, nullptr)) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    const auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
    if (!load_library) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote,
                                       0, nullptr);
    if (!thread) {
        VirtualFreeEx(process, remote, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(thread, 30000);
    DWORD exit_code = 0;
    GetExitCodeThread(thread, &exit_code);
    CloseHandle(thread);
    VirtualFreeEx(process, remote, 0, MEM_RELEASE);
    // Ненулевой код возврата = адрес загруженной DLL, то есть успех.
    return exit_code != 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    const std::wstring dir = ExeDir();
    const std::wstring game = dir + L"DarkSoulsIII.exe";
    const std::wstring mod_dll = dir + L"SeamlessCoop\\ds3sc.dll";
    const std::wstring tools_dll = dir + L"SeamlessCoop\\ds3coop_tools.dll";

    if (!FileExists(game)) {
        std::fwprintf(stderr, L"Не найден DarkSoulsIII.exe рядом с лаунчером\n");
        return 1;
    }
    if (!FileExists(mod_dll)) {
        std::fwprintf(stderr, L"Не найден SeamlessCoop\\ds3sc.dll\n");
        return 1;
    }
    const bool with_tools = FileExists(tools_dll);

    // Steam должен видеть игру как DS3, иначе мод не поднимется.
    SetEnvironmentVariableW(L"SteamAppId", L"374320");
    SetEnvironmentVariableW(L"SteamGameId", L"374320");

    std::wstring command = L"\"" + game + L"\"";
    for (int i = 1; i < argc; ++i) {
        command += L" ";
        command += argv[i];
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> mutable_command(command.begin(), command.end());
    mutable_command.push_back(L'\0');

    if (!CreateProcessW(game.c_str(), mutable_command.data(), nullptr, nullptr,
                        FALSE, 0, nullptr, dir.c_str(), &si, &pi)) {
        std::fwprintf(stderr, L"Не удалось запустить игру (код %lu)\n",
                      GetLastError());
        return 1;
    }

    std::fwprintf(stdout, L"Игра запущена, PID %lu\n", pi.dwProcessId);

    // Мод грузим первым: он должен успеть поставить свои перехваты.
    const bool mod_ok = InjectDll(pi.hProcess, mod_dll);
    std::fwprintf(stdout, L"  мод       : %s\n", mod_ok ? L"загружен" : L"ОШИБКА");

    bool tools_ok = false;
    if (with_tools) {
        tools_ok = InjectDll(pi.hProcess, tools_dll);
        std::fwprintf(stdout, L"  диагностика: %s\n",
                      tools_ok ? L"загружена" : L"ОШИБКА");
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!mod_ok) {
        std::fwprintf(stderr, L"Мод не загрузился — играть бессмысленно\n");
        return 1;
    }
    return 0;
}
