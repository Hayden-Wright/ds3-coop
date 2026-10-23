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

// Лог лаунчера. Нужен, чтобы отличить наш запуск от запуска родным
// ds3sc_launcher.exe: если этого файла нет, значит игру запускали не мы.
FILE* g_log = nullptr;

void Log(const wchar_t* fmt, ...) {
    if (!g_log) return;
    va_list args;
    va_start(args, fmt);
    std::vfwprintf(g_log, fmt, args);
    va_end(args);
    std::fputwc(L'\n', g_log);
    std::fflush(g_log);
}

// Вывод в консоль. Через fwprintf кириллица ломается: mingw конвертирует
// широкие строки через C-locale, а не через кодовую страницу консоли.
// WriteConsoleW пишет UTF-16 напрямую, поэтому текст всегда читаемый.
// Если stdout перенаправлен (не консоль), WriteConsoleW не работает —
// тогда пишем UTF-8 байтами, чтобы вывод не пропадал совсем.
void Say(const wchar_t* text) {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!out || out == INVALID_HANDLE_VALUE) return;

    DWORD mode = 0;
    if (GetConsoleMode(out, &mode)) {
        DWORD written = 0;
        const std::size_t len = std::wcslen(text);
        WriteConsoleW(out, text, static_cast<DWORD>(len), &written, nullptr);
        WriteConsoleW(out, L"\n", 1, &written, nullptr);
        return;
    }

    const int need = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0,
                                         nullptr, nullptr);
    if (need > 1) {
        std::string utf8(static_cast<std::size_t>(need), '\0');
        WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8.data(), need, nullptr,
                            nullptr);
        std::fwrite(utf8.c_str(), 1, utf8.size() - 1, stdout);
        std::fputc('\n', stdout);
        std::fflush(stdout);
    }
}

void SayFmt(const wchar_t* fmt, ...) {
    wchar_t buffer[1024]{};
    va_list args;
    va_start(args, fmt);
    _vsnwprintf(buffer, 1023, fmt, args);
    va_end(args);
    Say(buffer);
}

void Stamp() {
    SYSTEMTIME st{};
    GetLocalTime(&st);
    Log(L"время          : %04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth,
        st.wDay, st.wHour, st.wMinute, st.wSecond);
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

    // Приведение через void* — стандартный приём для такого внедрения:
    // WinAPI отдаёт FARPROC, а потоку нужен LPTHREAD_START_ROUTINE. Сигнатура
    // LoadLibraryW совместима с ожидаемой (один указатель), поэтому это безопасно.
    const auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        reinterpret_cast<void*>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW")));
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
    // Без этого mingw конвертирует широкие строки в консоль через C-locale
    // и русский текст превращается в мусор. Лог пишется в UTF-8 напрямую,
    // поэтому его это не касается.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    const std::wstring dir = ExeDir();
    const std::wstring game = dir + L"DarkSoulsIII.exe";
    const std::wstring mod_dll = dir + L"SeamlessCoop\\ds3sc.dll";
    const std::wstring tools_dll = dir + L"SeamlessCoop\\ds3coop_tools.dll";

    // Лог кладём рядом с DLL диагностики, в один каталог с ней.
    const std::wstring log_path = dir + L"SeamlessCoop\\ds3coop-launcher.log";
    g_log = _wfopen(log_path.c_str(), L"a, ccs=UTF-8");
    Log(L"=== ds3coop_launcher запущен ===");
    Stamp();
    Log(L"каталог        : %ls", dir.c_str());
    if (!g_log) {
        Say(L"Не удалось открыть лог для записи");
    }

    if (!FileExists(game)) {
        Say(L"Не найден DarkSoulsIII.exe рядом с лаунчером");
        Log(L"ОШИБКА: не найден DarkSoulsIII.exe");
        Log(L"ИТОГ: FAIL (нет игры)");
        return 1;
    }
    if (!FileExists(mod_dll)) {
        Say(L"Не найден SeamlessCoop\\ds3sc.dll");
        Log(L"ОШИБКА: не найден SeamlessCoop\\ds3sc.dll");
        Log(L"ИТОГ: FAIL (нет мода)");
        return 1;
    }
    const bool with_tools = FileExists(tools_dll);
    Log(L"мод найден     : да");
    Log(L"диагностика    : %ls", with_tools ? L"найдена" : L"НЕ НАЙДЕНА");

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
        SayFmt(L"Не удалось запустить игру (код %lu)", GetLastError());
        Log(L"ОШИБКА: CreateProcess не удался, код %lu", GetLastError());
        Log(L"ИТОГ: FAIL (не удалось запустить игру)");
        return 1;
    }

    SayFmt(L"Игра запущена, PID %lu", pi.dwProcessId);
    Log(L"игра запущена  : PID %lu", pi.dwProcessId);

    // Мод грузим первым: он должен успеть поставить свои перехваты.
    const bool mod_ok = InjectDll(pi.hProcess, mod_dll);
    SayFmt(L"  мод        : %s", mod_ok ? L"загружен" : L"ОШИБКА");
    Log(L"мод внедрён    : %ls", mod_ok ? L"да" : L"НЕТ");

    bool tools_ok = false;
    if (with_tools) {
        tools_ok = InjectDll(pi.hProcess, tools_dll);
        SayFmt(L"  диагностика: %s", tools_ok ? L"загружена" : L"ОШИБКА");
        Log(L"диагностика    : %ls", tools_ok ? L"внедрена" : L"НЕ ВНЕДРЕНА");
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (!mod_ok) {
        Say(L"Мод не загрузился — играть бессмысленно");
        Log(L"ИТОГ: FAIL (мод не внедрён)");
        return 1;
    }
    Log(L"ИТОГ: лаунчер отработал, можно играть");
    return 0;
}
