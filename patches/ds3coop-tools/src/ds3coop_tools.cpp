// DS3 Co-op: диагностический слой поверх Seamless Co-op.
//
// Задача этого файла — не менять игру, а ЧИТАТЬ её состояние и писать лог.
// Он нужен, чтобы до прихода второго игрока понять, как игра хранит
// «кто я сейчас» (хост или гость) и какие меню доступны.
//
// Ничего не патчим, никаких байтов игры не трогаем. Только чтение памяти
// по адресам, которые находит сама игра, плюс запись текстового лога.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

constexpr std::size_t kDs3ImageSize = 0x56f4000u;
constexpr unsigned long kDs3Timestamp = 0x639c4ddu;

FILE* g_log = nullptr;
HMODULE g_game = nullptr;

void Log(const char* fmt, ...) {
    if (!g_log) return;
    va_list args;
    va_start(args, fmt);
    std::vfprintf(g_log, fmt, args);
    va_end(args);
    std::fputc('\n', g_log);
    std::fflush(g_log);
}

// Путь к логу кладём рядом с DLL, чтобы не писать в чужие каталоги.
std::string LogPath(HMODULE self) {
    char path[MAX_PATH]{};
    GetModuleFileNameA(self, path, MAX_PATH);
    std::string s(path);
    const auto slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s.resize(slash + 1);
    return s + "ds3coop-tools.log";
}

struct ModuleInfo {
    std::uintptr_t base = 0;
    std::size_t size = 0;
    unsigned long timestamp = 0;
    bool ok = false;
};

// Читаем PE-заголовок загруженного модуля: нужны база, размер образа
// и timestamp, чтобы убедиться, что перед нами та самая версия игры.
ModuleInfo ReadModule(HMODULE module) {
    ModuleInfo info{};
    if (!module) return info;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(module);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return info;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        reinterpret_cast<const std::uint8_t*>(module) + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return info;
    info.base = reinterpret_cast<std::uintptr_t>(module);
    info.size = nt->OptionalHeader.SizeOfImage;
    info.timestamp = nt->FileHeader.TimeDateStamp;
    info.ok = true;
    return info;
}

// Безопасное чтение: проверяем, что страница действительно доступна,
// иначе чтение по «мусорному» указателю уронит игру.
bool Readable(const void* address, std::size_t bytes) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(address, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    if (mbi.Protect == PAGE_NOACCESS) return false;
    const auto begin = reinterpret_cast<std::uintptr_t>(address);
    const auto end = begin + bytes;
    const auto region_end =
        reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return end >= begin && end <= region_end;
}

// Ищем в памяти игры ссылку на строку-имя класса. Так мы находим объект
// менеджера, не зная заранее его адреса. Ничего не пишем.
std::uintptr_t FindPointerTo(std::uintptr_t start, std::size_t span,
                             std::uintptr_t target) {
    for (std::uintptr_t p = start; p + sizeof(std::uintptr_t) <= start + span;
         p += alignof(std::uintptr_t)) {
        if (!Readable(reinterpret_cast<const void*>(p), sizeof(std::uintptr_t)))
            continue;
        std::uintptr_t value = 0;
        std::memcpy(&value, reinterpret_cast<const void*>(p), sizeof(value));
        if (value == target) return p;
    }
    return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE self, DWORD reason, LPVOID) {
    if (reason != DLL_PROCESS_ATTACH) return TRUE;
    DisableThreadLibraryCalls(self);

    const std::string log_path = LogPath(self);
    g_log = std::fopen(log_path.c_str(), "w");
    if (!g_log) return TRUE;

    Log("ds3coop-tools: загрузка");
    Log("версия сборки: %s %s", __DATE__, __TIME__);

    // Даём игре догрузить модули: лаунчер внедряет нас очень рано.
    for (int attempt = 0; attempt < 300 && !g_game; ++attempt) {
        g_game = GetModuleHandleA("DarkSoulsIII.exe");
        if (!g_game) Sleep(100);
    }
    if (!g_game) {
        Log("ОШИБКА: DarkSoulsIII.exe не найден в процессе");
        Log("ИТОГ: FAIL (игра не загрузилась)");
        return TRUE;
    }

    const ModuleInfo info = ReadModule(g_game);
    if (!info.ok) {
        Log("ОШИБКА: не удалось прочитать PE-заголовок игры");
        Log("ИТОГ: FAIL (заголовок)");
        return TRUE;
    }

    Log("база игры      : 0x%llx",
        static_cast<unsigned long long>(info.base));
    Log("размер образа  : 0x%zx (ожидался 0x%zx)", info.size,
        static_cast<std::size_t>(kDs3ImageSize));
    Log("timestamp      : 0x%08lx (ожидался 0x%08lx)", info.timestamp,
        kDs3Timestamp);

    const bool size_ok = info.size == kDs3ImageSize;
    const bool ts_ok = info.timestamp == kDs3Timestamp;
    Log("идентичность   : %s", (size_ok && ts_ok) ? "СОВПАЛА" : "НЕ СОВПАЛА");

    // Ищем строку-имя класса менеджера меню в образе игры, затем ссылку на неё.
    // Это доказывает, что мы умеем находить объекты игры, не зная адресов.
    std::uintptr_t name_addr = 0;
    const char* needle = "SprjMenuMan";
    for (std::size_t off = 0; off + 11 < info.size; ++off) {
        const auto* p = reinterpret_cast<const char*>(info.base + off);
        if (!Readable(p, 11)) {
            off += 0xFFF;
            continue;
        }
        if (std::memcmp(p, needle, 11) == 0) {
            name_addr = info.base + off;
            break;
        }
    }
    if (name_addr) {
        Log("строка SprjMenuMan найдена по адресу 0x%llx",
            static_cast<unsigned long long>(name_addr));
        const std::uintptr_t ref =
            FindPointerTo(info.base, info.size, name_addr);
        Log("ссылка на неё       : %s",
            ref ? "найдена" : "не найдена");
    } else {
        Log("строка SprjMenuMan не найдена");
    }

    // Итог печатаем одной строкой, чтобы проверку можно было делать скриптом.
    Log("ИТОГ: %s", (size_ok && ts_ok) ? "PASS" : "FAIL (версия игры)");
    return TRUE;
}
