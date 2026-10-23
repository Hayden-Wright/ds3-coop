// DS3 Co-op: диагностический слой поверх Seamless Co-op.
//
// Задача этого файла — не менять игру, а ЧИТАТЬ её состояние и писать лог.
//
// Что умеет версия 2:
//   1. Проверяет версию игры (timestamp + размер образа).
//   2. Находит ЖИВЫЕ объекты игры в памяти по их таблице виртуальных функций
//      (vtable). Адреса vtable вычислены заранее по RTTI из самого exe игры,
//      см. local/analysis/vftables.json. Никаких жёстких абсолютных адресов:
//      всё считается от базы загруженного модуля.
//   3. Раз в несколько секунд повторяет поиск и пишет, что изменилось —
//      так видно, когда игра создаёт объекты (вход в игру, меню, костёр).
//   4. Для найденного MenuMan выводит первые поля объекта: это подсказка,
//      какие смещения читать дальше.
//
// Ничего не патчим, байты игры не трогаем. Только чтение и запись лога.
//
// Вся работа идёт в отдельном потоке, не в DllMain: в DllMain Windows держит
// блокировку загрузчика, и тяжёлый код в ней вешает старт игры.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kDs3ImageSize = 0x56f4000u;
// Ровно 8 hex-цифр: 0x639c4ddu было на одну цифру меньше и ломало проверку.
constexpr unsigned long kDs3Timestamp = 0x639c4dddu;

// RTTI-имя класса менеджера меню в игре.
constexpr char kMenuClassName[] = ".?AVMenuMan@NS_SPRJ@@";

// Таблица классов: имя и RVA их vtable в образе игры.
// Как получено: по RTTI-строке находим TypeDescriptor, затем
// CompleteObjectLocator, затем указатель на locator в vtable[-1].
// Проверено скриптом на файле игры; результат — local/analysis/vftables.json.
struct ClassInfo {
    const char* name;
    std::uint32_t vftable_rva;
};

constexpr ClassInfo kClasses[] = {
    {"MenuMan", 0x28180b0},
    {"FrpgMenuSys", 0x2816848},
    {"InGameMenuStep", 0x285e5c8},
    {"CsPlayerMenuCtrl", 0x29133b8},
    {"FrpgMenuDlgShopExtList", 0x2812448},
    {"FrpgMenuDlgWarp", 0x281d4b8},
    {"MenuData", 0x281b658},
    {"PlayerIns", 0x2857158},
    {"ChrIns", 0x284f478},
    {"GameMan", 0x27d89c8},
};

constexpr std::size_t kMaxHitsPerClass = 32;
constexpr int kScans = 6;         // сколько раз повторить поиск
constexpr DWORD kScanIntervalMs = 5000;

FILE* g_log = nullptr;

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

// Можно ли читать этот регион. Вызывается один раз на регион памяти,
// а не на каждый байт — иначе на 87 МБ образа уходят миллионы вызовов.
bool RegionReadable(const MEMORY_BASIC_INFORMATION& mbi) {
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & PAGE_GUARD) return false;
    if (mbi.Protect == PAGE_NOACCESS) return false;
    constexpr DWORD kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & kReadable) != 0;
}

// Обходим память регионами: одно обращение к VirtualQuery на регион.
template <typename Fn>
void ForEachReadableRegion(std::uintptr_t begin, std::uintptr_t end, Fn&& fn) {
    std::uintptr_t p = begin;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<const void*>(p), &mbi, sizeof(mbi)))
            break;
        const auto region_begin =
            reinterpret_cast<std::uintptr_t>(mbi.BaseAddress);
        const auto region_end = region_begin + mbi.RegionSize;
        if (region_end <= p) break;  // защита от зацикливания

        if (RegionReadable(mbi)) {
            const auto scan_begin = p;
            const auto scan_end = region_end < end ? region_end : end;
            if (scan_end > scan_begin) {
                fn(reinterpret_cast<const char*>(scan_begin),
                   static_cast<std::size_t>(scan_end - scan_begin));
            }
        }
        p = region_end;
    }
}

// Поиск подстроки в образе игры. Возвращает адрес первого вхождения или 0.
std::uintptr_t FindBytes(std::uintptr_t begin, std::uintptr_t end,
                         const char* needle, std::size_t len) {
    std::uintptr_t found = 0;
    ForEachReadableRegion(begin, end,
                          [&](const char* base, std::size_t size) -> bool {
                              if (size < len) return false;
                              const char* cur = base;
                              const char* last = base + size - len;
                              while (cur <= last) {
                                  const auto* hit = static_cast<const char*>(
                                      std::memchr(cur, needle[0],
                                                  static_cast<std::size_t>(
                                                      last - cur) + 1));
                                  if (!hit) break;
                                  if (std::memcmp(hit, needle, len) == 0) {
                                      found = reinterpret_cast<std::uintptr_t>(hit);
                                      return true;
                                  }
                                  cur = hit + 1;
                              }
                              return false;
                          });
    return found;
}

// Поиск 4-байтных RVA-ссылок: в MSVC структуры RTTI ссылаются друг на друга
// через RVA, а не через указатели.
std::size_t CountRvaRefs(std::uintptr_t begin, std::uintptr_t end,
                         std::uint32_t rva, std::uintptr_t* first_ref) {
    std::size_t hits = 0;
    if (first_ref) *first_ref = 0;
    ForEachReadableRegion(begin, end,
                          [&](const char* base, std::size_t size) {
                              const std::size_t count = size / sizeof(std::uint32_t);
                              const auto* words =
                                  reinterpret_cast<const std::uint32_t*>(base);
                              for (std::size_t i = 0; i < count; ++i) {
                                  if (words[i] == rva) {
                                      if (hits == 0 && first_ref)
                                          *first_ref = reinterpret_cast<std::uintptr_t>(
                                              &words[i]);
                                      ++hits;
                                  }
                              }
                          });
    return hits;
}

// Живые объекты класса: адреса, где первое поле (указатель на vtable)
// равно ожидаемому. Объекты игры выделены в куче, поэтому ищем по всей
// доступной памяти процесса.
std::vector<std::uintptr_t> FindInstances(std::uintptr_t vftable_abs,
                                          std::size_t max_hits) {
    std::vector<std::uintptr_t> hits;
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const auto begin =
        reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto end =
        reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

    ForEachReadableRegion(begin, end,
                          [&](const char* base, std::size_t size) -> bool {
                              const std::size_t count =
                                  size / sizeof(std::uintptr_t);
                              const auto* words =
                                  reinterpret_cast<const std::uintptr_t*>(base);
                              for (std::size_t i = 0; i < count; ++i) {
                                  if (words[i] == vftable_abs) {
                                      hits.push_back(reinterpret_cast<std::uintptr_t>(
                                          &words[i]));
                                      if (hits.size() >= max_hits) return true;
                                  }
                              }
                              return false;
                          });
    return hits;
}

// Печатает первые поля объекта — подсказка, какие смещения читать дальше.
void DumpObject(const char* label, std::uintptr_t obj) {
    constexpr int kWords = 8;
    std::uintptr_t words[kWords]{};
    std::memcpy(words, reinterpret_cast<const void*>(obj), sizeof(words));

    char line[512]{};
    std::size_t used = 0;
    for (int i = 0; i < kWords; ++i) {
        // snprintf возвращает СКОЛЬКО ХОТЕЛ записать, а не сколько записал.
        // Если места не осталось, дальше писать нельзя: size_t ушёл бы
        // в минус и snprintf писал бы за границу буфера.
        if (used >= sizeof(line) - 1) break;
        const int n = std::snprintf(line + used, sizeof(line) - used,
                                    " [%02x]=%llx", i * 8,
                                    static_cast<unsigned long long>(words[i]));
        if (n <= 0) break;
        const std::size_t written = static_cast<std::size_t>(n);
        used += written < sizeof(line) - used ? written : sizeof(line) - used - 1;
    }
    Log("  %s @ 0x%llx:%s", label, static_cast<unsigned long long>(obj), line);
}

// Вся работа. Запускается в отдельном потоке, не в DllMain.
DWORD WINAPI Worker(LPVOID) {
    const ULONGLONG started = GetTickCount64();

    HMODULE game = nullptr;
    for (int attempt = 0; attempt < 300 && !game; ++attempt) {
        game = GetModuleHandleA("DarkSoulsIII.exe");
        if (!game) Sleep(100);
    }
    if (!game) {
        Log("ОШИБКА: DarkSoulsIII.exe не найден в процессе");
        Log("ИТОГ: FAIL (игра не загрузилась)");
        return 0;
    }

    const ModuleInfo info = ReadModule(game);
    if (!info.ok) {
        Log("ОШИБКА: не удалось прочитать PE-заголовок игры");
        Log("ИТОГ: FAIL (заголовок)");
        return 0;
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

    // Строка класса: подтверждает, что образ тот самый и RTTI на месте.
    const ULONGLONG scan_started = GetTickCount64();
    const std::uintptr_t name_addr =
        FindBytes(info.base, info.base + info.size, kMenuClassName,
                  std::strlen(kMenuClassName));
    Log("поиск строки   : %llu мс",
        static_cast<unsigned long long>(GetTickCount64() - scan_started));
    if (name_addr) {
        const std::uintptr_t name_rva = name_addr - info.base;
        Log("строка %s найдена, RVA 0x%llx", kMenuClassName,
            static_cast<unsigned long long>(name_rva));
        const std::uintptr_t td_rva = name_rva - 0x10;
        std::uintptr_t first_ref = 0;
        const std::size_t refs =
            CountRvaRefs(info.base, info.base + info.size,
                         static_cast<std::uint32_t>(td_rva), &first_ref);
        Log("RVA TypeDescrip: 0x%llx, RVA-ссылок: %zu",
            static_cast<unsigned long long>(td_rva), refs);
    } else {
        Log("строка %s НЕ найдена", kMenuClassName);
    }

    if (!size_ok) Log("причина        : размер образа не совпал");
    if (!ts_ok) Log("причина        : timestamp не совпал");
    Log("ИТОГ: %s", (size_ok && ts_ok) ? "PASS" : "FAIL (версия игры)");

    // Поиск живых объектов. Игра к моменту инъекции ещё грузится, поэтому
    // повторяем несколько раз: объекты появляются по мере загрузки мира.
    //
    // Смысл имеет только на той версии игры, для которой посчитаны vtable.
    // На другой версии эти адреса указывают в случайные места, и «найденные
    // объекты» — мусор. Поэтому при несовпадении версии поиск не делаем.
    Log("");
    if (!size_ok || !ts_ok) {
        Log("=== поиск объектов пропущен: версия игры не совпала ===");
        Log("Смысла нет: адреса vtable посчитаны для 1.15.2 (0x639c4ddd).");
        Log("ИТОГ ДИАГНОСТИКИ: FAIL (версия игры)");
        return 0;
    }

    Log("=== поиск объектов игры (каждые %lu мс, всего %d раз) ===",
        static_cast<unsigned long>(kScanIntervalMs), kScans);

    std::vector<std::vector<std::uintptr_t>> previous(std::size(kClasses));

    for (int pass = 0; pass < kScans; ++pass) {
        if (pass > 0) Sleep(kScanIntervalMs);
        Log("--- проход %d (t+%llu мс) ---", pass + 1,
            static_cast<unsigned long long>(GetTickCount64() - started));

        for (std::size_t c = 0; c < std::size(kClasses); ++c) {
            const std::uintptr_t vt = info.base + kClasses[c].vftable_rva;
            const auto hits = FindInstances(vt, kMaxHitsPerClass);
            const bool changed = hits != previous[c];
            if (changed) {
                Log("%-22s : найдено %zu", kClasses[c].name, hits.size());
                for (const auto addr : hits) {
                    // Адрес внутри образа игры — это статическая ссылка
                    // (например, сама таблица RTTI), а не живой объект.
                    // Живые объекты лежат в куче, за пределами образа.
                    const bool inside_image =
                        addr >= info.base && addr < info.base + info.size;
                    if (inside_image) continue;
                    DumpObject(kClasses[c].name, addr);
                }
                previous[c] = hits;
            } else if (pass == 0) {
                Log("%-22s : найдено %zu (без изменений)", kClasses[c].name,
                    hits.size());
            }
        }
    }

    Log("");
    Log("всего          : %llu мс",
        static_cast<unsigned long long>(GetTickCount64() - started));
    Log("ИТОГ ДИАГНОСТИКИ: PASS");
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

    // В DllMain только самое необходимое: открыть лог и уйти.
    // Вся диагностика — в отдельном потоке, иначе блокировка загрузчика
    // держится всё время скана и игра может не стартовать.
    HANDLE thread = CreateThread(nullptr, 0, Worker, nullptr, 0, nullptr);
    if (thread) {
        CloseHandle(thread);
    } else {
        Log("ОШИБКА: не удалось создать рабочий поток");
        Log("ИТОГ: FAIL (поток)");
    }
    return TRUE;
}
