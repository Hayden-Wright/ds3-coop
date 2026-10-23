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

// Потолок на класс. Было 32, и FrpgMenuSys давал ровно 32 в обоих запусках —
// то есть поиск упирался в потолок, и настоящее число было неизвестно.
// 256 заведомо выше любого ожидаемого количества: если и это упрётся,
// в логе появится предупреждение.
constexpr std::size_t kMaxHitsPerClass = 256;
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

// Чтение памяти через ReadProcessMemory.
//
// Почему не обычная загрузка по указателю: между проверкой VirtualQuery и
// чтением игра может освободить или защитить страницу — тогда обычное чтение
// роняет ВЕСЬ процесс (так и случилось 02:22, код 0xc0000005 по смещению
// 0x19fd). ReadProcessMemory в этом случае просто возвращает FALSE.
bool SafeRead(std::uintptr_t addr, void* out, std::size_t size) {
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(),
                           reinterpret_cast<const void*>(addr), out, size,
                           &got)) {
        return false;
    }
    return got == size;
}

// Поиск подстроки в образе игры. Возвращает адрес первого вхождения или 0.
// Образ игры замаплен на всё время жизни процесса и не освобождается,
// поэтому здесь прямое чтение безопасно — в отличие от поиска по всей памяти.
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

// Диапазон адресов, который поиск должен игнорировать.
struct Range {
    std::uintptr_t begin;
    std::uintptr_t end;
};

bool InAnyRange(std::uintptr_t addr, const std::vector<Range>& ranges) {
    for (const auto& r : ranges) {
        if (addr >= r.begin && addr < r.end) return true;
    }
    return false;
}

// Ищем сразу все классы за один проход по памяти. Раньше на каждый класс
// приходился отдельный проход по всей памяти — 10 проходов вместо одного,
// то есть в 10 раз больше чтения при том же результате.
//
// Читаем кусками через ReadProcessMemory, а не напрямую по указателю:
// игра в это время выделяет и освобождает память, и прямое чтение может
// попасть на только что освобождённую страницу. ReadProcessMemory в таком
// случае вернёт FALSE, а не уронит процесс.
//
// excluded — наша собственная память. Без этого поиск находит САМ СЕБЯ:
// массив адресов vtable лежит в куче и состоит ровно из тех значений,
// которые мы ищем. В логе 02:31 это дало ложные «объекты», идущие подряд
// через 8 байт (0x...430, 0x...438, 0x...440 ...) — это был наш массив.
std::vector<std::vector<std::uintptr_t>> FindAllInstances(
    const std::vector<std::uintptr_t>& vftables, std::size_t max_hits,
    const std::vector<Range>& excluded) {
    constexpr std::size_t kChunk = 0x10000;  // 64 КБ — один вызов на кусок
    std::vector<std::vector<std::uintptr_t>> all(vftables.size());
    // Резервируем заранее: иначе push_back перевыделяет память, старые
    // блоки освобождаются, и следующий проход может прочитать в них
    // остатки прежних значений — снова ложные срабатывания.
    for (auto& v : all) v.reserve(max_hits);

    std::vector<std::uintptr_t> buffer(kChunk / sizeof(std::uintptr_t));
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    const auto begin =
        reinterpret_cast<std::uintptr_t>(si.lpMinimumApplicationAddress);
    const auto end =
        reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

    ForEachReadableRegion(
        begin, end, [&](const char* base, std::size_t size) -> bool {
            const auto region_begin = reinterpret_cast<std::uintptr_t>(base);
            for (std::size_t off = 0; off < size; off += kChunk) {
                const std::size_t want =
                    size - off < kChunk ? size - off : kChunk;
                const std::size_t words_want = want / sizeof(std::uintptr_t);
                if (words_want == 0) break;
                const auto addr = region_begin + off;
                if (!SafeRead(addr, buffer.data(),
                              words_want * sizeof(std::uintptr_t))) {
                    continue;  // страницу уже отдали — пропускаем
                }
                for (std::size_t i = 0; i < words_want; ++i) {
                    const std::uintptr_t word = buffer[i];
                    if (!word) continue;
                    const auto hit = addr + i * sizeof(std::uintptr_t);
                    if (InAnyRange(hit, excluded)) continue;
                    for (std::size_t c = 0; c < vftables.size(); ++c) {
                        if (word != vftables[c]) continue;
                        if (all[c].size() >= max_hits) break;
                        all[c].push_back(hit);
                    }
                }
            }
            return false;
        });
    return all;
}

// Печатает первые поля объекта — подсказка, какие смещения читать дальше.
//
// expected_vt — адрес vtable, по которому объект был найден. Проверяем его
// ещё раз при чтении: между поиском и печатью объект могли освободить и
// переиспользовать под другие данные. В логе 02:31 так и вышло — «GameMan»
// напечатал первым словом 0x7ffeaa0172ef вместо адреса своей vtable.
//
// Печатаем ОБА представления: 8-байтные слова (как раньше, удобно для
// указателей) и 4-байтные (для чисел). Это не избыточность, а исправление
// конкретной ошибки чтения: в логе 02:57 поле [08] показало 7ff410004000,
// потому что 4-байтное число 0x10004000 слиплось с соседним полем.
// Младшие 32 бита того значения — ровно 0x10004000, то есть настоящий номер
// слота. Читая только 8-байтные слова, легко принять соседнее поле за часть
// числа и сделать неверный вывод.
void DumpObject(const char* label, std::uintptr_t obj,
                std::uintptr_t expected_vt) {
    constexpr int kWords = 8;
    std::uintptr_t words[kWords]{};
    if (!SafeRead(obj, words, sizeof(words))) {
        Log("  %s @ 0x%llx: [объект уже освобождён, чтение отменено]", label,
            static_cast<unsigned long long>(obj));
        return;
    }
    if (words[0] != expected_vt) {
        Log("  %s @ 0x%llx: [объект изменился, уже не %s — пропуск]", label,
            static_cast<unsigned long long>(obj), label);
        return;
    }

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

    // Те же байты, но по 4 байта. Показывают, где на самом деле кончается
    // каждое поле, если оно 4-байтное.
    char line32[512]{};
    used = 0;
    const auto* words32 = reinterpret_cast<const std::uint32_t*>(words);
    for (int i = 0; i < kWords * 2; ++i) {
        if (used >= sizeof(line32) - 1) break;
        const int n = std::snprintf(line32 + used, sizeof(line32) - used,
                                    " [%02x]=%x", i * 4, words32[i]);
        if (n <= 0) break;
        const std::size_t written = static_cast<std::size_t>(n);
        used += written < sizeof(line32) - used ? written
                                                : sizeof(line32) - used - 1;
    }
    Log("  %*s 32-бит:%s", static_cast<int>(std::strlen(label)), "", line32);
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

    // Абсолютные адреса vtable считаем один раз: база модуля не меняется.
    std::vector<std::uintptr_t> vftables;
    vftables.reserve(std::size(kClasses));
    for (const auto& cls : kClasses) {
        vftables.push_back(info.base + cls.vftable_rva);
    }

    // Наша собственная память, которую поиск обязан обходить стороной.
    // Иначе он находит массив vftables, который мы же и держим в куче.
    std::vector<Range> excluded;
    const auto exclude_own = [&excluded](const void* p, std::size_t bytes) {
        const auto a = reinterpret_cast<std::uintptr_t>(p);
        if (a && bytes) excluded.push_back({a, a + bytes});
    };
    exclude_own(vftables.data(), vftables.capacity() * sizeof(std::uintptr_t));
    exclude_own(kClasses, sizeof(kClasses));

    std::vector<std::vector<std::uintptr_t>> previous(std::size(kClasses));

    for (int pass = 0; pass < kScans; ++pass) {
        if (pass > 0) Sleep(kScanIntervalMs);
        Log("--- проход %d (t+%llu мс) ---", pass + 1,
            static_cast<unsigned long long>(GetTickCount64() - started));

        const auto all = FindAllInstances(vftables, kMaxHitsPerClass, excluded);

        for (std::size_t c = 0; c < std::size(kClasses); ++c) {
            const auto& hits = all[c];
            const bool changed = hits != previous[c];
            if (changed) {
                Log("%-22s : найдено %zu", kClasses[c].name, hits.size());
                // Ровно потолок означает, что объектов может быть больше:
                // поиск останавливается на kMaxHitsPerClass. Без этого
                // предупреждения обрезанное число легко принять за точное.
                if (hits.size() >= kMaxHitsPerClass) {
                    Log("%-22s : ВНИМАНИЕ — упёрлось в потолок %zu, "
                        "настоящее число может быть больше",
                        kClasses[c].name, kMaxHitsPerClass);
                }
                for (const auto addr : hits) {
                    // Адрес внутри образа игры — это статическая ссылка
                    // (например, сама таблица RTTI), а не живой объект.
                    // Живые объекты лежат в куче, за пределами образа.
                    const bool inside_image =
                        addr >= info.base && addr < info.base + info.size;
                    if (inside_image) continue;
                    DumpObject(kClasses[c].name, addr, vftables[c]);
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
