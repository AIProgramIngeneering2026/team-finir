# Контракт Tool

В VulnScout два вида исполнителей, которых вызывает Dispatcher: **Parser** (разбор манифеста)
и **VulnSource** (поиск уязвимостей). Dispatcher знает только эти интерфейсы, конкретные реализации
подставляются при запуске. Новый формат манифеста или новый источник уязвимостей добавляется
новой реализацией без правки Dispatcher.

## Общие правила

- Первый параметр — `context.Context`. При отмене контекста или таймауте Tool прекращает работу
  и возвращает `ctx.Err()`.
- Tool не меняет состояние скана и не пишет в хранилище: он только возвращает результат или ошибку.
  Состояние меняет Dispatcher.
- Ошибки возвращаются как значения с кодом (см. ниже), Tool не вызывает `panic`.
- **Кто проверяет параметры.** Размер файла, наличие полей и поддерживаемый формат проверяет HTTP API
  до создания скана. Tool проверяет только содержимое, которое может понять лишь он сам:
  синтаксис манифеста, корректность ответа внешнего сервиса.

## Общие типы

```go
// Package — пакет с конкретной версией из манифеста.
type Package struct {
	Ecosystem string // "Go", "npm" — как в OSV.dev
	Name      string // "golang.org/x/net"
	Version   string // "0.6.0", без префикса "v"
}

// Unchecked — пакет, который не удалось проверить, и причина.
type Unchecked struct {
	Package Package
	Reason  string // "vuln_source_unavailable", "local_module"
}

// ToolError — ошибка Tool с машиночитаемым кодом.
type ToolError struct {
	Code    string // см. таблицы ошибок ниже
	Message string // для человека: "go.mod:7: unexpected token"
	Err     error  // исходная ошибка, доступна через errors.Unwrap
}
```

## Tool 1. Parser

```go
type Parser interface {
	// Name — имя для логов: "gomod", "npm".
	Name() string
	// CanParse — подходит ли парсер для файла с таким именем. Используется Registry.
	CanParse(filename string) bool
	// Parse читает манифест и возвращает пакеты для проверки
	// и пакеты, которые проверить нельзя.
	Parse(ctx context.Context, r io.Reader) ([]Package, []Unchecked, error)
}
```

| | |
|---|---|
| **Получает** | содержимое манифеста (`io.Reader`) уже после проверки размера и имени файла |
| **Возвращает** | список пакетов с точными версиями; список пакетов, которые проверить нельзя, с причиной |
| **Отказывает** | `manifest_parse_error` — синтаксическая ошибка, в сообщении номер строки; `context.Canceled` / `DeadlineExceeded` |
| **Что делает Dispatcher при ошибке** | `manifest_parse_error` → скан в `failed` с этой ошибкой, OSV.dev не вызывается |

### Реализация 1: `GoModParser` — `go.mod`

- `CanParse`: имя файла `go.mod`.
- Разбирает `require` через `golang.org/x/mod/modfile`, учитывает `replace`: проверяется итоговая версия.
- Псевдоверсии (`v0.0.0-20230213185550-547e7edf3673`) передаёт как есть, без префикса `v`.
- `replace` на локальный путь (`=> ../lib`) → пакет в `Unchecked` с причиной `local_module`.
- Экосистема — `Go`.

### Реализация 2: `NpmLockParser` — `package-lock.json`

- `CanParse`: имя файла `package-lock.json`.
- Читает раздел `packages` (lockfileVersion 2 и 3). Ключ `""` — сам проект, пропускается.
- Имя пакета — часть ключа после последнего `node_modules/`, включая scope: `@babel/core`.
  Один пакет в разных версиях проверяется каждой версией.
- Записи с `"link": true` → `Unchecked` с причиной `local_module`.
- Экосистема — `npm`.

## Tool 2. VulnSource

```go
type Match struct {
	Package Package
	VulnIDs []string // "GO-2023-1571", "GHSA-35jh-r3h4-6jhm"
}

type Vuln struct {
	ID           string
	CVE          string   // из aliases; пусто, если CVE нет
	Summary      string
	Severity     string   // CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
	CVSSScore    float64  // 0, если вектора нет
	CVSSVector   string
	FixedVersion string   // пусто, если исправления нет
}

type VulnSource interface {
	// QueryBatch находит ID уязвимостей для пакетов.
	// Пакеты, по которым ответа нет после всех повторов, возвращаются в unchecked.
	QueryBatch(ctx context.Context, pkgs []Package) (matches []Match, unchecked []Unchecked, err error)
	// GetVuln возвращает детали уязвимости для конкретного пакета:
	// версия с исправлением зависит от пакета и его версии.
	GetVuln(ctx context.Context, id string, pkg Package) (Vuln, error)
}
```

| | |
|---|---|
| **Получает** | список пакетов (`QueryBatch`); ID уязвимости и пакет (`GetVuln`) |
| **Возвращает** | найденные уязвимости по пакетам и непроверенные пакеты; детали уязвимости |
| **Отказывает** | `vuln_source_unavailable` — источник не ответил ни по одному пакету после всех повторов; `vuln_not_found` — уязвимости с таким ID нет; `context.Canceled` / `DeadlineExceeded` |
| **Что делает Dispatcher** | часть пакетов в `unchecked` → скан в `partial`; ошибка `vuln_source_unavailable` → `failed` |

Внутри реализации, невидимо для Dispatcher: таймаут запроса, ограниченные повторы с задержкой
только для `5xx`, `429` и сетевых ошибок, проверка формата ответа, дочитывание страниц
(`next_page_token`), кэш деталей уязвимостей, расчёт критичности из CVSS.

### Реализация 1: `OSVClient` — OSV.dev

- `QueryBatch` → `POST https://api.osv.dev/v1/querybatch`, пакеты отправляются пачками.
- `GetVuln` → `GET https://api.osv.dev/v1/vulns/{id}`; CVE берётся из `aliases`, версия с исправлением —
  из записи `affected` нужного пакета и диапазона, куда попадает его версия.
- Критичность: CVSS-вектор → оценка → уровень; если вектора нет — `database_specific.severity`;
  если нет и его (записи `GO-…`) — та же цепочка для алиаса `GHSA-…`; иначе `UNKNOWN`.
- Ответ, который не разбирается как JSON или в котором нет обязательных полей, считается
  ошибкой источника так же, как `5xx`.

### Реализация 2: `FakeVulnSource` — для тестов

- Отдаёт ответы из `testdata/osv/*.json` — сохранённые реальные ответы OSV.dev.
- Умеет имитировать отказ: задержку дольше таймаута, `503`, некорректный JSON, переименованное поле.
- Используется в модульных и интеграционных тестах и для запуска без интернета.
