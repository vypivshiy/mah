# DEVEL

## Оглавление:

- [Дамп моделей](#дамп-моделей)
- [Кодогенерация из дампа](#кодогенерация-из-дампа)
- [Как с этим работать?](#как-с-этим-работать)
- [Транспорт](#транспорт)

## Дамп моделей

dumper/ - скрипт для IDA pro 7.1+ для дампа структур пакетов для последующей генерации SDK. требуется hex-rays декомпилятор, на free версии не будет работать.

dumper_binja/ - скрипт для Binary ninja 5.2+ для дампа структур. Сканирует медленнее, потребляет больше ОЗУ, но **точнее извлекает типы полей** (подробнее ниже). Требуется версия personal или выше, на free не будет работать.

Извлечение:
* скачать windows client https://download.max.ru/#desktop

>[!note]
> (24.05.2026) если будете вручную скачивать установочный файл нажимайте "MSI для организаций".
> в кнопке "WINDOWS" при определенных условиях может начать скачивать `MAX+Yandex.msi` с яндекс браузером. 
> Из отличий, только добавляет в client hello индетификатор установки yandex браузера.

![](img/download.png)


или воспользуйтесь скриптами:

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\download_win_max.ps1`
```
*Unix

```shell
chmod +x download_win_max.sh
./download_win_max.sh
```

* Вы можете установить мессенджер и вручную найти `core.dll` файл или воспользуйтесь скриптами для его извлечения:

Нужно положить установочник `MAX.msi` в каталог. Требуется установленный архиватор 7zip в системе с доступом к команде `7z`:

Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\extract_msi.ps1
```

с задаванием параметров:

```powershell
powershell -ExecutionPolicy Bypass -File .\extract_msi.ps1 `
    -Msi "C:\temp\MAX(3).msi" `
    -Out "C:\temp\unpack"
```

*Unix:

дать доступ на выполнение:

```shell
chmod +x extract_msi.sh
```

запустить:

```shell
./extract_msi.sh
```

с кастомными параметрами:

```shell
./extract_msi.sh "/path/to/file.msi" "/tmp/unpack"
```

### IDA Pro

Запуск:
1. загрузить dll в ida-pro
2. подождать полное сканирование проекта (в левом нижнем углу должен быть label `AU: idle | Down` )
3. загрузить скрипт (File -> Script File...) dumper/run.py, ждать когда сохранит дамп 
4. дамп сохранится в директории откуда загружали dll в IDA-PRO, не в папке со скриптом

#### Структура дампера

| Файл                        | Назначение                                                      |
| --------------------------- | --------------------------------------------------------------- |
| `dumper/run.py`             | Точка входа, загрузка и запуск анализатора                      |
| `dumper/analyzer.py`        | Оркестрация: сбор пакетов, анализ типов, сохранение JSON        |
| `dumper/field_extractor.py` | Извлечение полей структур (hex-rays + fallback на дизассемблер) |
| `dumper/common.py`          | Общие утилиты                                                   |
| `dumper/ida_utils.py`       | IDA-специфичные хелперы                                         |
| `dumper/symbol_index.py`    | Индексация символов                                             |
| `dumper/template_parser.py` | Парсинг шаблонов типов                                          |

#### Overview дампа

```
{
  "image_base": "0x180000000",  // базовый адрес, для отладки в дизассемблере
  "app_version": str, //  версия билда клиента
  "build_number": int, // номер сборки
  "rpc_ver": 11,  // версия RPC протокола
  "packets": [...],  // дамп request/response пакетов
  "models": { ... }, // вложенные типы объектов
  "polymorphic_models": { ... },  // наследуемые типы
  "opcodes": [int, ...],  // все найденные опкоды в дампах. Чтобы в кодовой базе не создавать "магические" числа
  "string_enums": [str, ...] // все найденные строковые константы, которые используются в payload. Чтобы не плодить "магические" строковые константы
}
```

`type` каждого поля — это **строка C++ типа** (например `"std::optional<__int64>"`). Кодогенератору приходится парсить эти шаблоны самостоятельно.

#### Пример пакета

```
    {
      "opcode": 64,  // номер опкода команды
      "request": {   // объект для запроса (ориентироваться на этот payload)
        "full_name": "Api::OneMe::Packets::Messaging::Send::Parameters",  // найденная структура
        "kind": "Parameters",
        "name_method": "hexrays",
        "offset": "0x3f46c0",  // оффсет для отладки в декомпиляторе из снятого клиента
        "fields": [  // поля payload структуры
          {
            "name": "chatId",  // имя ключа
            "type": "std::optional<__int64>",  // определенный c++ тип данных декомпилятором
            "required": true  // обязательный параметр (эвристическая метка)
          },
          {
            "name": "postId",
            "type": "std::optional<__int64>",
            "required": true
          },
          {
            "name": "userId",
            "type": "std::optional<__int64>",
            "required": true
          },
          {
            "name": "notify",
            "type": "std::optional<bool>",
            "required": true
          },
          {
            "name": "message",
            "type": "Api::OneMe::Types::OutgoingMessage", // вложенный тип, искать его в "models"
            "required": true
          },
          {
            "name": "lastKnownDraftTime",
            "type": "std::optional<__int64>",
            "required": true
          }
        ],
        "warn": null  // используется для записи если не все типы определились
      },
      "response": {  // структура ответа
        "full_name": "Api::OneMe::Packets::Messaging::Send::Response",
        "kind": "Response",
        "name_method": "hexrays",
        "offset": "0x3f4af0",
        "fields": [
          {
            "name": "chatId",
            "type": "__int64",
            "required": true
          },
          {
            "name": "postId",
            "type": "std::optional<__int64>",
            "required": true
          },
          {
            "name": "message",
            "type": "Api::OneMe::Types::Message",
            "required": true
          },
          {
            "name": "chat",
            "type": "std::optional<Api::OneMe::Types::Chat>",
            "required": true
          },
          {
            "name": "unread",
            "type": "std::optional<int>",
            "required": true
          },
          {
            "name": "mark",
            "type": "std::optional<__int64>",
            "required": true
          }
        ],
        "warn": null
      }
    },
```

#### пример модели

```
{
  "Api::OneMe::Types::OutgoingMessage": {  // имя определенной структуры-модели
      "fields": [
        {
          "name": "cid",
          "type": "std::optional<__int64>",
          "required": true
        },
        {
          "name": "text",
          "type": "std::optional<std::string>",
          "required": true
        },
        {
          "name": "zoom",
          "type": "std::optional<int>",
          "required": false
        },
        {
          "name": "attaches",
          "type": "std::optional<std::vector<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::Outgoing::BaseAttachment,Api::OneMe::Types::Outgoing::BaseAttachment>>>",
          "required": true
        },
        {
          "name": "link",
          "type": "std::optional<Api::OneMe::Types::OutgoingMessage::OutgoingMessageLink>",
          "required": true
        },
        {
          "name": "attachMEL",
          "type": "std::optional<bool>",
          "required": true
        },
        // ошибка декомпилятора, реальный тип bool
        // ниже будет инструкция как исправить
        {
          "name": "ttl",
          "type": "std::optional<int>",
          "required": true
        },
        {
          "name": "isLive",
          "type": "std::optional<bool>",
          "required": true
        },
        {
          "name": "elements",
          "type": "std::optional<std::vector<Api::OneMe::Types::MessageElement>>",
          "required": true
        },
        {
          "name": "delayedAttributes",
          "type": "std::optional<Api::OneMe::Types::DelayedTamAttributes>",
          "required": true
        }
      ],
      "name_method": "hexrays",
      "offset": "0x87a6d0",
      "warn": null
    }
}
```

пример полиморфной модели вложений (наследуемые типы от базового):

```json
{
  "Api::OneMe::Types::BaseAttachment": {
    "variants": {
      "Api::OneMe::Types::ContactAttachment": {
        "fields": [
          { "name": "_type", "type": "std::string", "required": true },
          { "name": "deleted", "type": "std::optional<bool>", "required": true },
          { "name": "contactId", "type": "std::optional<__int64>", "required": true },
          { "name": "firstName", "type": "std::string", "required": false },
          { "name": "lastName", "type": "std::optional<std::string>", "required": false },
          { "name": "vcfBody", "type": "std::optional<std::string>", "required": true }
        ]
      },
      "Api::OneMe::Types::AudioAttachment": {
        "fields": [
          { "name": "_type", "type": "std::string", "required": true },
          { "name": "deleted", "type": "std::optional<bool>", "required": true },
          { "name": "audioId", "type": "__int64", "required": true },
          { "name": "url", "type": "std::optional<std::string>", "required": false },
          { "name": "duration", "type": "int", "required": true }
        ]
      }
    }
  }
}
```

### Binary Ninja

`dumper_binja/` — альтернативный дампер. Сканирует медленнее, потребляет больше ОЗУ, но **точнее извлекает типы полей**. Главный плюс: сырая строка C++ тип приходит **структурированным объектом** с явными флагами `optional` / `array` / `map` и базовым именем — кодогенератору не нужно парсить шаблоны.

Запуск:
1. загрузить `core.dll` в Binary Ninja (Personal версия и выше), дождаться **полного** завершения анализа
2. запустить `dumper_binja/run.py` через **File -> Run Script...** или Scripting console
3. дождаться сообщения о сохранении дампа
4. результат сохранится в `packets_binja.json` рядом с `.bndb`

#### Структура дампера

| Файл                             | Назначение                                                        |
| -------------------------------- | ----------------------------------------------------------------- |
| `dumper_binja/run.py`            | Точка входа, bootstrap загрузчик                                  |
| `dumper_binja/analyzer.py`       | Оркестрация: сбор пакетов, анализ, сохранение JSON                |
| `dumper_binja/field_extractor.py`| Извлечение полей структур на базе HLIL                            |
| `dumper_binja/type_parser.py`    | Разложение C++ типа в структурированный объект (optional/array/map) |
| `dumper_binja/template_parser.py`| Парсинг шаблонов типов                                            |
| `dumper_binja/symbol_index.py`   | Индексация символов                                               |
| `dumper_binja/binja_utils.py`    | Binary Ninja-специфичные хелперы                                  |
| `dumper_binja/common.py`         | Общие утилиты                                                     |
| `dumper_binja/PATCHES.py`        | Ручные правки типов (переопределение/удаление полей)              |

#### Отличия формата дампа от IDA

- `type` — это **объект**, а не строка. `type_parser.py` раскладывает C++ тип так:
  ```
  decompose_type("std::optional<std::vector<...Contact>>")
    -> { "full": "...", "name": "базовый тип", "optional": true, "array": true, "map": false, "map_key": null, "map_value": null }
  ```
- `models` — это **список** объектов (`[{ "name", "offset", "fields", "warn" }, ...]`), а не словарь по имени
- доп. top-level ключи: `events` (серверные пуши/нотификации), `error` (структура ошибки)

#### Пример пакета

Тот же пакет (`opcode: 64`) в дампе из Binary Ninja — обратите внимание на формат `type`: это объект с явными флагами вместо строки C++ шаблона:

```
    {
      "opcode": 64,
      "request": {
        "offset": "0x452dc0",
        "name": "Api::OneMe::Packets::Messaging::Send::Parameters",
        "fields": [
          {
            "name": "chatId",
            "type": {
              "full": "std::optional<int64_t>",   // исходная C++ строка (для отладки или fallback)
              "name": "int64_t",                  // базовый тип
              "optional": true,                   // std::optional<T>?
              "array": false,                     // std::vector<T>?
              "map": false,                       // *map<K, V>?
              "map_key": null,                    // K
              "map_value": null                   // V
            },
            "required": true
          },
          // ... postId / userId / notify / lastKnownDraftTime — int64_t/bool, optional: true
          {
            "name": "message",
            "type": {
              "full": "Api::OneMe::Types::OutgoingMessage",  // вложенная модель
              "name": "Api::OneMe::Types::OutgoingMessage",
              "optional": false,
              "array": false,
              "map": false,
              "map_key": null,
              "map_value": null
            },
            "required": true
          }
        ],
        "warn": null
      }
    }
```

#### пример модели

Та же модель `OutgoingMessage`, но типы — объекты. Сравните поле `attaches`: у IDA это «полотно» `std::optional<std::vector<...Polymorphic<...>>>`, которое надо парсить, здесь — `array: true` + базовое имя:

```
{
  "name": "Api::OneMe::Types::OutgoingMessage",
  "offset": "0x2becb0",
  "fields": [
    {
      "name": "cid",
      "type": { 
        "full": "std::optional<int64_t>", 
        "name": "int64_t", 
        "optional": true, "array": false, 
        "map": false, 
        "map_key": null, 
        "map_value": null 
        },
      "required": true
    },
    {
      "name": "text",
      "type": { 
        "full": "std::optional<std::string>", 
        "name": "std::string", 
        "optional": true, 
        "array": false, 
        "map": false, 
        "map_key": null, 
        "map_value": null 
        },
      "required": false
    },
    {
      "name": "attaches",
      "type": {
        "full": "std::optional<std::vector<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::Outgoing::BaseAttachment>>>",
        "name": "Api::OneMe::Types::Polymorphic<Api::OneMe::Types::Outgoing::BaseAttachment>",
        "optional": true,
        "array": true,   // <-- явно массив (std::vector), парсить не нужно
        "map": false,
        "map_key": null,
        "map_value": null
      },
      "required": true
    },
    {
      "name": "ttl",
      "type": { 
        "full": "std::optional<int32_t>", 
        "name": "int32_t", 
        "optional": true, 
        "array": false,
        "map": false, 
        "map_key": null, 
        "map_value": null 
        },
      "required": true
    }
    // ... link / attachMEL / isLive / elements / delayedAttributes / type
  ],
  "warn": null
}
```

## Дамп конфигурации

нужен `config.dll` клиента или `CM_FP_Unspecified.config.dll` из установочного файла. Требуется python 3.8+

* распаковать в папку
* запустить `python config_extractor.py CM_FP_Unspecified.config.dll`
* в config.json будут дополнительные данные, которые могут пригодится ("api_version_uint" и "user_agent" )

>[!important]
>
> Не хардкодьте эти значения в клиенте — берите из извлечённого `config.json`, чтобы SDK оставался актуальным при обновлениях:
>
> | Параметр | Ключ в config.json | Пример | Назначение |
> | --- | --- | --- | --- |
> | версия RPC / API | `api_version_uint` | `11` | поле `ver` заголовка пакета. Совпадает с `rpc_ver` в дампе структур |
> | api endpoint (host) | `ssl_url` | `api.oneme.ru` | хост TCP/TLS подключения |
> | api endpoint (port) | `ssl_port` | `443` | порт подключения |
> | user-agent | `user_agent` | `OneMe Desktop` | передаётся в рукопожатии |
> | интервал PING | `ping_interval` | `30000` (мс) | keepalive, чтобы сервер не закрыл соединение |
>
> `rpc_ver: 11` из дампа структур и `api_version_uint: 11` из config — это один и тот же источник истины.

### Пайплайн дампа

```
+-------------+     +---------+     +----------------+     +--------------+
| *core.dll   |---->| IDA Pro |---->| dumper/run.py  |---->| packets.json |
+-------------+     +---------+     +----------------+     +--------------+
```

## Кодогенерация из дампа

Примеры скриптов на python генерируют готовый шаблонный код в соответствии описанию структур с трансформацией c++ типов в его аналог:

```
+---------------+     +-----------------------------+     +-------------+
| packets.json  |---->| codegen_script              |---->| *.py / *.go | <--- любые расширения
+---------------+     +-----------------------------+     +-------------+
```

Пример запуска генератора (из папки проекта):

```
python generate_py.py packets.json python_max_tcp/
```

### Советы по дизайну кодогенератора

>[!tip]
>
> Этот раздел для тех, кто хочет через LLM по принципу vibecode максимально быстро реализовать кодогенератор. Финального кода выйдет <2000 строк кода. Для этой задачи подойдут бюджетные LLM модели в режим чата из браузера+copy-paste.
>
> Если вам идеология не позволяет генерировать слоп или вы знаете как сделать лучше - пропускайте написанное.

Для реализации рекомендуется использовать простые, мейнстримные, динамические скриптовые ЯП. Компилируемые ЯП подойдут, **если есть динамические списки для строк**, но не рекомендуются, они могут быть избыточны для этой задачи для нечастой генерации кода. 
Прикладывайте минимальный образец дампов и все cpp типы которые применяются.
Транспорт можно отдельно сгенерировать - его практически не нужно изменять, нужно только добавлять shortcut методы для удобства вызова.

>[!tip]
>
> Чтобы **MAX**сиамально упростить создание кодогенератора через LLM, рекомендуется не тащить шаблонизаторы или конкатенировать строки: собирайте все куски строк в динамический лист и затем объединяйте в конце. Да это не самый эффективный и элегантный подход, но это стабильный способ с минимумом галлюцинаций для ваибкод победы!


```python
# не рекомендуется, LLM может запутаться:
result = "def foo():"
result += "\n    x = "
result += str(42)  # <-- здесь модель "видит" незавершённый паттерн

# отлично, LLM не путается в контексте, стабильно генерирует
# семантически модель "понимает" завершение конструкций фрагментов
parts = []
parts.append("def foo():")
parts.append("    return 42")
result = "".join(parts)  # LLM видит чёткую границу закрытия операции

# тоже норм, меньше цепочек вызовов, приятнее читать, LLM vibecode friendly
code = []
code.extend([
  "def foo():",
  "    return " + str(42),
])
result = "\n".join(code)
```

Даже если "глаза вытекают" от такой реализации и очень руки чешется что-то типа такого вынести в константу - максимум выводите такие блоки кода в отдельные вспомогательные методы или функции, выносить в константы не рекомендуется.

```python
# ужас, хочется в константу вынести это полотно!
code.extend([
            "// Client is the main API client.",
            "type Client struct {",
            "  AppVersion string",
            "  VerboseLog bool",
            "  conn       net.Conn",
            "  wsConn     *websocket.Conn",
            "  useWS      bool",
            "  seq        uint8",
            "  mu         sync.Mutex",
            "  pending    map[uint8]chan *Packet",
            "  handlers   map[uint16][]func(*Packet)",
            "  closeCh    chan struct{}",
            "}",
            "",
        ])
```


### Замечания по финальным моделям

* так как это неофициальный API, базирующийся на дампе, **100% стабильность и полнота структур не гарантируется**. Чтобы код неожиданно не падал в runtime, в архитектуру закладывайте следующие условия:
  * для статик ЯП закладывайте safe геттеры и допускайте ситуации, что payload пакета может отличаться от сгенерированного: разработчики могут добавлять новые поля или убрать старые. Например, это явно видно явно на модели для настроек `Api::OneMe::Types::UserSettings` и на response `"opcode": 22, "Api::OneMe::Packets::Config"`
  * `std::optional<T>` в большинстве случаев больше подходит по смыслу как `NotRequired` поле. Из дампа это узнать невозможно, ориентируйтесь на реальное поведение клиента
  * Может понадобиться делать патчи в файле `dev/dumper/PATCHES.py`, чтобы тип данных совпадал с реальным.
    * Например, в ["models"]["Api::OneMe::Types::Message"] дизассемблер определил поле `ttl` как `std::optional<int>`, но в реальности он bool:

  ```json
  "Api::OneMe::Types::Message": {
      "fields": [
        // ...
        {
          "name": "attaches",
          "type": "std::optional<std::vector<Api::OneMe::Types::Polymorphic<Api::OneMe::Types::BaseAttachment,Api::OneMe::Types::BaseAttachment>>>",
          "required": true
        },
        {
          "name": "link",
          "type": "std::optional<std::shared_ptr<Api::OneMe::Types::MessageLink>>",
          "required": true
        },
        // ОШИБКА! Ральный тип этого поля - bool, а не int
        {
          "name": "ttl",
          "type": "std::optional<int>",
          "required": true
        },
        // ...
      ],
    },

  ```
* для динамических ЯП не рекомендуется сериализовывать payload объекты в жесткие структуры (например python dataclasses, pydantic). Используйте хеш-таблицы с аннотациями.
  * для python это [typing.TypedDict](https://docs.python.org/3/library/typing.html#typing.TypedDict) с параметром `total=False`.
  * для javascript - [jsdoc](https://jsdoc.app/)

### Как с этим работать?

>[!warning]
> Раздел устарел. структура пакетов в браузере изменилась (на webproto?). пакеты аналогично упаковываются как в tcp реализации.

>[!tip]
> Код надо сгенерировать. Генератором. Я его дам. Как этим пользоваться нужна документация. Документацию я не дам.

Её не существует в природе, надо проводить обратную разработку, смотреть траффик реальных приложений: в  мобильном приложении или его ближайшем аналоге - веб версии. Сгенерированные модели помогут в автокомплите - описывать модели руками не нужно!

![example](img/image.png)

Пример автокомплита реализации отправки сообщения

В демонстрационных SDK показана минимальная демонстрация авторизации и применения методов.

## Транспорт

> [!note]
> WebSocket клиент может отличаться от десктопного TCP-клиента. В этом документе рассматривается **только TCP** реализация.

### Формат TCP-пакета

Каждый пакет — это 10-байтный заголовок (big-endian) + тело:

```
┌──────────┬──────────┬──────────┬──────────┬───────────────────┐
│  ver (1) │ cmd (2)  │ seq (1)  │opcode(2) │  packed_len (4)   │
└──────────┴──────────┴──────────┴──────────┴───────────────────┘
┌───────────────────────────────────────────────────────────────┐
│                     payload (N bytes)                         │
└───────────────────────────────────────────────────────────────┘
```

| Поле         | Размер  | Описание                                                                                                                  |
| ------------ | ------- | ------------------------------------------------------------------------------------------------------------------------- |
| `ver`        | 1 byte  | Версия протокола (11)                                                                                                     |
| `cmd`        | 2 bytes | Тип: клиент всегда шлёт `0`, сервер отвечает значением от 0-256 (не исследовано поведение)                                |
| `seq`        | 1 byte  | Порядковый номер запроса (0–255, циклический). Сервер отвечает тем же seq (на практике может быть 2bytes, не исследовано) |
| `opcode`     | 2 bytes | Номер команды (определяет, что именно запрашиваем/получаем)                                                               |
| `packed_len` | 4 bytes | **Старший байт** — флаг lz4-сжатия (`0` или `1`), **младшие 3 байта** — длина payload                                     |

struct: `!BHBHI` (network byte order / big-endian)

### Payload

Раздел основан на наработках https://github.com/nyakokitsu/MaxProtoExplanation/, здесь его краткая выжимка с диаграммами.

- **Сериализация**: [msgpack](https://msgpack.org/)
- **Сжатие**: если payload после msgpack > 4096 байт и lz4-сжатие даёт выгоду — сжимается через `lz4.block` (raw block, без сохранения оригинального размера в заголовке lz4)
- При получении: если `comp_flag == 1` — сначала lz4 decompress, затем msgpack unpack

#### Как отправить пакет

```
 Приложение                    BaseClient                     TCP Socket (TLS)
     |                              |                                |
     |  send_raw(opcode, payload)   |                                |
     |----------------------------->|                                |
     |                              | seq = (seq + 1) & 0xFF         |
     |                              | pending[seq] = Future          |
     |                              |                                |
     |                              | payload= msgpack.packb(payload)|
     |                              |                                |
     |                              | [payload_bytes > 4096?]        |
     |                              |   compressed = lz4.compress    |
     |                              |   [len(compressed) < len?]     |
     |                              |     comp_flag = 1              |
     |                              |     payload_bytes = compressed |
     |                              |                                |
     |                              | packed_len = (comp_flag << 24) | len(payload_bytes)
     |                              | HEADER                         | (header = struct.pack("!BHBHI", 11, 0, seq, opcode, packed_len))
     |                              |                                |
     |                              |   header + payload_bytes       |
     |                              |------------------------------->|
     |                              |                                |
     |                              |   [сервер обрабатывает...]     |
     |                              |<-------------------------------|
     |                              |                                |
     |                              | _read_loop() получает ответ    |
     |                              |                                |
     |   Packet(opcode, payload)    |                                |
     |<-----------------------------|                                |
```

**TLDR**
1. Сериализуем payload через msgpack
2. Если результат > 4 KB — пытаемся сжать lz4, ставим флаг сжатия (неизвестно, нужно ли это делать?)
3. Собираем 10-байтный заголовок с `cmd=0`, текущим `seq` и нужным `opcode`
4. Отправляем `header + payload` в TCP-сокет
5. Сохраняем `seq → Future` в словарь pending-запросов
6. Ждём, пока фоновый read loop не сопоставит ответ по seq и не зарезолвит Future

#### Как принять пакет

>[!warning]
> В PoC реализации используется максимальный размер в 0xFFFFFF. Не исследовано какого максимального размера может быть реальный пакет. Учитывайте это, чтобы оптимизировать потребление памяти!

```
 +------------------------------+
 | _read_loop: фоновая корутина |
 +------------------------------+
                |
                v
 +------------------------------+
 | readexactly 10 bytes         |
 +------------------------------+
                |
                v
 +-------------------------------------------------+
 | parse header: ver, cmd, seq, opcode, packed_len |
 +-------------------------------------------------+
                |
       +--------+--------+
       |                 |
       v                 v
 +--------------------+  +--------------------------------+
 | comp_flag =        |  | payload_len =                  |
 | packed_len >> 24   |  | packed_len & 0xFFFFFF          |
 +--------------------+  +--------------------------------+
                              |
                              v
                +-------------------------------+
                | readexactly payload_len bytes |
                +-------------------------------+
                              |
                              v
                    +-------------------+
                    | comp_flag != 0 ?  |
                    +-------------------+
                     /                 \
                   Да                  Нет
                    |                   |
                    v                   |
 +---------------------------+          |
 | lz4.block.decompress      |          |
 +---------------------------+          |
                    |                   |
                    +--------+----------+
                             |
                             v
                +------------------------------+
                | msgpack.unpackb              |
                +------------------------------+
                             |
                             v
                +------------------------------+
                | Packet объект                |
                +------------------------------+
                             |
                             v
                +------------------------------+
                | _dispatch                    |
                +------------------------------+
                             |
                    +--------+--------+
                    |                 |
                    v                 v
          +----------------+  +--------------------+
          | pending есть   |  | нет pending по seq |
          | по seq? - Да   |  |                    |
          +----------------+  +--------------------+
                    |                 |
                    v                 v
          +----------------+  +--------------------+
          | resolve Future |  | есть handler по    |
          +----------------+  | opcode?            |
                    |         +--------------------+
                    |          /           \
                    |        Да            Нет
                    |         |             |
                    |         v             v
                    | +----------------+ +-------------+
                    | | вызвать handler| | игнорировать|
                    | +----------------+ +-------------+
                    v
          +-------------------------------+
          | send_raw() получает результат |
          +-------------------------------+
```

**TLDR:**
1. Фоновая корутина `_read_loop()` вечно читает из сокета
   1. Чтобы не оборвалось соединение: как оригинальный клиент, присылайте каждые 30 секунд команду PING (opcode=1) и читайте
2. Сначала reads exactly 10 байт — заголовок
3. Извлекает длину payload (маскируем флаг сжатия)
4. Читает ровно столько байт тела
5. Если стоит флаг сжатия — lz4 decompress
6. msgpack unpack → получаем `Packet`
7. `_dispatch()` ищет pending Future по `seq` — если нашёл, резолвит (это ответ на наш запрос)
8. Также вызывает зарегистрированные handlers по `opcode` (это серверные пуши/нотификации)

### Seq — корреляция запрос-ответ

`seq` — это 1-байтный счётчик (0–255, wrap around, (может быть больше, не исследовано)). Он единственный способ понять, какой ответ к какому запросу относится:

```
Клиент шлёт:     seq=5  opcode=64   → "отправить сообщение"
Сервер отвечает:  seq=5  opcode=64   → "сообщение отправлено, вот result"

Клиент шлёт:     seq=6  opcode=22   → "получить конфиг"
                  seq=7  opcode=64   → "отправить ещё"
Сервер отвечает:  seq=7  opcode=64   → "вот ответ на второй запрос"
                  seq=6  opcode=22   → "вот конфиг" (может прийти в любом порядке!)
```

### Пример

Краткий пример реализации python asyncio транспорта. Корреляция запрос-ответ по `seq` через словарь Future'ов, отдельные handler'ы для серверных пушей по `opcode`, heartbeat PING по интервалу из config, и проверка серверной ошибки.

```python
import asyncio
import struct
import ssl
import msgpack
import lz4.block

PROTO_VER = 11
HEADER_FMT = "!BHBHI"   # ver, cmd, seq, opcode, packed_len
HEADER_SIZE = 10
COMPRESS_THRESHOLD = 4096
# api endpoint / rpc-версию / ping-интервал БЕРИТЕ ИЗ config.json!
HOST, PORT = "api.oneme.ru", 443
PING_INTERVAL = 30  # config.json["ping_interval"] / 1000

# маркер определения ошибки. ровно столько ключей
_API_ERROR_KEYS = {"error", "message", "title", "localizedMessage"}


class ApiError(Exception):
    def __init__(self, payload):
        self.title = payload.get("title", "")
        self.message = payload.get("message", "")
        super().__init__(f"{self.title}: {self.message}")


def _check_error(payload):
    if isinstance(payload, dict) and payload.keys() == _API_ERROR_KEYS:
        raise ApiError(payload)


def pack(seq, opcode, payload):
    body = msgpack.packb(payload, use_bin_type=True)
    comp = 0
    if len(body) > COMPRESS_THRESHOLD:
        z = lz4.block.compress(body, store_size=False)
        if len(z) < len(body):
            body, comp = z, 1
    packed_len = (comp << 24) | (len(body) & 0xFFFFFF)
    return struct.pack(HEADER_FMT, PROTO_VER, 0, seq, opcode, packed_len) + body


def unpack(data):
    ver, cmd, seq, opcode, packed_len = struct.unpack(HEADER_FMT, data[:HEADER_SIZE])
    body = data[HEADER_SIZE:HEADER_SIZE + (packed_len & 0xFFFFFF)]
    if packed_len >> 24:
        body = lz4.block.decompress(body, uncompressed_size=8 * 1024 * 1024)
    payload = msgpack.unpackb(body, raw=False) if body else None
    return cmd, seq, opcode, payload


class Client:
    def __init__(self):
        self.reader = self.writer = None
        self.seq = 0
        self._write_lock = asyncio.Lock()
        self._pending: dict[int, asyncio.Future] = {}      # seq -> Future (запрос-ответ)
        self._handlers: dict[int, list] = {}               # opcode -> [handler] (серверные пуши)

    async def connect(self):
        ctx = ssl.create_default_context()
        self.reader, self.writer = await asyncio.open_connection(HOST, PORT, ssl=ctx)
        asyncio.create_task(self._read_loop())

    def on(self, opcode):
        """Регистрация handler'а для серверного пуша (декоратор)."""
        def deco(fn):
            self._handlers.setdefault(opcode, []).append(fn)
            return fn
        return deco

    async def send(self, opcode, payload, timeout=30.0):
        """Отправить запрос и дождаться ответа по seq."""
        async with self._write_lock:
            seq = self.seq
            self.seq = (self.seq + 1) & 0xFF
            fut = asyncio.get_running_loop().create_future()
            self._pending[seq] = fut
            self.writer.write(pack(seq, opcode, payload))
            await self.writer.drain()
        try:
            resp = await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            raise
        _check_error(resp[3])            # серверная ошибка вместо данных
        return resp

    async def _read_loop(self):
        """Фоновое чтение: читает пакеты и диспетчеризирует."""
        try:
            while True:
                header = await self.reader.readexactly(HEADER_SIZE)
                body = await self.reader.readexactly(
                    struct.unpack(HEADER_FMT, header)[4] & 0xFFFFFF
                )
                pkt = unpack(header + body)
                # ответ на наш запрос?
                fut = self._pending.pop(pkt[1], None)
                if fut is not None and not fut.done():
                    fut.set_result(pkt)
                # серверный пуш — дёргаем handler'ы по opcode
                for fn in self._handlers.get(pkt[2], []):
                    asyncio.create_task(fn(pkt))
        except asyncio.IncompleteReadError:
            pass  # соединение закрыто сервером


async def main():
    client = Client()
    await client.connect()
    # пропущены шаги отправки Client Hello и авторизации

    # heartbeat: PING каждые PING_INTERVAL сек, иначе сервер рвёт соединение
    async def ping():
        while True:
            await asyncio.sleep(PING_INTERVAL)
            await client.send(1, {"interactive": False})
    asyncio.create_task(ping())

    # opcode=64 — отправить сообщение (пример пакета см. выше)
    resp = await client.send(64, {"chatId": 123, "message": {"text": "hi"}})
    print("ответ:", resp)


asyncio.run(main())
```

>[!tip] Что можно заложить в реальный транспорт
> * **seq-корреляция** — единственный способ сопоставить ответ с запросом; `seq` крутится `& 0xFF`
> * **раздельные потоки диспетчеризации**: `_pending[seq]` для ответов на запросы, `_handlers[opcode]` для серверных пушей/нотификаций
> * **one-shot ожидание** конкретного opcode (`wait_for(opcode, filter=...)`) удобно для последовательностей «запросил → ждём событие»
> * **heartbeat PING** по `ping_interval` из config — без него сервер закроет соединение
> * **проверка `ApiError`** — сервер может вернуть payload `{error, message, title, localizedMessage}` вместо ожидаемых данных
> * **переподключение** с exponential backoff и отменой всех pending Future'ов при разрыве
