# Compliance Auth Service

Backend-сервис экосистемы Trustflow: **аутентификация и авторизация**, учёт пользователей, ролей и прав, интеграция с **OAuth2 Authorization Server** (JWT) и внешними сервисами (CMS, Kafka).

## Стек и инструменты

| Компонент | Технология |
|-----------|------------|
| Язык | Java **21** |
| Фреймворк | **Spring Boot 4.0** |
| Сборка | **Maven** |
| БД | **PostgreSQL**, миграции **Flyway** |
| Безопасность | **Spring Security**, **OAuth2 Authorization Server**, JWT |
| Очереди | **Spring Kafka** (producer/consumer) |
| API-документация | **SpringDoc OpenAPI 3** (Swagger UI) |
| Мониторинг | **Spring Boot Actuator** (health, metrics, prometheus) |
| Тесты | JUnit, **Testcontainers** (PostgreSQL в интеграционных тестах) |

Артефакт Maven: `com.trustflow:compliance-auth-service`.

## Структура кода

Пакет `com.trustflow.compliance_auth_service`:

- `config/` — Spring Security, OAuth2 AS, Kafka, OpenAPI, JWT и прочая конфигурация  
- `controller/` — REST-контроллеры (`/auth`, `/api/users`, `/api/tokens`, внутренний `/api/internal/users`)  
- `domain/` — JPA-сущности и перечисления (роли, права)  
- `dto/` — объекты запросов/ответов API  
- `repository/` — Spring Data JPA  
- `service/` — бизнес-логика, Kafka-продюсер/листенер, интеграции  
- `exception/` — исключения и глобальный обработчик ошибок  

Миграции БД: `src/main/resources/db/migration/`.

## Запуск и сборка

```bash
# Компиляция
mvn clean compile

# Тесты
mvn test

# Интеграционные тесты (пример)
mvn test -Dtest="*IT"

# Сборка JAR
mvn clean package

# Локальный запуск
mvn spring-boot:run
```

Инфраструктура для разработки описана в `docker-compose.yaml`: PostgreSQL, Zookeeper, Kafka, Kafka UI. Параметры подключения к Kafka/БД для контейнерного профиля смотрите в `application-docker.yaml` и переменных окружения (порты брокера на хосте могут отличаться от `localhost:9092` — сверяйте с compose и `KAFKA_BOOTSTRAP_SERVERS`).

Сборка образа и запуск с БД при необходимости:

```bash
docker build -t compliance-auth-service .
# docker-compose — см. комментарии в AGENTS.md / compose-файле
```

## Конфигурация

- Основной файл: `src/main/resources/application.yaml`  
- Docker-профиль: `application-docker.yaml`  
- Опционально локальные секреты: импорт `optional:file:.env[.properties]`  

**По умолчанию (локально):**

- HTTP-порт приложения: **9091**  
- PostgreSQL: `localhost:5432`, БД `auth_db` (учётные данные в `application.yaml`)  
- Kafka bootstrap: `localhost:9092` (переопределение: `KAFKA_BOOTSTRAP_SERVERS`)  
- Интеграция CMS (информация о компании/сотруднике): `integration.cms-company-info.base-url` (`CMS_COMPANY_INFO_BASE_URL`)  

Ключи OAuth2/JWT и клиенты authorization server настраиваются в `application.yaml` (см. блок `oauth2.authorization-server`).

## Функциональность в общих чертах

- **Регистрация и вход** (`/auth`): выдача access/refresh токенов, регистрация пользователей (в т.ч. первый EXECUTIVE с компанией).  
- **Пользователи** (`/api/users`): список по компании, профиль, обновление, статус, удаление, текущий пользователь (`/me`).  
- **Токены** (`/api/tokens`): сведения о токене, массовая отзыв по username (по правилам безопасности в коде).  
- **Права** (часть маршрутов под `/api/users`): проверки и управление доступом, синхронизировано с таблицей `permissions`.  
- **Внутренний API** (`/api/internal/users/{id}`): выдача пользователя по ID для локальных/доверенных вызовов (ограничение по loopback в контроллере).  

Роли приложения моделируются через сущность `Role` и enum `RoleType` (например, MANAGER, SUPERVISOR, EXECUTIVE, DEFAULT).

## Документация API (Swagger)

После запуска сервиса:

- Swagger UI: `http://localhost:9091/swagger-ui.html`  
- OpenAPI JSON: `http://localhost:9091/v3/api-docs`  

Сканируются контроллеры с путями `/api/**` и `/auth/**` (см. `springdoc` в `application.yaml`).

## Взаимодействие с другими сервисами

Ниже — как **этот сервис** связан с остальной экосистемой: кто к нему обращается, куда он сам ходит по HTTP и что обменивается через Kafka.

### Кто выступает клиентом auth-service

Сервис поднимает **OAuth2 Authorization Server** и REST API (`/auth`, `/api/**`). К нему обращаются:

- **SPA / фронтенд** и **бэкенд-сервисы** (мониторинг, правила, workflow, уведомления и т.д.), зарегистрированные как OAuth2-клиенты: получение кодов авторизации и токенов (`/oauth2/authorize`, `/oauth2/token` и смежные точки по конфигурации Spring Authorization Server).
- Любой клиент с **JWT доступа**, выданным этим сервисом, для вызовов защищённых маршрутов (`Authorization: Bearer …`).

Точный список redirect URI и клиентов задаётся в `application.yaml` / `AuthorizationServerConfig` и в конфигурации каждого потребляющего приложения.

### Исходящие HTTP-вызовы: сервис **cms-company-info**

Базовый URL: `integration.cms-company-info.base-url` (`CMS_COMPANY_INFO_BASE_URL`; в Docker профиле по умолчанию `http://cms-company-info:9092`).

Клиент в коде: `CmsCompanyInfoClient` поверх Spring `RestClient` (`RestClientConfig`).

| Метод и путь (относительно base-url) | Назначение | Аутентификация и контекст |
|-------------------------------------|------------|---------------------------|
| `GET /employee/id` | Получить идентификатор сотрудника для текущего пользователя по access token | Заголовок `Authorization: Bearer <access_token>`, дополнительно может передаваться `X-User-Id`, извлечённый из JWT (`userId` / `user_id`). Ответ трактуется как строка или JSON с полями `employeeId` / `id`. |
| `GET /employee/{userId}` | Загрузить данные сотрудника по ID пользователя | `Authorization` с Bearer-токеном вызывающей стороны. |
| `GET /company/id/{userId}` | Узнать `companyId` пользователя во внешней системе компаний | `Authorization` (как правило Bearer). Ответ — строка или JSON с полями `companyId` / `id`. Используется для **проверки принадлежности к компании** (например, смена статуса пользователя, проверки прав) и для согласования контекста с CMS. |
| `GET /companies/{companyId}/employees` | Список сотрудников компании | Bearer вызывающего пользователя. Ответ десериализуется как JSON-массив объектов **`CompanyEmployeeResponseDto`**: `id`, `email`, `firstName`, `lastName`, `role`, `companyId`, `departmentId`, `employeeId`, `isFirstLogin` (поля см. в DTO в репозитории). При выборке пользователей компании (`GET /api/users`) этот список используется для **синхронизации** локальных пользователей с CMS (имя/фамилия, роль, при необходимости другие поля согласно `UserServiceImpl.syncUsersFromCompanyEmployees`). При ошибке HTTP при синхронизации запрос может завершиться ошибкой сервера. |

Таким образом, **cms-company-info** выступает источником правды для оргструктуры/сотрудников и связки user ↔ company там, где данные уже заведены в CMS; auth-хранилище дополняется и сверяется при операциях вроде списка пользователей компании.

### Обмен сообщениями через Kafka

- **Исходящие:** топик создания компании (событие `CREATED`) — см. раздел **Kafka → Исходящие сообщения** ниже; подписчики могут создавать сущность компании в своих системах.
- **Входящие:** топик `auth_topic` (настраиваемое имя); ожидается JSON с типом **`ADD_USER_COMPANY`** для проставления `company_id` локальному пользователю. Продюсируют **другие** сервисы; auth-service только потребляет.

### Внутренний REST для локальных процессов

`GET /api/internal/users/{id}` возвращает пользователя как DTO для **межсервисных** сценариев. Доступ ограничен **loopback** (обращение считается доверенным только с локального адреса) — см. `InternalUserController.validateLocalRequest`. Другие контейнеры/хосты в общем случае этот эндпоинт использовать не смогут без изменения правил безопасности в коде.

## Kafka

Ниже — детали по топикам; кратко: сервис **публикует** событие создания компании в топик **`company`** (имя настраиваемое) и **подписан** на топик **`auth_topic`** для обновления `companyId` у пользователя.

### Исходящие сообщения (producer)

Сервис **пишет** в **один** топик — событие создания компании при регистрации пользователя с ролью `EXECUTIVE`.

| Параметр | Значение |
|----------|----------|
| **Имя топика** | Задаётся свойством `app.kafka.topics.company`. По умолчанию: `company`. Переопределение: переменная окружения `KAFKA_TOPIC_COMPANY`. |
| **Ключ сообщения** | Строка UUID пользователя (`userId`), тот же идентификатор, что у созданного пользователя в БД. |
| **Значение (value)** | Тело — **строка JSON** (UTF-8). Сериализация: `StringSerializer` (не Avro/Schema Registry). |
| **Когда публикуется** | После успешного сохранения пользователя в `TokenServiceImpl` при регистрации, если выбрана роль `EXECUTIVE` и указано имя компании (`companyName`). Реализация: `CompanyEventPublisher.publishCompanyCreated`. |

#### Формат JSON (value)

Поле `name` и `role` подставляются в JSON вручную; для `name` и `role` выполняется экранирование спецсимволов (`\`, кавычки, переводы строк и т.д.) — см. `CompanyEventPublisher.escapeJson`.

Структура:

| Поле | Тип | Описание |
|------|-----|----------|
| `event` | строка | Всегда литерал `CREATED`. |
| `name` | строка | Название компании из запроса регистрации (`companyName`). |
| `userId` | строка | UUID создателя (пользователь с ролью `EXECUTIVE`) в стандартном строковом виде. |
| `role` | строка | Имя роли, переданное в публикацию — в коде это `roleType.name()` (например, `EXECUTIVE`). |

Пример **value** (без экранирования в `name`):

```json
{
  "event": "CREATED",
  "name": "Acme Corp",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "role": "EXECUTIVE"
}
```

#### Создание топика при старте

В `KafkaConfig` объявлен bean `NewTopic` для топика компаний (по умолчанию **3 партиции**, **1 replica** — для локальной/простой среды). Параметры могут быть применены брокером при автосоздании топиков; в продакшене топики часто создаются отдельно политикой инфраструктуры.

#### Связанные настройки

- `spring.kafka.bootstrap-servers` — адрес брокера (по умолчанию `localhost:9092`, в Docker см. `application-docker.yaml`).  
- Продюсер: ключ и значение — строки (`StringSerializer`).  

### Входящие сообщения (consumer)

Топик **`app.kafka.topics.auth`** (по умолчанию `auth_topic`, переменная `KAFKA_TOPIC_AUTH`) сервис **не записывает**; он только **читает** его (`AuthTopicListener`).

Поддерживаемый тип сообщения в value (JSON):

- `type`: `ADD_USER_COMPANY`  
- `userId`, `companyId`: строки UUID  

При получении такого сообщения у пользователя обновляется `companyId` в таблице `users`. Формат предназначен для внешних продюсеров, а не для ответов этого сервиса.

Группа consumer: `spring.kafka.consumer.group-id` (по умолчанию `auth-service`, переменная `KAFKA_CONSUMER_GROUP_ID`).

## Прочее

Подробные соглашения по стилю кода, паттернам тестов и типовым проблемам см. в **`AGENTS.md`** (ориентир для разработки и код-ревью).
