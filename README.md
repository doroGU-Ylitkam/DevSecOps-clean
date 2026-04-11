# Прототип алгоритма-конвейера DevSecOps
Дипломная работа бакалавриата: Разработка метода автоматического обнаружения уязвимостей в процессе DevSecOps

---

## Структура каталога проекта

```
devsecops-clean/
│
├── Jenkinsfile                              # Основной файл проекта, в котором прописан алгоритм из 11 стадий по проверке кода
├── pom.xml                                  # Файл с зависимостями для проверяемого приложения
├── README.md
│
├── docker/
│   └── Dockerfile                           # Файл для Docker. На его основе формируется контейнер, в котором запускается тестируемое приложение
│
├── k8s/
│   ├── deployment.yaml                      # Файлы запуска тестовой среды
│   └── service.yaml                         
│
├── src/
│   └── test/java/com/example/vulnerable
│       └── VulnerableApplicationTest.java   # Код проекта, который тестируется на наличие уязвимостей
│   
│   
│ 
│
├── security/
│   ├── config/
│   │   └── scanner_config.yaml              # файл с конфигурацией для сканирования на наличие угроз
│   │
│   ├── orchestrator/
│   │   └── security_orchestrator.py         # [SCRIPT 1] Файл оркестрации: унифицирует выводы работы всех применяемых инструментов
│   │
│   ├── merger/
│   │   └── report_merger.py                 # [SCRIPT 2] Производит слияние всех отчетов в один, убирает дубликаты ошибок
│   │
│   ├── triage/
│   │   └── vulnerability_triage.py          # [SCRIPT 3] Производит триаж уязвимостей (распределение от критических к легким)
│   │
│   └── reporter/
│       └── report_generator.py              # [SCRIPT 4] Формирует из образованных с помощью security_orchestrator файлов отчеты в формате JSON и HTML
│
└── reports/                                 # Отчеты, которые воспроизводятся алгоритмом во время исполнения
    ├── sonarqube-report.json
    ├── dependency-check-normalized.json
    ├── trivy-normalized.json
    ├── zap-report.json
    ├── merged-vulnerabilities.json
    ├── triaged-vulnerabilities.json
    ├── final-vulnerability-report.json
    └── final-vulnerability-report.html
```

---

## Общая схема взаимодействия компонентов

```
ИСХОДНЫЙ КОД
    │
    ▼
[Стадия 1] Checkout (получение кода из репозитория) ─────────────────────
    │
    ▼
[Стадия 2] Сборка Maven (mvn clean package)
    │
    ▼
[Стадия 3] Модульные тесты + покрытие JaCoCo
    │
    ▼
[Стадия 4] SAST (статический анализ) ── SonarQube ──► security_orchestrator.py ──► sonarqube-report.json
    │                                    (получение через REST API + нормализация)
    ▼
[Стадия 5] SCA (анализ зависимостей) ── OWASP Dependency-Check ──► security_orchestrator.py ──► dep-check-normalized.json
    │                                    (парсинг сырого JSON + нормализация)
    ▼
[Стадия 6] Сборка Docker-образа ── сборка ${DOCKER_IMAGE}:${BUILD_NUMBER}
    │
    ▼
[Стадия 7] Сканирование контейнера ── Trivy ──► security_orchestrator.py ──► trivy-normalized.json
    │                                    (парсинг сырого JSON + нормализация)
    ▼
[Стадия 8] Развёртывание в тестовом пространстве имён Kubernetes
    │
    ▼
[Стадия 9] DAST (динамический анализ) ── OWASP ZAP ──► security_orchestrator.py ──► zap-report.json
    │                                    (обход сайта + активное сканирование + нормализация)
    ▼
[Стадия 10] Триаж (сортировка уязвимостей)
    │   report_merger.py
    │   ├── Загрузить все 4 нормализованных отчёта
    │   ├── Объединить в единый плоский список
    │   ├── Дедуплицировать (по CVE-ID или по сигнатуре "название + компонент")
    │   └── merged-vulnerabilities.json
    │
    │   vulnerability_triage.py
    │   ├── PriorityScore = CVSS + Exploitability + SystemImpact
    │   ├── Отсортировать по убыванию приоритета
    │   └── triaged-vulnerabilities.json
    │
    ▼
[Стадия 11] Формирование отчёта
    │   report_generator.py
    │   ├── final-vulnerability-report.json
    │   └── final-vulnerability-report.html  (публикуется в Jenkins)
    │
    ▼
  Jenkins: архивирование артефактов, публикация HTML, уведомление по email при ошибке
```

---

## Формула расчёта приоритета уязвимости

```
PriorityScore = CVSS_Score + Exploitability_Score + SystemImpact_Score
```

| Компонент | Диапазон | Описание |
|---|---|---|
| CVSS_Score | 0.0 – 10.0 | Базовая оценка NVD, полученная от сканера |
| Exploitability_Score | 0.0 – 5.0 | Основана на уровне опасности; +0.5 если подтверждено DAST; +0.5 если обнаружено несколькими сканерами |
| SystemImpact_Score | 1.0 – 3.0 | 3.0 для ZAP (живая система), 2.5 для SonarQube (исходный код), 2.0 для Trivy/DC (библиотеки) |

| Метка приоритета | Порог оценки | Действие со стороны команды разработки |
|---|---|---|
| 🔴 IMMEDIATE | ≥ 14.0 |Блокировать развёртывание, исправить сейчас |
| 🟠 HIGH | ≥ 9.0 |Исправить в текущем спринте |
| 🟡 MEDIUM | ≥ 5.0 | Запланировать на следующий релиз |
| 🟢 LOW | < 5.0 | 	Отслеживать в бэклоге |

---

## Сводка по инструментам безопасности

| Инструмент | Тип | Стадия | Результат |
|---|---|---|---|
| SonarQube | SAST (статический анализ) | 4 | Уязвимости в коде и «горячие точки» |
| OWASP Dependency-Check | SCA (анализ зависимостей) | 5 | CVE в сторонних библиотеках |
| Trivy | Сканирование контейнеров | 7 | CVE в ОС и библиотеках внутри Docker-образа |
| OWASP ZAP | 	DAST (динамический анализ) | 9 | Атаки на HTTP-поверхность работающего приложения |
