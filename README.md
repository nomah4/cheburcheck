# ![Cheburcheck Logo](website/static/favicon.svg) Cheburcheck.ru

[Cheburcheck.ru](https://cheburcheck.ru) — open-source сервис для проверки доменов и IP-адресов на наличие в списках блокировок Роскомнадзора и популярных заблокированных CDN-провайдеров.

---

## О проекте

Этот сервис реализован на языке Rust с использованием веб-фреймворка [Rocket.rs](https://rocket.rs/). Основная задача — проверять, заблокирован ли домен или IP-адрес, основываясь на актуальных данных из реестров Роскомнадзора и других источниках.

---

## Технологии

- **Rust** — язык программирования, на котором написан весь бекенд.  
- **Rocket.rs** — веб-фреймворк для построения HTTP API и серверной логики.  
- **DoH резолвер Quad9** — для разрешения DNS-запросов используется DNS-over-HTTPS, что позволяет обойти локальные ограничения и получать актуальные данные.  
- **Tera** — шаблонизатор для генерации HTML страниц, используется для фронтенда.  
- **lucide** — библиотека иконок, применяемая для визуального оформления интерфейса.  

---

## Как это работает

1. Пользователь вводит домен или IP-адрес в форму на сайте.  
2. Сервер выполняет DNS-запрос через Quad9 DoH для получения актуальной информации.  
3. Полученный домен/IP проверяется на наличие в блокировочных списках через префиксные деревья.
4. Результат формируется с помощью Tera и отображается пользователю.  

---

## Списки

Для проверки используются списки [123jjck/cdn-ip-ranges](https://github.com/123jjck/cdn-ip-ranges), [antifilter.download](https://antifilter.download/) и [antifilter.network](https://antifilter.network).

Мы собираем собственные белые списки с помощью [Cheburcheck Reporter](reporter/README.md).

---

## Структура проекта

* `querying` — модуль проверки сайтов по базам данных
* `reporter` — [Cheburcheck Reporter](reporter/README.md)
* `reports` — общий протокол для отправки отчетов
* `website` — исходный код веб-сайта

## Разработка и проверка

Требуются Rust/Cargo, PostgreSQL и переменная `DATABASE_URL`. Из корня workspace:

```bash
cargo build --workspace
cargo test --workspace
DATABASE_URL=postgresql://USER:PASSWORD@localhost/cheburcheck cargo run -p website
```

Дополнительные параметры подключения задаются через стандартные переменные Rocket. `API_RATE_LIMIT_RPM` управляет лимитом запросов JSON API.

## JSON API

Проверка доступна по `GET /api/v1/check?target=example.org`. `target` может быть доменом или IP-адресом. Успешный ответ содержит исходную цель, тип, итоговый признак `blocked`, найденные IP/подсети, сведения CDN, GeoIP/ASN и данные белого списка, если они есть.

```bash
curl --get 'http://localhost:8000/api/v1/check' \
  --data-urlencode 'target=example.org'
```

API возвращает `404`, если цель не найдена, `429` при превышении лимита и `500` при внутренней ошибке.

---

## Вклад

Если хотите помочь с разработкой — открывайте issue или присылайте pull requests.
Если хотите помочь финансово:
- TON: `UQAACsiwpGryjP-kqp4TJPAWpXytuB6M_puuO0Cg5zNvaSJW`

---

## Контакты

Для вопросов и обсуждений можно написать на [support@cheburcheck.ru](mailto:support@cheburcheck.ru).
