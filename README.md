# практическое задание 10
## Шишков А.Д. ЭФМО-02-25
## Тема
JWT-аутентификация: создание и проверка токенов. Middleware для авторизации
## Цели
- Понять устройство JWT и где его уместно применять в REST API. 
- Сгенерировать и проверить JWT в Go (HS256), передавать его в Authorization: Bearer …. 
- Реализовать middleware-аутентификацию (достаёт токен, валидирует, кладёт клеймы в context). 
- Добавить middleware-авторизацию (RBAC/права на эндпоинты). 
- Встроить это в уже знакомую архитектуру HTTP-сервиса/роутера.

## Описание проекта
В рамках практического задания была разработана серверная REST-система аутентификации и авторизации на Go с использованием библиотеки chi и механизма JWT-токенов. Реализован полный цикл обработки пользователей: выдача access- и refresh-токенов, обновление пары токенов, а также проверка их валидности. Доступ ко всем защищённым маршрутам осуществляется через middleware уровня AuthN (проверка JWT) и AuthZ (RBAC по ролям admin/user). Дополнительно реализован механизм ABAC-контроля: пользователь с ролью user может просматривать только собственный профиль.

Refresh-токены защищены через встроенный blacklist, предотвращающий их повторное использование. Пользователи хранятся в in-memory репозитории, с паролями, защищёнными хэшированием bcrypt. Проект развёрнут на удалённом сервере Ubuntu и доступен извне на порту 8080. Полностью подготовлена коллекция Postman и набор curl-команд для демонстрации работы всех маршрутов: /login, /me, /admin/stats, /users/{id}, /refresh. 

## Структура проекта 

<img width="371" height="890" alt="изображение" src="https://github.com/user-attachments/assets/29a2d0d5-1978-4023-8559-cc779ecbfd2a" /> 

### Запуск проекта
1. Склонировать репозиторий и перейти в папку проекта:
   ```bash
   git clone https://github.com/Alex171228/Pz10
   cd pz9
    ```
3. Создать файл .env:
      ```bash
   cp .env.example .env
    ```
   Откройте и заполните его:
   ```bash
   JWT_SECRET=supersecretkey123
   JWT_ACCESS_TTL=15m
   JWT_REFRESH_TTL=168h
   ```
   JWT_SECRET — ключ подписи токенов (обязателен) 
   JWT_ACCESS_TTL — срок жизни access токена 
   JWT_REFRESH_TTL — срок жизни refresh токена 
4. Установите зависимости
   ```bash
   go mod tidy
   ```
5. Запуск приложения
   ```bash
   go run ./cmd/server
   ```
### Примеры запросов и результат их выполнения 
1. Успешный /login (токен) 

   <img width="1251" height="632" alt="изображение" src="https://github.com/user-attachments/assets/c0f43c0e-a890-4966-ad1d-bbb14afbec05" />
   <img width="1242" height="755" alt="изображение" src="https://github.com/user-attachments/assets/86e6c0ee-7678-4525-aa20-5ca14e66c632" /> 

3. /me и /admin/stats для admin 

   <img width="829" height="615" alt="изображение" src="https://github.com/user-attachments/assets/b26c36e3-a453-4fc4-a2ee-8cf4fb8fde2c" /> 

  <img width="855" height="591" alt="изображение" src="https://github.com/user-attachments/assets/dfa3a37d-2457-4b16-a1ec-1bfbada1684a" /> 

3. 403 для user на /admin/stats
   
   <img width="785" height="543" alt="изображение" src="https://github.com/user-attachments/assets/bfd6ba3d-9bc8-4795-b59f-a6a2fb67eadf" /> 

4. refresh-флоу (старый/новый access)
   
   <img width="1253" height="745" alt="изображение" src="https://github.com/user-attachments/assets/befab74f-2163-41de-ad27-50e900bda02e" />

Для выполнения запросов приложен json для Postman https://github.com/Alex171228/pz10/blob/main/pz10-auth-postman.json
