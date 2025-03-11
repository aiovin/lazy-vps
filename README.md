# lazy vps setup
Automate basic VPS setup with Ansible.<br><br>
Just run:
```
bash <(curl -Ls https://raw.githubusercontent.com/aiovin/lazy-vps/refs/heads/main/setup.sh)
```
For **systemd-based systems** (tested on Ubuntu 24.04 and Debian 12).

### What it does:
- System update and dependencies installation
- Creation of a new user with sudo privileges
- Secure SSH configuration (key-based auth, custom port, root login disabled)
- UFW setup
- Timezone and hostname configuration
- Adds useful shell aliases (`cls` for clearing the terminal and `act` for activating Python virtual environments)
- Set the congestion control algorithm to BBR
- Optional ntfy.sh notifications (server startup and disk space alerts)
- Generates ready-to-use SSH connection command

---

# lazy vps setup (rus)

Скрипт для автоматизации базовой настройки VPS с использованием Ansible.  
Для **систем на основе systemd** (протестировано на Ubuntu 24.04 и Debian 12).

### Что делает скрипт:
- Обновление системы и установка зависимостей
- Создание нового пользователя с правами sudo
- Настройку SSH (аутентификация по ключам, смена порта, отключение root-доступа)
- Настройку UFW
- Установку временной зоны и имени хоста
- Добавление полезных алиасов (`cls`/`сды` для очистки терминала и `act` для активации виртуального окружения Python)
- Установка алгоритма управления перегрузкой на BBR
- Опциональные уведомления через ntfy.sh (старт сервера и контроль дискового пространства)
- Генерацию готовой команды для SSH-подключения
