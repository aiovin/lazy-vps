# lazy vps setup
Bash script for basic VPS setup using Ansible.<br><br>
Just run on a newly created VPS:
```
bash <(curl -Ls https://raw.githubusercontent.com/aiovin/lazy-vps/refs/heads/main/setup.sh)
```
For **systemd-based systems** (tested on Ubuntu 22.04, 24.04 and Debian 12).

### What it does:
- System update and dependencies installation
- Creation of a new user with sudo privileges
- Basic SSH and UFW setup (allow SSH key only, changing SSH port, root login disabled, limit connection attempts, block all ports except SSH)
- Timezone and hostname configuration
- Adds useful shell aliases (`cls` for clearing the terminal and `act` for activating Python virtual environments)
- Set the congestion control algorithm to BBR
- Optional ntfy.sh notifications (server startup and disk space alerts)
- Generates ready-to-use SSH connection command

### What exactly it does:
After running the cript, it will first update your system and install Ansible along with necessary dependencies. Then it will guide you through entering required configuration details such as new user credentials, SSH port, timezone, and other settings. After that Ansible will perform the server setup using provided parameters. At the end, the script will verify the changes made and display your new SSH connection command with all the updated settings.

### Installed packages:
In addition to Ansible, the following will be installed: python3-pip, python3-venv, and neofetch. All other necessary utilities are typically pre-installed in modern distributions.
No additional or unnecessary packages beyond these will be installed.

---

<p align="center">
  <img src="https://raw.githubusercontent.com/aiovin/lazy-vps/main/script_finish.png" width="75%">
  <br><i>Script finish</i>
</p>

> [!NOTE]
> *Most likely, the whole script could've been done more easily just in bash, but I just felt like trying out Ansible for fun, so no complaints about the approach.*

---

# lazy vps setup (rus)

Bash скрипт для базовой настройки чистого VPS при помощи Ansible.<br><br>
Для **систем на основе systemd** (протестировано на Ubuntu 22.04, 24.04 и Debian 12).

### Что делает скрипт:
- Обновление системы и установка зависимостей
- Создание нового пользователя с правами sudo
- Базовая настройка SSH и UFW (вход только по SSH-ключам, изменение порта SSH, отключение входа для root, ограничение попыток подключения и закрытие всех портов кроме SSH)
- Установку временной зоны и имени хоста
- Добавление полезных алиасов (`cls`/`сды` для очистки терминала и `act` для активации виртуального окружения Python)
- Установка алгоритма управления перегрузкой на BBR
- Опциональные уведомления через ntfy.sh (старт сервера и контроль дискового пространства)
- Генерацию готовой команды для SSH-подключения

### Что именно он делает?
После запуска скрипта, он сначала обновит вашу систему и установит Ansible вместе с необходимыми зависимостями. Затем он предложит вам ввести требуемые параметры настройки, такие как учетные данные нового пользователя, порт SSH, временная зона и другие настройки. После чего Ansible выполнит настройку сервера с использованием предоставленных параметров. В конце работы скрипт проверит сделанные изменения и выведет команду для SSH-подключения с учетом всех новых настроек.

### Устанавливаемые пакеты:
Кроме Ansible будут установлены python3-pip, python3-venv, neofetch. Все остальные необходимые утилиты обычно предустановлены в современных дистрибутивах.
Никаких дополнительных или ненужных пакетов помимо этих установлено не будет.

> [!NOTE]
> *Скорее всего, весь скрипт можно было бы сделать проще и легче, используя только bash, но мне хотелось попробовать Ansible ради интереса, так что без претензий к подходу.*
