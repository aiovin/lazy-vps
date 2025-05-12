# lazy vps setup
Bash script for basic and secure VPS setup.<br><br>
Just run on a newly created VPS:
```
bash -c "$(curl -Ls https://raw.githubusercontent.com/aiovin/lazy-vps/refs/heads/main/setup-ba.sh)"
```
For **systemd-based systems** (tested on Ubuntu 22.04, 24.04 and Debian 11, 12).

### What it does:
- System update.
- Creation of a new user with sudo privileges.
- Basic SSH and UFW setup (allow SSH key only, changing SSH port, root login disabled, limit connection attempts, block all ports except SSH).
- Timezone and hostname configuration.
- Adds useful shell aliases (`cls` for clearing the terminal, `act` for activating Python virtual environments and `x` for the `exit` and more).
- Set the congestion control algorithm to BBR.
- Optional ntfy.sh notifications (server startup and disk space alerts).
- Generates ready-to-use SSH connection command.

### What exactly it does:
After running the cript, it will first update your system, then it will guide you through entering required configuration details such as new user credentials, SSH port, timezone, and other settings. After that script will perform the server setup using provided parameters. At the end, the script will verify the changes made and display your new SSH connection command with all the updated settings.

### Installed packages:
Will be instaled: sudo, nano, ufw, curl, htop, gzip, logrotate, bash-completion, neofetch. Most of them are typically pre-installed in modern distributions.
No additional or unnecessary packages beyond these will be installed.

---

<p align="center">
  <img src="https://raw.githubusercontent.com/aiovin/lazy-vps/main/script_finish.png" width="75%">
  <br><i>Script finish</i>
</p>

---

# lazy vps setup (rus)

Bash скрипт для базовой настройки чистого VPS.<br><br>
Для **систем на основе systemd** (протестировано на Ubuntu 22.04, 24.04 и Debian 11, 12).

### Что делает скрипт:
- Обновление системы.
- Создание нового пользователя с правами sudo.
- Базовая настройка SSH и UFW (вход только по SSH-ключам, изменение порта SSH, отключение входа для root, ограничение попыток подключения и закрытие всех портов кроме SSH).
- Установку временной зоны и имени хоста.
- Добавление полезных алиасов (`cls`/`сды` для очистки терминала, `act` для активации виртуального окружения Python и `x` для `exit` и другие).
- Установка алгоритма управления перегрузкой на BBR.
- Опциональные уведомления через ntfy.sh (старт сервера и контроль дискового пространства).
- Генерацию готовой команды для SSH-подключения.

### Что именно он делает?
После запуска скрипта, он обновит вашу систему pатем он предложит вам ввести требуемые параметры настройки, такие как учетные данные нового пользователя, порт SSH, временная зона и другие настройки. После чего скрипт выполнит настройку сервера с использованием предоставленных параметров. В конце работы скрипт проверит сделанные изменения и выведет команду для SSH-подключения с учетом всех новых настроек.

### Устанавливаемые пакеты:
Будет установлено: sudo, nano, ufw, curl, htop, gzip, logrotate, bash-completion, neofetch. Большинство этих утилит обычно предустановлены в современных дистрибутивах.
Никаких дополнительных или ненужных пакетов помимо этих установлено не будет.
