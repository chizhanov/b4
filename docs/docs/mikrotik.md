---
sidebar_position: 3
title: Установка на MikroTik
description: Запуск B4 в контейнере на MikroTik RouterOS 7.x
---

# Установка на MikroTik (RouterOS 7.x)

B4 можно запустить как контейнер прямо на маршрутизаторе MikroTik с поддержкой контейнеризации.

## Требования

- **Архитектура:** ARM64 или AMD64
- **RouterOS:** версия >= 7.21.1
- **Диск:** подключённый Flash/SSD/HDD, форматированный в Ext4

:::warning Внимание
Контейнеры на MikroTik требуют внешний накопитель — внутренней памяти роутера недостаточно.
:::

## Параметры примера

В этом руководстве используются следующие значения. Замените их на свои:

| Параметр              | Значение           |
| --------------------- | ------------------ |
| Сеть моста            | 192.168.210.0/24   |
| Шлюз моста            | 192.168.210.1      |
| Имя моста             | bridge-docker      |
| IP-адрес контейнера   | 192.168.210.10     |
| Имя интерфейса        | B4                 |
| Сеть LAN              | 192.168.100.0/24   |
| DNS-сервер            | 192.168.100.1      |
| Таблица маршрутизации | to_b4              |
| Диск                  | /usb1              |
| Список монтирования   | mount_b4           |
| Список клиентов       | b4users            |

## Шаг 1: Создание моста

Создайте мост для Docker-сети и назначьте ему IP-адрес:

```routeros
/interface/bridge add name=bridge-docker port-cost-mode=short

/ip/address add address=192.168.210.1/24 interface=bridge-docker network=192.168.210.0
```

## Шаг 2: Создание интерфейса

Создайте виртуальный Ethernet-интерфейс для контейнера и подключите его к мосту:

```routeros
/interface/veth add address=192.168.210.10/24 gateway=192.168.210.1 name=B4

/interface/bridge/port add bridge=bridge-docker interface=B4
```

## Шаг 3: Маршрутизация

Создайте отдельную таблицу маршрутизации и маршрут через контейнер:

```routeros
/routing table add disabled=no fib name=to_b4

/ip route add check-gateway=ping gateway=192.168.210.10 routing-table=to_b4
```

## Шаг 4: Маркировка трафика

Настройте правила mangle для перенаправления трафика клиентов из списка `b4users` через контейнер:

```routeros
/ip firewall mangle add chain=prerouting action=mark-connection \
    new-connection-mark=b4_connections passthrough=yes connection-state=new \
    dst-address-type=!local src-address-list=b4users in-interface-list=LAN \
    place-before=0

/ip firewall mangle add chain=prerouting action=mark-routing \
    new-routing-mark=to_b4 passthrough=no connection-mark=b4_connections \
    in-interface-list=LAN log=no place-before=1
```

:::caution Если включён FastTrack
FastTrack обходит правила mangle. Чтобы трафик B4-клиентов обрабатывался корректно, ограничьте FastTrack немаркированными соединениями:

```routeros
/ip firewall filter set [find action=fasttrack-connection] connection-mark=no-mark
```

:::

## Шаг 5: Точки монтирования

Создайте точки монтирования для данных контейнера:

```routeros
/container/mounts add name=b4_etc src=/usb1/docker/b4-mounts/etc dst=/opt/etc/b4
```

:::tip Совет
Убедитесь, что директории на диске созданы до запуска контейнера.
:::

## Шаг 6: Настройка и запуск контейнера

### Настройка реестра

```routeros
/container/config set registry-url=https://registry-1.docker.io tmpdir=/usb1/docker/pull
```

### Создание контейнера

```routeros
/container add remote-image=lavrushin/b4:latest interface=B4 \
    root-dir=/usb1/docker/b4-mikrotik mounts=mount_b4 \
    cmd="--config /opt/etc/b4/b4.json" start-on-boot=yes \
    logging=yes dns=192.168.100.1
```

### Запуск

После загрузки образа запустите контейнер:

```routeros
/container start [find tag~"b4"]
```

## Шаг 7: Добавление клиентов

Добавьте устройства, трафик которых должен проходить через B4, в адресный список `b4users`:

```routeros
/ip firewall address-list add list=b4users address=192.168.100.50
/ip firewall address-list add list=b4users address=192.168.100.51
```

## Обновление контейнера

Для обновления до последней версии:

```routeros
/container stop [find tag~"b4"]
/container remove [find tag~"b4"]
/container add remote-image=lavrushin/b4:latest interface=B4 \
    root-dir=/usb1/docker/b4-mikrotik mounts=mount_b4 \
    cmd="--config /opt/etc/b4/b4.json" start-on-boot=yes \
    logging=yes dns=192.168.100.1
```

:::info Данные сохраняются
Конфигурация B4 хранится на точке монтирования (`/usb1/docker/b4-mounts/etc`), поэтому при пересоздании контейнера настройки не теряются.
:::

## Веб-интерфейс

После запуска контейнера веб-интерфейс B4 будет доступен по адресу:

```text
http://192.168.210.10:7000
```

## Решение проблем

### Контейнер не запускается

1. Проверьте, что образ загружен: `/container print`
2. Проверьте логи: `/log print where topics~"container"`
3. Убедитесь, что диск смонтирован и отформатирован в Ext4

### Нет доступа к веб-интерфейсу

1. Проверьте, что контейнер запущен: `/container print`
2. Проверьте связность: `/ping 192.168.210.10`
3. Убедитесь, что firewall не блокирует трафик между мостом и LAN

### Трафик не перенаправляется

1. Проверьте, что устройство добавлено в список: `/ip firewall address-list print where list=b4users`
2. Проверьте правила mangle: `/ip firewall mangle print`
3. Проверьте маршрут: `/ip route print where routing-table=to_b4`
