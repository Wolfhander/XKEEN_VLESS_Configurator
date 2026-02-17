# XKEEN_VLESS_Configurator
Configurator for xkeen with multiple vless (outbounds, routing with balancer, observatory)

Создаёт файлы 04_outbounds.json, 05_routing.json, 06_observatory.json
Проверяет, что 06 файл это observatory. В частном случае там был 06_policy.json, который предлагает переименовать в 10_policy.json с подсказкой как это сделать.

Предлагает добавить существующий файл 05_routing.json
Это необходимо, если там есть добавленные вручную доменные имена и ip-адреса.
При добавлении старого 05_routing.json все "ручные" правила будут перенесены в новый файл.

Инструкция: 
1) Запустите исправленную программу
2) Добавьте ваши прокси (Tag - название прокси (для каждого прокси должно быть уникальным в одном файле), VLESS URL - ваш vless)
3) Загрузите существующий routing.json (ваш старый файл с ручными правилами)
4) Сгенерируйте файлы в папку /opt/etc/xray/configs/
