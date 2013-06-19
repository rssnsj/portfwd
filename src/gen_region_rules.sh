#!/bin/sh -e

[ -f delegated-apnic-latest  ] || wget http://ftp.apnic.net/stats/apnic/delegated-apnic-latest -O delegated-apnic-latest
(
	cat delegated-apnic-latest | awk -F'|' '$2=="CN"&&$3=="ipv4"{printf "%s:+%s\n", $4, $5-1}' | xargs -n1 netmask -r | awk '{printf "%s = none\n", $1}'
	cat delegated-apnic-latest | awk -F'|' '$2=="TW"&&$3=="ipv4"{printf "%s:+%s\n", $4, $5-1}' | xargs -n1 netmask -r | awk '{printf "%s = 127.0.0.1:1080\n", $1}'
) > __config_tmp

rule_items=`cat __config_tmp | wc -l`

echo "Adding /etc/socksnatd.conf.basic and $rule_items generated items to /etc/socksnatd.conf"

cat /etc/socksnatd.conf.basic __config_tmp > /etc/socksnatd.conf
rm -f __config_tmp

# Countries' IP amount
# cat delegated-apnic-latest | awk -F'|' 'BEGIN{c=0} $2=="CN"&&$3=="ipv4"{c+=$5} END{print c}'
