#!/bin/sh -e

prefix=.
download_url="http://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
tmpfile="delegated-apnic-latest"

[ -f $tmpfile  ] || wget "$download_url" -O $tmpfile

(
	echo "# Data from: $download_url"
	echo -n "# Date: "; date -u
	echo ""
	
	for country_proxy in CN=none TW=127.0.0.1:1080; do
		country=`echo "$country_proxy" | awk -F= '{print $1}'`
		proxy=`echo "$country_proxy" | awk -F= '{print $2}'`
		echo "# ==== Contry: $country, proxy: $proxy ===="
		awk -F'|' -vc="$country" '$2==c&&$3=="ipv4"{printf "%s:+%s\n", $4, $5-1}' $tmpfile |
			xargs -n1 netmask -r | awk -vp="$proxy" '{printf "%s = %s\n", $1, p}'
		echo ""
	done
) > __config_tmp

rule_items=`cat __config_tmp | wc -l`

echo "Adding $prefix/socksnatd.conf.basic and $rule_items generated items to $prefix/socksnatd.conf"

cat $prefix/socksnatd.conf.basic __config_tmp > $prefix/socksnatd.conf
rm -f __config_tmp

# Country IP amount
# cat delegated-apnic-latest | awk -F'|' 'BEGIN{c=0} $2=="CN"&&$3=="ipv4"{c+=$5} END{print c}'

