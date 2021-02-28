#!/bin/bash

NOW_PID=$$
HOME_DIR=/etc/ssmanager
URL="https://github.com/yiguihai/shadowsocks_install/raw/dev"
export PATH=${PATH}:${HOME_DIR}/usr/bin:${HOME_DIR}/usr/sbin:${PWD}

Binary_file_list=(
	sslocal
	ssserver
	ssurl
	ssmanager
	obfs-server
	kcptun-server
	simple-tls
	v2ray-plugin
	ss-tool
	ss-main
	qrencode
)

Encryption_method_list=(
	plain
	none
	aes-128-gcm
	aes-256-gcm
	chacha20-ietf-poly1305
)

Query_URL_list=(
	ipv4.icanhazip.com
	ipinfo.io/ip
	ifconfig.me
	api.ipify.org
)

Generate_random_numbers() (
	min=$1
	max=$(($2 - min + 1))
	num=$((RANDOM + 1000000000)) #增加一个10位的数再求余
	echo -n $((num % max + min))
)

Introduction() (
	cat >&1 <<-EOF

		$1

	EOF
)

Prompt() (
	cat >&1 <<-EOF

		---------------------------
		$1
		---------------------------

	EOF
)

# 判断命令是否存在
command_exists() {
	#type -P $@
	command -v "$@" >/dev/null 2>&1
}

# 判断输入内容是否为数字
is_number() {
	expr "$1" + 1 >/dev/null 2>&1
}

# 按任意键继续
Press_any_key_to_continue() {
	read -n 1 -r -s -p $'请按任意键继续或 Ctrl + C 退出\n'
}

Curl_get_files() {
	if ! curl -L -s -q --retry 5 --retry-delay 10 --retry-max-time 60 --output $1 $2; then
		Prompt "下载 $1 文件时失败！"
		rm -f $1
		Exit
	fi
}

Wget_get_files() {
	if ! wget --no-check-certificate -q -c -t2 -T8 -O $1 $2; then
		Prompt "下载 $1 文件时失败！"
		rm -f $1
		Exit
	fi
}

Url_encode_pipe() {
	local LANG=C
	local c
	while IFS= read -r c; do
		case $c in [a-zA-Z0-9.~_-])
			printf "$c"
			continue
			;;
		esac
		printf "$c" | od -An -tx1 | tr ' ' % | tr -d '\n'
	done <<EOF
$(fold -w1)
EOF
}

Url_encode() (
	printf "$*" | Url_encode_pipe
)

#https://stackoverflow.com/questions/238073/how-to-add-a-progress-bar-to-a-shell-script
Progress_Bar() {
	let _progress=(${1} * 100 / ${2} * 100)/100
	let _done=(_progress * 4)/10
	let _left=40-_done

	_fill=$(printf "%${_done}s")
	_empty=$(printf "%${_left}s")

	local run
	if [ "$3" ]; then
		[ ${#3} -gt 15 ] && run="${3:0:15}..." || run=$3
	else
		run='Progress'
	fi

	printf "\r${run} : [${_fill// /#}${_empty// /-}] ${_progress}%%"
	[ ${_progress:-100} -eq 100 ] && echo
}

Address_lookup() {
	unset -v ipv4 addr
	local cur_time last_time
	ipv4=$(ip -4 -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
	if [ ! -s /tmp/myaddr ]; then
		addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://myip.ipip.net)
		addr=${addr##*\来\自\于}
		addr=${addr:1}
		if [[ $addr == *"台湾"* ]]; then
			addr=${addr/中国/中华民国}
			addr=${addr/台湾省/台湾}
		fi
		[ "$addr" ] && echo $addr >/tmp/myaddr
	else
		addr=$(</tmp/myaddr)
		cur_time=$(date +%s)
		last_time=$(date -r /tmp/myaddr +%s)
		#一天后删除重新获取地址
		if [ $((cur_time - last_time)) -gt 86400 ]; then
			rm -f /tmp/myaddr
		fi
	fi
	if [ -z "$ipv4" ]; then
		for i in ${Query_URL_list[@]}; do
			ipv4=$(wget -qO- -t1 -T2 $i)
			[ "$ipv4" ] && break
		done
	fi
	if [ -z "$addr" ]; then
		Prompt "获取归属地位置失败！"
		Exit
	fi
	if [ -z "$ipv4" ]; then
		Prompt "获取IP地址失败！"
		Exit
	fi
}

Parsing_User() {
	unset -v server_port password method plugin plugin_opts total
	IFS='|'
	for l in $1; do
		case ${l%^*} in
		server_port)
			server_port=${l#*^}
			;;
		password)
			password=${l#*^}
			;;
		method)
			method=${l#*^}
			;;
		plugin)
			plugin=${l#*^}
			;;
		plugin_opts)
			plugin_opts=${l#*^}
			;;
		total)
			total=${l#*^}
			;;
		esac
	done
}

Parsing_plugin_opts() (
	if [ "$1" -a "$2" ]; then
		IFS=';'
		for l in $1; do
			if [ "${l%=*}" = "$2" ]; then
				echo -n ${l#*=}
			fi
		done
	fi
)

Used_traffic() (
	a=$(ss-tool /dev/shm/ss-manager.socket ping 2>/dev/null)
	b=${a#stat:\ \{}
	c=${b%\}}
	IFS=','
	for i in ${c//\"/}; do
		IFS=' '
		for j in $i; do
			if [ "${j%\:*}" = "$1" ]; then
				is_number ${j#*\:} && echo -n ${j#*\:}
			fi
		done
	done
)

Create_certificate() {
	unset -v tls_common_name tls_key tls_cert
	tls_key=$HOME_DIR/ssl/server.key
	tls_cert=$HOME_DIR/ssl/server.cer
	until [ -s $tls_key -o -s $tls_cert ]; do
		if [ "$(netstat -ln | grep LISTEN | grep ":80 ")" ]; then
			Prompt "80端口被其它进程占用！"
			Exit
		fi
		Introduction "请输入域名以申请证书为空则使用自签证书。(申请证书次数有限制)"
		read -p "(默认: lucky.me): " tls_common_name
		if [ "$tls_common_name" ]; then
			if [ -x ${HOME}/.acme.sh/acme.sh ]; then
				${HOME}/.acme.sh/acme.sh --upgrade
			else
				wget --no-check-certificate -O - https://get.acme.sh | sh
			fi
			if ${HOME}/.acme.sh/acme.sh --issue --domain $tls_common_name --standalone -k ec-256 --test --force; then
				if ${HOME}/.acme.sh/acme.sh --issue --domain $tls_common_name --standalone -k ec-256 --force --listen-v4; then
					if ${HOME}/.acme.sh/acme.sh --install-cert --domain $tls_common_name --cert-file ${tls_cert} --key-file ${tls_key} --ca-file ${HOME_DIR}/ssl/ca.cer --fullchain-file ${HOME_DIR}/ssl/fullchain.cer --ecc --force --listen-v4; then
						echo "$tls_common_name" >${HOME_DIR}/ssl/my_host
						Prompt "$tls_common_name"
					else
						Prompt "安装证书失败！"
						Exit
					fi
				else
					Prompt "签发证书失败!"
					Exit
				fi
			else
				Prompt "预签测试失败!"
				Exit
			fi
		else
			tls_common_name='lucky.me'
			simple-tls -gen-cert -n $tls_common_name -key $tls_key -cert $tls_cert
			echo "$tls_common_name" >${HOME_DIR}/ssl/my_host
		fi
	done
	if [ ! -s $tls_key -o ! -s $tls_cert ]; then
		Prompt "无法找到证书文件! "
		Exit
	fi
	tls_common_name=$(<${HOME_DIR}/ssl/my_host)
	[ -z "$tls_common_name" ] && Exit
}

Check() {
	if [ ${UID:=65534} -ne 0 ]; then
		Prompt "You must run this script as root!"
		Exit
	fi
	if command_exists apt; then
		common_install='apt install -y --no-install-recommends'
		common_remove='apt purge -y --auto-remove'
	elif command_exists dnf; then
		common_install='dnf install -y'
		common_remove='dnf remove -y'
	elif command_exists yum; then
		common_install='yum install -y'
		common_remove='yum remove -y'
	elif command_exists zypper; then
		common_install='zypper install -y --no-recommends'
		common_remove='zypper remove -yu'
	elif command_exists pacman; then
		common_install='pacman -Syu --noconfirm'
		common_remove='pacman -Rsun --noconfirm'
	else
		Prompt "The script does not support the package manager in this operating system."
		Exit
	fi
	local package_list=(wget netstat pkill socat)
	for i in ${package_list[@]}; do
		if ! command_exists $i; then
			case $i in
			netstat)
				$common_install net-tools
				;;
			pkill)
				$common_install psmisc
				;;
			shasum)
				$common_install libdigest-sha-perl
				;;
			*)
				$common_install $i
				;;
			esac
		fi
	done
	if [ ! -d $HOME_DIR ]; then
		mkdir -p $HOME_DIR || Exit
	fi
	for i in conf usr ssl web; do
		if [ ! -d $HOME_DIR/$i ]; then
			mkdir -p $HOME_DIR/$i || Exit
		fi
	done
	for i in bin conf etc html lib php sbin fastcgi_temp client_body_temp; do
		if [ ! -d $HOME_DIR/usr/$i ]; then
			mkdir -p $HOME_DIR/usr/$i || Exit
		fi
	done
	if command_exists systemctl; then
		if [ ! -s /etc/systemd/system/ss-main.service ]; then
			Wget_get_files /etc/systemd/system/ss-main.service $URL/init.d/ss-main.service
			chmod 0644 /etc/systemd/system/ss-main.service
			systemctl enable ss-main.service
			systemctl daemon-reload
			systemctl reset-failed
		fi
	else
		echo -e "\033[31m缺少systemctl支持!\033[0m"
		Uninstall
	fi
	local i=0
	for x in ${Binary_file_list[@]}; do
		((i++))
		if [[ ! -f $HOME_DIR/usr/bin/$x || ! -x $HOME_DIR/usr/bin/$x ]]; then
			Wget_get_files $HOME_DIR/usr/bin/$x $URL/usr/bin/$x
			chmod +x $HOME_DIR/usr/bin/$x
			Progress_Bar $i ${#Binary_file_list[@]}
		fi
		if [ "$x" = "ss-main" -a ! -h /usr/local/bin/$x ]; then
			rm -f /usr/local/bin/$x
			ln -s $HOME_DIR/usr/bin/$x /usr/local/bin/$x
		fi
	done
}

Author() {
	echo -e "=========== \033[1mShadowsocks-rust\033[0m 多端口管理脚本 by \033[$(Generate_random_numbers 1 7);$(Generate_random_numbers 30 37);$(Generate_random_numbers 40 47)m爱翻墙的红杏\033[0m ==========="
	#for i in {1..7} ; do
	#for j in {30..37}; do
	#for k in {40..47}; do
	#echo -e "=========== \033[1mShadowsocks-rust\033[0m 多端口管理脚本 by \033[${i};${j};${k}m爱翻墙的红杏\033[0m =========== $i $j $k";
	#done
	#done
	#done
}

Status() {
	echo -e "服务状态: \c"
	local ssm dae
	if [ -s /run/ss-manager.pid ]; then
		read ssm </run/ss-manager.pid
	fi
	if [ -d /proc/${ssm:=ss-manager} ]; then
		if [ -s /run/ss-daemon.pid ]; then
			read dae </run/ss-daemon.pid
		fi
		if [ -d /proc/${dae:=ss-daemon} ]; then
			echo -e "\033[7;32;107m运行中\033[0m"
			runing=true
		else
			echo -e "\033[7;31;43m守护脚本未运行\033[0m"
			Stop
		fi
	else
		if [[ "$(ssmanager -V)" == "shadowsocks"* ]]; then
			echo -e "\033[7;31;43m未运行\033[0m"
			runing=false
		else
			echo -e "\033[7;31;43m系统平台版本不兼容\033[0m"
			Uninstall
		fi
	fi
}

Obfs_plugin() {
	unset -v obfs
	Introduction "请选择流量混淆方式"
	local obfs_rust=(http tls)
	select obfs in ${obfs_rust[@]}; do
		if [ "$obfs" ]; then
			Prompt "$obfs"
			break
		fi
	done
}

Tls_plugin() {
	Create_certificate

	unset -v tls_pd
	Introduction "启用填充数据模式，服务端会发送填充数据来对抗流量分析。"
	select tls_pd in true false; do
		if [ "$tls_pd" ]; then
			Prompt "$tls_pd"
			break
		fi
	done
}

V2ray_plugin() {
	Create_certificate

	unset -v v2ray_mode
	Introduction "请选择传输模式"
	local mode_list=(websocket-http websocket-tls quic-tls)
	select v2ray_mode in ${mode_list[@]}; do
		if [ "$v2ray_mode" ]; then
			Prompt "$v2ray_mode"
			break
		fi
	done

	unset -v v2ray_path
	if [ "$v2ray_mode" != "quic-tls" ]; then
		until [ $v2ray_path ]; do
			local v2ray_paths=($(shasum -a1 /proc/sys/kernel/random/uuid))
			Introduction "请输入一个监听路径(path)"
			read -p "(默认: ${v2ray_paths}): " v2ray_path
			[ -z "$v2ray_path" ] && v2ray_path=${v2ray_paths}
			#[ "${v2ray_path:0:1}" != "/" ] && v2ray_path="/$v2ray_path"
			Prompt "$v2ray_path"
		done
	fi
}

Kcptun_plugin() {
	Introduction "key"
	unset -v kcp_key
	read kcp_key
	[ -z "$kcp_key" ] && kcp_key="$password"
	[ -z "$kcp_key" ] && kcp_key="it's a secrect"
	Prompt "$kcp_key"

	unset -v kcp_crypt
	Introduction "crypt"
	local crypt_list=(aes aes-128 aes-192 salsa20 blowfish twofish cast5 3des tea xtea xor sm4 none)
	select kcp_crypt in ${crypt_list[@]}; do
		if [ "$kcp_crypt" ]; then
			Prompt "$kcp_crypt"
			break
		fi
	done

	unset -v kcp_mode
	Introduction "mode"
	local mode_list=(fast3 fast2 fast normal manual)
	select kcp_mode in ${mode_list[@]}; do
		if [ "$kcp_mode" ]; then
			Prompt "$kcp_mode"
			break
		fi
	done

	unset -v kcp_mtu
	Introduction "mtu"
	read -p "(默认: 1350): " kcp_mtu
	! is_number $kcp_mtu && kcp_mtu=1350
	Prompt "$kcp_mtu"

	unset -v kcp_sndwnd
	Introduction "sndwnd"
	read -p "(默认: 1024): " kcp_sndwnd
	! is_number $kcp_sndwnd && kcp_sndwnd=1024
	Prompt "$kcp_sndwnd"

	unset -v kcp_rcvwnd
	Introduction "rcvwnd"
	read -p "(默认: 1024): " kcp_rcvwnd
	! is_number $kcp_rcvwnd && kcp_rcvwnd=1024
	Prompt "$kcp_rcvwnd"

	unset -v kcp_datashard
	Introduction "datashard,ds"
	read -p "(默认: 10): " kcp_datashard
	! is_number $kcp_datashard && kcp_datashard=10
	Prompt "$kcp_datashard"

	unset -v kcp_parityshard
	Introduction "parityshard,ps"
	read -p "(默认: 3): " kcp_parityshard
	! is_number $kcp_parityshard && kcp_parityshard=3
	Prompt "$kcp_parityshard"

	unset -v kcp_dscp
	Introduction "dscp"
	read -p "(默认: 0): " kcp_dscp
	! is_number $kcp_dscp && kcp_dscp=0
	Prompt "$kcp_dscp"

	unset -v kcp_nocomp
	Introduction "nocomp"
	select kcp_nocomp in true false; do
		if [ "$kcp_nocomp" ]; then
			Prompt "$kcp_nocomp"
			break
		fi
	done

	unset -v extra_parameters
	Introduction "基础参数设置完成，是否设置额外的隐藏参数? (Y/N)"
	read -p "(默认: N): " -n1 extra_parameters
	echo
	if [[ $extra_parameters =~ ^[Yy]$ ]]; then
		unset -v kcp_acknodelay
		Introduction "acknodelay"
		select kcp_acknodelay in true false; do
			if [ "$kcp_acknodelay" ]; then
				Prompt "$kcp_acknodelay"
				break
			fi
		done

		unset -v kcp_nodelay
		Introduction "nodelay"
		read -p "(默认: 0): " kcp_nodelay
		! is_number $kcp_nodelay && kcp_nodelay=0
		Prompt "$kcp_nodelay"

		unset -v kcp_interval
		Introduction "interval"
		read -p "(默认: 30): " kcp_interval
		! is_number $kcp_interval && kcp_interval=30
		Prompt "$kcp_interval"

		unset -v kcp_resend
		Introduction "resend"
		read -p "(默认: 2): " kcp_resend
		! is_number $kcp_resend && kcp_resend=2
		Prompt "$kcp_resend"

		unset -v kcp_nc
		Introduction "nc"
		read -p "(默认: 1): " kcp_nc
		! is_number $kcp_nc && kcp_nc=1
		Prompt "$kcp_nc"
	fi
	echo
}

Shadowsocks_info_input() {
	unset -v server_port password method plugin
	while true; do
		local sport=$(Generate_random_numbers 1024 65535)
		Introduction "请输入Shadowsocks远程端口"
		read -p "(默认: $sport): " -n5 server_port
		[ -z "$server_port" ] && server_port=$sport
		if is_number $server_port && [ $server_port -gt 0 -a $server_port -le 65535 ]; then
			if is_number $(Used_traffic $server_port); then
				Prompt "端口正常使用中！"
				unset -v server_port
				continue
			fi
			if [ "$(netstat -ln | grep LISTEN | grep ":$server_port ")" ]; then
				Prompt "端口被其它进程占用！"
				unset -v server_port
				continue
			fi
			local temp_file=$(mktemp)
			if [ -s $HOME_DIR/port.list ]; then
				echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
					IFS='|'
					for l in $line; do
						if [ "${l#*^}" = "$server_port" ]; then
							Prompt "端口已存在于端口列表中！"
							date >$temp_file #无法获取循环内的变量，只能用土办法了。
						fi
					done
				done
			fi
			if [ -s $temp_file ]; then
				unset -v server_port
				rm -f $temp_file
				continue
			else
				rm -f $temp_file
			fi
			if [ "$server_port" ]; then
				Prompt "$server_port"
				break
			fi
		fi
	done

	local ciphertext=$(base64 -w0 /proc/sys/kernel/random/uuid)
	local spass=${ciphertext:0:15}
	Introduction "请输入Shadowsocks密码"
	read -p "(默认: $spass): " password
	[ -z "$password" ] && password=$spass
	Prompt "$password"

	Introduction "请选择Shadowsocks加密方式"
	select method in ${Encryption_method_list[@]}; do
		if [ "$method" ]; then
			Prompt "$method"
			break
		fi
	done

	while true; do
		Introduction "请输入端口流量配额 (MB): "
		read total
		if is_number $total && [ $total -gt 0 ]; then
			Prompt "$total MB"
			break
		fi
	done

	local add_plugin
	Introduction "需要加装插件吗? (Y/N)"
	read -p "(默认: N): " -n1 add_plugin
	if [[ $add_plugin =~ ^[Yy]$ ]]; then
		echo -e "\r\n"
		plugin_list=(simple-obfs kcptun simple-tls v2ray-plugin)
		select plugin in ${plugin_list[@]}; do
			if [ "$plugin" ]; then
				Prompt "$plugin"
				break
			fi
		done
		if [ "$plugin" = 'simple-obfs' ]; then
			Obfs_plugin
		elif [ "$plugin" = 'kcptun' ]; then
			Kcptun_plugin
		elif [ "$plugin" = 'simple-tls' ]; then
			Tls_plugin
		elif [ "$plugin" = 'v2ray-plugin' ]; then
			V2ray_plugin
		fi
	fi
}

#https://stackoverflow.com/questions/12768907/how-can-i-align-the-columns-of-tables-in-bash
function printTable() {
	local -r delimiter="${1}"
	local -r data="$(removeEmptyLines "${2}")"

	if [[ ${delimiter} != '' && "$(isEmptyString "${data}")" == 'false' ]]; then
		local -r numberOfLines="$(wc -l <<<"${data}")"

		if [[ ${numberOfLines} -gt '0' ]]; then
			local table=''
			local i=1

			for ((i = 1; i <= "${numberOfLines}"; i = i + 1)); do
				local line=''
				line="$(sed "${i}q;d" <<<"${data}")"

				local numberOfColumns='0'
				numberOfColumns="$(awk -F "${delimiter}" '{print NF}' <<<"${line}")"

				# Add Line Delimiter

				if [[ ${i} -eq '1' ]]; then
					table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
				fi

				# Add Header Or Body

				table="${table}\n"

				local j=1

				for ((j = 1; j <= "${numberOfColumns}"; j = j + 1)); do
					table="${table}$(printf '#| %s' "$(cut -d "${delimiter}" -f "${j}" <<<"${line}")")"
				done

				table="${table}#|\n"

				# Add Line Delimiter

				if [[ ${i} -eq '1' ]] || [[ ${numberOfLines} -gt '1' && ${i} -eq ${numberOfLines} ]]; then
					table="${table}$(printf '%s#+' "$(repeatString '#+' "${numberOfColumns}")")"
				fi
			done

			if [[ "$(isEmptyString "${table}")" == 'false' ]]; then
				echo -e "${table}" | column -s '#' -t | awk '/^\+/{gsub(" ", "-", $0)}1'
			fi
		fi
	fi
}

function removeEmptyLines() {
	local -r content="${1}"

	echo -e "${content}" | sed '/^\s*$/d'
}

function repeatString() {
	local -r string="${1}"
	local -r numberToRepeat="${2}"

	if [[ ${string} != '' && ${numberToRepeat} =~ ^[1-9][0-9]*$ ]]; then
		local -r result="$(printf "%${numberToRepeat}s")"
		echo -e "${result// /${string}}"
	fi
}

function isEmptyString() {
	local -r string="${1}"

	if [[ "$(trimString "${string}")" == '' ]]; then
		echo 'true' && return 0
	fi

	echo 'false' && return 1
}

function trimString() {
	local -r string="${1}"

	sed 's,^[[:blank:]]*,,' <<<"${string}" | sed 's,[[:blank:]]*$,,'
}

Client_Quantity() (
	i=0
	j=0
	while IFS= read -r line; do
		((i++))
		[ $i -le 2 ] && continue #仅跳出当前循环
		unset -v proto recv send local_address foreign_address state program_name
		IFS=' '
		x=0
		for l in $line; do
			((x++))
			case $x in
			1)
				proto=$l
				;;
			2)
				recv=$l
				;;
			3)
				send=$l
				;;
			4)
				local_address=$l
				;;
			5)
				foreign_address=$l
				;;
			6)
				state=$l
				;;
			7)
				program_name=$l
				break
				;;
			esac
		done
		if [ $state = "ESTABLISHED" ]; then
			if [ ${local_address##*:} = $1 ]; then
				((j++))
				array_reme[j]=${foreign_address%:*}
			fi
		fi
	done <$net_file
	if [ $j -ge 1 ]; then
		array_reme=($(echo "${array_reme[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
		echo -n ${#array_reme[@]}
	fi
)

User_list_display() {
	while true; do
		local temp_file=$(mktemp) net_file=$(mktemp)
		if [ -s $HOME_DIR/port.list ]; then
			echo '序号,端口,传输插件,流量,使用率,客户端数量,状态' >$temp_file
			netstat -anp46 >$net_file
			local serial=0
			echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
				Parsing_User "$line"
				if [ "$server_port" ]; then
					if [[ $plugin != "kcptun-server" && $plugin_opts != *quic* ]]; then
						local quantity=$(Client_Quantity $server_port)
					else
						local quantity='不支持'
					fi
					local used=$(Used_traffic $server_port)
					! is_number $used && unset -v used
					((serial++))
					if [ "$used" -a ${used:=-1} -ge 0 ]; then
						local status='正常'
					else
						local used=0
					fi
					if [ "$plugin" = "obfs-server" ]; then
						plugin='simple-obfs'
					elif [ "$plugin" = "kcptun-server" ]; then
						plugin='kcptun'
					elif [ "$plugin" = "v2ray-plugin" ]; then
						plugin='v2ray'
					fi
					[ -z "$total" ] && local total=0
					#1024*1024=1048576
					echo "${serial:-0},${server_port:-0},$plugin,$((used / 1048576))/$((total / 1048576)) MB,$((used * 100 / total)) %,$quantity,${status:=停止}" >>$temp_file
				fi
				unset -v quantity used status
			done
			printTable ',' "$(<$temp_file)"
		fi
		rm -f $net_file $temp_file
		cat <<EOF
1. 添加端口
2. 删除端口
3. 强制下线
EOF
		read -p $'请选择 \e[95m1-3\e[0m: ' -n1 action
		echo
		case $action in
		1)
			Add_user
			;;
		2)
			Delete_users
			;;
		3)
			Forced_offline
			;;
		*)
			break
			;;
		esac
		clear
	done
}

Add_user() {
	Address_lookup
	Shadowsocks_info_input
	Press_any_key_to_continue
	clear
	local userinfo_v4 qrv4 name plugin_url
	if [ "$ipv4" ]; then
		echo -e "服务器(IPv4)     : \033[1;31m $ipv4 \033[0m"
		userinfo_v4="$(echo -n "$method:$password" | base64 -w0 | sed 's/=//g; s/+/-/g; s/\//_/g')"
		#websafe-base64-encode-utf8 不兼容标准的的base64
		#https://www.liaoxuefeng.com/wiki/1016959663602400/1017684507717184
	fi
	name=$(Url_encode "$addr")
	echo -e "远程端口      : \033[1;31m $server_port \033[0m"
	echo -e "密码      : \033[1;31m $password \033[0m"
	echo -e "加密方式      : \033[1;31m $method \033[0m"
	case $plugin in
	simple-obfs)
		ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^obfs-server|plugin_opts^obfs=$obfs|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "obfs-local;obfs=$obfs;obfs-host=checkappexec.microsoft.com")"
		;;
	kcptun)
		local kcp_nocomps kcp_acknodelays
		[ "$kcp_nocomp" = "true" ] && kcp_nocomps=';nocomp'
		[ "$kcp_acknodelay" = "true" ] && kcp_acknodelays=';acknodelay'
		if [[ $extra_parameters =~ ^[Yy]$ ]]; then
			ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun-server\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun-server|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays")"
		else
			ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun-server\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun-server|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps")"
		fi
		;;
	simple-tls)
		local tls_pds
		[ "$tls_pd" = "true" ] && tls_pds=';pd'
		ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"simple-tls\",\"plugin_opts\":\"s;key=$tls_key;cert=$tls_cert$tls_pds\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^simple-tls|plugin_opts^s;key=$tls_key;cert=$tls_cert$tls_pds|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "simple-tls;cca=$(base64 -w0 $tls_cert);n=$tls_common_name$tls_pds")"
		;;
	v2ray-plugin)
		local v2ray_modes v2ray_certraw v2ray_client qui
		v2ray_certraw=$(sed '1d;$d' $tls_cert)
		case $v2ray_mode in
		websocket-http)
			v2ray_modes="server;path=$v2ray_path;host=$tls_common_name"
			v2ray_client="path=$v2ray_path;host=$tls_common_name"
			;;
		websocket-tls)
			v2ray_modes="server;tls;path=$v2ray_path;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="tls;path=$v2ray_path;host=$tls_common_name;certRaw=$v2ray_certraw"
			;;
		quic-tls)
			v2ray_modes="server;mode=quic;host=$tls_common_name;key=$tls_key;cert=$tls_cert"
			v2ray_client="mode=quic;host=$tls_common_name;certRaw=$v2ray_certraw"
			qui='tcp_only'
			;;
		esac
		ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"${qui:=tcp_and_udp}\",\"plugin\":\"v2ray-plugin\",\"plugin_opts\":\"$v2ray_modes\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^v2ray-plugin|plugin_opts^$v2ray_modes|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "v2ray-plugin;$v2ray_client")"
		;;
	*)
		ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^|plugin_opts^|total^$((total * 1048576))" >>$HOME_DIR/port.list
		;;
	esac
	if [ "$plugin" ]; then
		echo -e "传输插件      : \033[1;31m $plugin \033[0m"
		if [ "$userinfo_v4" ]; then
			qrv4="ss://$userinfo_v4@$ipv4:$server_port$plugin_url#$name"
			echo -e "\033[0;32m$qrv4 \033[0m"
		fi
	else
		if [ "$userinfo_v4" ]; then
			qrv4="ss://$userinfo_v4@$ipv4:$server_port#$name"
			echo -e "\033[0;32m$qrv4 \033[0m"
		fi
	fi
	echo -e "\n[\033[41;37mFBI WARNING\033[0m]\033[0;33m以上链接信息拿笔记好！！！\033[0m\n"
	Introduction "需要显示二维码和客户端配置文件吗？"
	read -p "(默认: N): " -n1 qrv
	if [[ $qrv =~ ^[Yy]$ ]]; then
		clear
		if [ "$qrv4" ]; then
			ssurl -d "$qrv4"
			qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv4"
		fi
	fi
	echo
	Press_any_key_to_continue
}

Delete_users() {
	if [ -s $HOME_DIR/port.list ]; then
		port=$1
		until [ $port ]; do
			Introduction "请输入需要删除的Shadowsocks远程端口"
			read -n5 port
			is_number $port && [ $port -gt 0 -a $port -le 65535 ] && break || unset -v port
		done
		local temp_file=$(mktemp)
		echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
			Parsing_User "$line"
			if is_number $server_port && is_number $total; then
				if [[ $server_port -ne $port && $server_port -gt 0 && $server_port -lt 65535 && $password && $method && $total -gt 0 ]]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|total^$total" >>$temp_file
				fi
				if [ $server_port -eq $port ]; then
					ss-tool /dev/shm/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
				fi
			fi
		done
		mv -f $temp_file $HOME_DIR/port.list
	else
		Prompt "没有找到端口列表文件"
		Press_any_key_to_continue
	fi
}

Forced_offline() {
	while true; do
		Introduction "请输入需要强制下线的Shadowsocks远程端口"
		read -n5 port
		if is_number $port && [ $port -gt 0 -a $port -le 65535 ]; then
			ss-tool /dev/shm/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
			break
		fi
	done
}

Daemon() {
	if [ -r /run/ss-daemon.pid ]; then
		pkill -F /run/ss-daemon.pid 2>/dev/null
	fi
	echo $NOW_PID >/run/ss-daemon.pid
	if [ -r /run/ss-manager.pid -a -r /run/ss-daemon.pid ]; then
		read pid1 </run/ss-manager.pid
		read pid2 </run/ss-daemon.pid
		if is_number $pid1 && is_number $pid2; then
			while [ -d /proc/${pid1} -a -d /proc/${pid2} ]; do
				if [ -s $HOME_DIR/port.list ]; then
					echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
						Parsing_User "$line"
						local flow=$(Used_traffic $server_port)
						if is_number $server_port && is_number $flow && is_number $total; then
							if [ ${flow:-0} -ge ${total:-0} ]; then
								Delete_users "$server_port" >/dev/null
							fi
							unset -v flow
						fi
					done
				fi
				sleep 1
			done
		fi
	fi
}

Start() {
	if [ -s $HOME_DIR/port.list ]; then
		if [ ${runing:-false} = true ]; then
			Prompt "服务运行中请先停止运行!"
			Press_any_key_to_continue
		else
			ssmanager \
				--manager-address /dev/shm/ss-manager.socket \
				--daemonize-pid /run/ss-manager.pid \
				--daemonize
			local cs=50 #5秒启动超时，太快了会报(ERROR failed to daemonize, unable to lock pid file)错误，需要等待完成
			until [ -e /dev/shm/ss-manager.socket -a -s /run/ss-manager.pid ]; do
				((cs--))
				if [ ${cs:-0} -eq 0 ]; then
					Prompt "启动ss-manager超时!"
					Stop
					Exit
				else
					sleep 0.1
				fi
			done
			echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
				Parsing_User "$line"
				local using=$(Used_traffic $server_port)
				if is_number $server_port && is_number $total && [ -z $using ] && [ $password -a $method ]; then
					if [ "$plugin" -a "$plugin_opts" ]; then
						#echo -e "正在打开\033[32m $server_port \033[0m端口服务 传输插件 $plugin"
						if [[ $plugin == "kcptun-server" || $plugin_opts == *quic* ]]; then
							ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
						else
							ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
						fi
					else
						#echo -e "正在打开\033[32m $server_port \033[0m端口服务"
						ss-tool /dev/shm/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\"}" >/dev/null
					fi
				fi
				unset -v using
			done
			(setsid ss-main daemon >/dev/null 2>&1 &)
			cs=30 #3秒超时，需要等待后台守护脚本启动完成
			until [ -s /run/ss-daemon.pid ]; do
				((cs--))
				if [ ${cs:-0} -eq 0 ]; then
					Prompt "守护脚本启动超时!"
					Stop
					Exit
				else
					sleep 0.1
				fi
			done
		fi
	else
		Prompt "没有找到端口列表文件！请先添加端口。"
		Press_any_key_to_continue
	fi
}

Stop() {
	for i in /run/ss-manager.pid /run/ss-daemon.pid; do
		[ -s $i ] && read kpid <$i
		[ -d /proc/${kpid:=abcdefg} ] && kill $kpid && rm -f $i
	done
}

Update_core() {
	local temp_file=$(mktemp) temp_file2=$(mktemp)
	echo '核心文件路径,更新状态' >$temp_file2
	Wget_get_files $temp_file $URL/version/update
	#sed -i "s=*bin=$HOME_DIR/usr/bin=" $temp_file
	! shasum -a512 -c $temp_file >>$temp_file2 && _update=true || _update=false
	sed -i 's/: /,/g' $temp_file2
	printTable ',' "$(<$temp_file2)"
	rm -f $temp_file $temp_file2
	if $_update; then
		rm -rf $HOME_DIR/usr $HOME_DIR/conf
		Check
		Prompt "请重启本脚本的所有服务以完成后续更新升级。"
		Exit
	else
		Prompt "未发现任何更新！"
	fi
	Press_any_key_to_continue
}

Uninstall() {
	Introduction "确定要卸载吗? (Y/N)"
	read -p "(默认: N): " -n1 delete
	if [[ $delete =~ ^[Yy]$ ]]; then
		systemctl stop ss-main.service
		systemctl disable ss-main.service
		rm -f /etc/systemd/system/ss-main.service
		systemctl daemon-reload
		systemctl reset-failed
		Stop
		Close_traffic_forward
		rm -rf $HOME_DIR
		rm -f $0
		rm -f /usr/local/bin/ss-main
		${HOME}/.acme.sh/acme.sh --uninstall
		rm -rf ${HOME}/.acme.sh
		Prompt "已卸载！(最好重启一下)"
		Exit
	else
		Prompt "已取消操作..."
	fi
	Press_any_key_to_continue
}

Speed_test() (
	if [ ! -f $HOME_DIR/usr/bin/iperf3 ] || [ ! -x $HOME_DIR/usr/bin/iperf3 ]; then
		Wget_get_files $HOME_DIR/usr/bin/iperf3 $URL/usr/bin/iperf3
		chmod +x $HOME_DIR/usr/bin/iperf3
	fi
	client_file=$(mktemp)
	server_file=$(mktemp)
	client_pid=$(mktemp)
	server_pid=$(mktemp)
	iperf3_pid=$(mktemp)
	log=$(mktemp)
	i=0
	iperf3 --server --bind 127.0.0.1 --port 5201 --pidfile $iperf3_pid --daemon
	for x in ${Encryption_method_list[@]}; do
		((i++))
		Progress_Bar $i ${#Encryption_method_list[@]} $x
		cat >$server_file <<EOF
{
    "server": "127.0.0.1",
    "server_port": 8388,
    "method": "$x",
    "password": "your-password",
    "timeout": 5,
    "dns": "google",
    "mode": "tcp_only",
    "no_delay": false,
    "ipv6_first": false
}
EOF
		pkill -F $server_pid 2>/dev/null
		ssserver --config $server_file --daemonize-pid $server_pid --daemonize
		cat >$client_file <<EOF
{
    "local_address": "127.0.0.1",
    "local_port": 1080,
    "server": "127.0.0.1",
    "server_port": 8388,
    "method": "$x",
    "password": "your-password",
    "timeout": 5,
    "dns": "google",
    "mode": "tcp_only",
    "no_delay": false,
    "ipv6_first": false
}
EOF
		pkill -F $client_pid 2>/dev/null
		sslocal --config $client_file --protocol tunnel --forward-addr 127.0.0.1:5201 --daemonize-pid $client_pid --daemonize
		temp=$(mktemp)
		#env \
		#PROXYCHAINS_CONF_FILE=$conf \
		#LD_PRELOAD_LD_PRELOAD=/usr/local/lib/libproxychains4.so \
		iperf3 --client 127.0.0.1 --port 1080 --version4 --logfile $temp --bytes 1G --zerocopy #iperf3用脚本运行太快了所以要sleep一会让其正常处理好数据防止出错，被这个坑了好久百思不得其解
		until [ "$(grep 'iperf Done.' $temp)" ]; do
			sleep 0.1
		done
		send=$(grep 'sender' $temp | awk '{print $7,$8}')
		recv=$(grep 'receiver' $temp | awk '{print $7,$8}')
		echo "$x,$send,$recv" >>$log
		rm -f $temp
	done
	pkill -F $client_pid 2>/dev/null
	pkill -F $server_pid 2>/dev/null
	pkill -F $iperf3_pid 2>/dev/null
	printTable ',' "$(sed '1i加密方式,发送,接收' $log)"
	rm -f $client_file $server_file $client_pid $iperf3_pid $server_pid $log
	Press_any_key_to_continue
)

ShadowsocksR_Link_Decode() {
	local link a b server_port protocol method obfs password other obfsparam protoparam remarks group
	read -p "请输入SSR链接: " link
	[[ $link != "ssr://"* || -z $link ]] && Exit
	a=${link#ssr\:\/\/}
	b=$(echo $a | base64 -d 2>&-)
	i=0
	IFS=':'
	for c in ${b%\/}; do
		((i++))
		case $i in
		1)
			server=$c
			;;
		2)
			server_port=$c
			;;
		3)
			protocol=$c
			;;
		4)
			method=$c
			;;
		5)
			obfs=$c
			;;
		6)
			password=$(echo ${c%\/\?*} | base64 -d 2>&-) #再解一次base64被坑了好久
			other=${c#*\/\?}
			;;
		esac
	done
	IFS='&'
	for d in $other; do
		case ${d%\=*} in
		obfsparam)
			obfsparam=$(echo ${d#*\=} | base64 -d 2>&-)
			;;
		protoparam)
			protoparam=$(echo ${d#*\=} | base64 -d 2>&-)
			;;
		remarks)
			remarks=${d#*\=} #不解码了不规范的命名会乱码
			;;
		group)
			group=${d#*\=}
			;;
		esac
	done
	cat >/tmp/ssr-redir.conf <<EOF
{
    "server":"$server",
    "server_port":$server_port,
    "method":"$method",
    "password":"$password",
    "protocol":"$protocol",
    "protocol_param":"$protoparam",
    "obfs":"$obfs",
    "obfs_param":"$obfsparam",
    "user":"nobody",
    "fast_open":false,
    "nameserver":"1.1.1.1",
    "mode":"tcp_only",
    "local_address":"127.0.0.1",
    "local_port":1088,
    "timeout":30
}
EOF
	cat /tmp/ssr-redir.conf
}

Close_traffic_forward() {
	iptables -w -t nat -D OUTPUT -j SHADOWSOCKS
	iptables -w -t nat -F SHADOWSOCKS
	iptables -w -t nat -X SHADOWSOCKS
	ipset destroy ipv4_lan
	ipset destroy traffic_forward
	ipset destroy bahamut
	ipset destroy cloudmusic
	pkill -F /run/ssr-redir.pid && rm -f /run/ssr-redir.pid
}

Start_traffic_forward() {
	[ ! -s /tmp/ssr-redir.conf ] && Exit
	ssr-redir -c /tmp/ssr-redir.conf -f /run/ssr-redir.pid || Exit
	rm -f /tmp/ssr-redir.conf
	local ipv4_lan=(
		0.0.0.0/8
		10.0.0.0/8
		100.64.0.0/10
		127.0.0.0/8
		169.254.0.0/16
		172.16.0.0/12
		192.0.0.0/24
		192.0.2.0/24
		192.88.99.0/24
		192.168.0.0/16
		198.18.0.0/15
		198.51.100.0/24
		203.0.113.0/24
		224.0.0.0/4
		240.0.0.0/4
		255.255.255.255/32
		${server}/32
	)
	iptables -w -t nat -N SHADOWSOCKS
	ipset create ipv4_lan hash:net
	for i in ${ipv4_lan[@]}; do
		ipset add ipv4_lan $i
	done
	ipset create bahamut hash:net
	ipset create cloudmusic hash:ip
	ipset create traffic_forward hash:net
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set ipv4_lan dst -j RETURN
	#iptables -w -t nat -A SHADOWSOCKS -m owner --uid-owner nobody -j ACCEPT
	#iptables -w -t nat -A SHADOWSOCKS -p tcp -j LOG --log-prefix='[netfilter] '
	#grep 'netfilter' /var/log/kern.log
	iptables -w -t nat -A SHADOWSOCKS -p tcp -m set --match-set traffic_forward dst -j REDIRECT --to-ports 1088
	iptables -w -t nat -A OUTPUT -j SHADOWSOCKS
}

Debug_mode() {
	cat >/tmp/ss-debug.conf <<EOF
{
    "server": "0.0.0.0",
    "server_port": 1234,
    "method": "aes-128-gcm",
    "password": "admin",
    "timeout": 5,
    "dns": "google",
    "mode": "tcp_and_udp",
    "no_delay": false,
    "ipv6_first": false
}
EOF
	Prompt "server_port 1234 method aes-128-gcm password admin"
	ssserver --config /tmp/ss-debug.conf -v
}

Start_nginx_program() {
	Create_certificate

	if [ ! -f $HOME_DIR/usr/bin/nginx ] || [ ! -x $HOME_DIR/usr/bin/nginx ]; then
		echo "正在下载 nginx"
		Wget_get_files $HOME_DIR/usr/bin/nginx $URL/usr/sbin/nginx
		chmod +x $HOME_DIR/usr/bin/nginx
	fi
	if [ ! -f $HOME_DIR/usr/bin/php-fpm ] || [ ! -x $HOME_DIR/usr/bin/php-fpm ]; then
		echo "正在下载 php-fpm"
		Wget_get_files $HOME_DIR/usr/bin/php-fpm $URL/usr/sbin/php-fpm
		chmod +x $HOME_DIR/usr/bin/php-fpm
	fi
	if [ ! -d $HOME_DIR/usr/logs ]; then
		mkdir -p $HOME_DIR/usr/logs
	else
		rm -rf $HOME_DIR/usr/logs/*
	fi
	if [ ! -f $HOME_DIR/conf/cdn_only.conf ]; then
		touch $HOME_DIR/conf/cdn_only.conf
	fi
	if [ -s $HOME_DIR/port.list ]; then
		rm -f $HOME_DIR/conf/v2ray_list.conf
		echo -e "$(<$HOME_DIR/port.list)\n" | while IFS= read -r line; do
			unset -v v2_path
			Parsing_User "$line"
			if [[ $plugin == "v2ray-plugin" && $plugin_opts != *quic* ]]; then
				unset -v v2_protocols
				if [[ $plugin_opts == *tls* ]]; then
					local v2_protocols='https'
				else
					local v2_protocols='http'
				fi
				local v2_path=$(Parsing_plugin_opts $plugin_opts "path")
				if [ "$v2_path" ]; then
					cat >>$HOME_DIR/conf/v2ray_list.conf <<-EOF

						location /${v2_path} {
						    include    v2safe.conf;
						    proxy_pass ${v2_protocols}://127.0.0.1:${server_port};
						    include    proxy.conf;
						}
						    
					EOF
				fi
			fi
		done
	else
		Prompt "没有找到端口列表文件"
		Exit
	fi
	if [ -z $tls_common_name ]; then
		Prompt "无法获取域名信息！"
		Exit
	fi
	if [ ! -s $HOME_DIR/conf/mime.types ]; then
		echo "正在下载 mime.types"
		Wget_get_files $HOME_DIR/conf/mime.types $URL/usr/conf/mime.types
	fi
	for i in v2safe.conf add_header.conf v2ray-plugin.conf proxy.conf nginx.conf general.conf fastcgi_params.conf php-fpm.conf www.conf; do
		if [ ! -s $HOME_DIR/conf/$i ]; then
			echo "正在下载 $i"
			Wget_get_files $HOME_DIR/conf/$i $URL/conf/$i
		fi
	done
	for i in 50x.html index.html; do
		if [ ! -s $HOME_DIR/web/$i ]; then
			echo "正在下载 $i"
			Wget_get_files $HOME_DIR/web/$i $URL/usr/html/$i
		fi
	done
	sed -i "/server_name/c\    server_name         $tls_common_name;" $HOME_DIR/conf/v2ray-plugin.conf
	#groupadd web
	#useradd -g web nginx -M -s /sbin/nologin
	if nginx -c $HOME_DIR/conf/nginx.conf -t; then
		nginx -c $HOME_DIR/conf/nginx.conf
		Prompt "请将你的客户端v2ray插件websocket-http模式的节点服务器选项改为 \"你的域名或者CDN节点IP\" 端口改为 \"80\" 现在访问你的域名 http://$tls_common_name 应该可以看到nginx的首页了"
	else
		Prompt "请检查nginx配置是否有误"
		Exit
	fi
	if ! php-fpm -n -y $HOME_DIR/conf/php-fpm.conf -R; then
		Prompt "请检查php-fpm配置是否有误"
		Exit
	fi
}

Advanced_features() {
	[ $first -le 1 ] && {
		#https://lncn.org/ 免费节点
		if [ ! -f $HOME_DIR/usr/bin/ssr-redir ] || [ ! -x $HOME_DIR/usr/bin/ssr-redir ]; then
			Wget_get_files $HOME_DIR/usr/bin/ssr-redir $URL/usr/bin/ss-redir
			chmod +x $HOME_DIR/usr/bin/ssr-redir
		fi
		if [ "$common_install" ]; then
			for i in iptables ipset curl git; do
				if ! command_exists $i; then
					$common_install $i
				fi
			done
		fi
	}
	while true; do
		Introduction "高级功能需熟读本脚本源码后再使用，否则后果自负！"
		local srd ngx pfm onc ret_code
		if [ -s /run/ssr-redir.pid ]; then
			read srd </run/ssr-redir.pid
		fi
		if [ -d /proc/${srd:=ssr-dir} ]; then
			ret_code=$(curl --silent --output /dev/null --write-out '%{http_code}' --connect-timeout 2 --max-time 4 --url https://www.google.com)
			#https://stackoverflow.com/a/28356429
			if [[ ${ret_code:-0} != +(200|301|302) ]]; then
				echo -e '\033[7;31;43m无法访问Google请尝试切换或者关闭代理！\033[0m'
			fi
			echo -e "\033[1mssr-redir运行中 PID: \033[0m\033[7m$srd\033[0m"
		fi
		if [ -s /run/nginx.pid ]; then
			read ngx </run/nginx.pid
		fi
		if [ -d /proc/${ngx:=nginxx} ]; then
			echo -e "\033[1mnginx运行中 PID: \033[0m\033[7m$ngx\033[0m"
		fi
		if [ -s /run/php-fpm.pid ]; then
			read pfm </run/php-fpm.pid
		fi
		if [ -d /proc/${pfm:=pfmcj} ]; then
			echo -e "\033[1mphp-fpm运行中 PID: \033[0m\033[7m$pfm\033[0m"
		fi
		cat <<EOF

—————————————— 服务器发出流量代理 ——————————————
1. 打开代理
2. 关闭代理
3. 调试模式
4. SSR链接解析
5. 添加IP地址
6. 添加Google网段
7. 添加Cloudflare网段
8. 清空IP列表
9. 查看IP列表
10. 查看iptables规则链状态
11. 80,443全局流量代理
12. 解锁动画疯限制
13. 解锁网易云音乐限制
—————————————— CDN中转+Nginx分流 ——————————————
14. 开启Nginx
15. 关闭Nginx
16. 更新证书
17. 更换网站模板
18. 仅限通过CDN访问
19. 禁止ping服务器
EOF
		read -p $'请选择 \e[95m1-19\e[0m: ' -n2 action
		echo
		case $action in
		1)
			ShadowsocksR_Link_Decode
			Start_traffic_forward
			;;
		2)
			Close_traffic_forward
			;;
		3)
			Debug_mode
			;;
		4)
			ShadowsocksR_Link_Decode
			;;
		5)
			read -p "请输入IP地址: " aip
			ipset add traffic_forward $aip
			;;
		6)
			local google_ipv4_ranges=$(curl --silent --connect-timeout 5 https://md5calc.com/google/ip | grep '<div>' | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
				IFS='@'
				for i in $google_ipv4_ranges; do
					[ "$i" ] && ipset add traffic_forward $i
				done
			}
			;;
		7)
			local cloudflare_ipv4_ranges=$(curl --silent --connect-timeout 5 https://www.cloudflare.com/ips-v4 | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
				IFS='@'
				for i in $cloudflare_ipv4_ranges; do
					[ "$i" ] && ipset add traffic_forward $i
				done
			}
			;;
		8)
			ipset flush traffic_forward
			;;
		9)
			ipset list traffic_forward
			;;
		10)
			iptables -vxn -t nat -L SHADOWSOCKS --line-number
			;;
		11)
			iptables -w -t nat -R SHADOWSOCKS 2 -p tcp -m multiport --dport 80,443 -j REDIRECT --to-ports 1088
			;;
		12)
			#gamer-cds.cdn.hinet.net gamer2-cds.cdn.hinet.net ani.gamer.com.tw 从ipip.net收集的网段
			bahamut_ipv4_ranges=$(curl --silent --connect-timeout 5 https://whois.ipip.net/AS3462 | grep "<td><a href=" | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | sort -u | tr '\n' '@') && {
				IFS='@'
				for i in $bahamut_ipv4_ranges 104.16.181.30/32 104.16.182.30/32; do
					[ "$i" ] && ipset add bahamut $i
				done
			}
			iptables -w -t nat -I SHADOWSOCKS 3 -p tcp -m multiport --dport 80,443 -m set --match-set bahamut dst -j REDIRECT --to-ports 1089 && Prompt "流量将会发送到iptables透明代理端口1089"
			;;
		13)
			cat <<EOF
路由>全局模式
流量将会发送到iptables透明代理端口1090
EOF
			for i in 103.126.92.132 103.126.92.133; do
				ipset add cloudmusic $i
			done
			iptables -w -t nat -I SHADOWSOCKS 3 -p tcp -m multiport --dport 80,443 -m set --match-set cloudmusic dst -j REDIRECT --to-ports 1090
			;;
		14)
			Start_nginx_program
			;;
		15)
			pkill -F /run/nginx.pid && rm -f /run/nginx.pid
			pkill -F /run/php-fpm.pid && rm -f /run/php-fpm.pid
			;;
		16)
			Introduction "确定要更新吗?注意申请次数限制 (Y/N)"
			read -p "(默认: N): " -n1 delete
			if [[ $delete =~ ^[Yy]$ ]]; then
				rm -f $HOME_DIR/ssl/*
				Create_certificate
			else
				Prompt "已取消操作..."
			fi
			;;
		17)
			cat <<EOF
为防止伪装站点千篇一律，特意准备了以下模板
1. Speedtest-X
2. Mikutap
3. Flappy Winnie
4. FlappyFrog
5. bao
6. ninja
EOF
			read -p $'请选择 \e[95m1-6\e[0m: ' -n1 action
			is_number $action && [ $action -ge 1 -a $action -le 6 ] && {
				rm -rf $HOME_DIR/web
				case $action in
				1)
					git clone --depth 1 https://github.com/BadApple9/speedtest-x $HOME_DIR/web
					;;
				2)
					git clone --depth 1 https://github.com/HFIProgramming/mikutap $HOME_DIR/web
					;;
				3)
					git clone --depth 1 https://github.com/hahaxixi/hahaxixi.github.io $HOME_DIR/web
					;;
				4)
					git clone --depth 1 https://github.com/hahaxixi/FlappyFrog $HOME_DIR/web
					;;
				5)
					git clone --depth 1 https://github.com/hahaxixi/bao $HOME_DIR/web
					;;
				6)
					git clone --depth 1 https://github.com/hahaxixi/ninja $HOME_DIR/web
					;;
				esac
			}
			;;
		18)
			if [ -s $HOME_DIR/conf/cdn_only.conf ]; then
				onc=true
			else
				onc=false
			fi
			cat <<EOF
为了nginx服务器安全仅允许CDN的来源IP访问nginx上架设的网页与反向代理。(目前仅支持Cloudflare)
1. 开启nginx防火墙 ($onc)
2. 关闭nginx防火墙
3. 启用iptables防护 ($(iptables -w -t filter -C INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset 2>/dev/null && echo true || echo false))
4. 取消iptables防护
EOF
			read -p $'请选择 \e[95m1-4\e[0m: ' -n1 action
			is_number $action && [ $action -ge 1 -a $action -le 4 ] && {
				if [ ! -s /tmp/ips4 ] || [ ! -s /tmp/ips6 ]; then
					Wget_get_files /tmp/ips4 https://www.cloudflare.com/ips-v4
					Wget_get_files /tmp/ips6 https://www.cloudflare.com/ips-v6
				fi
				case $action in
				1)
					rm -f $HOME_DIR/conf/cdn_only.conf
					: <<EOF
if (\$http_cf_ipcountry = "") {
  return 403;
}
if (\$http_cf_connecting_ip = "") {
  return 403;
}
EOF
					echo -e "$(cat /tmp/ips4 /tmp/ips6)\n" | while IFS= read -r line; do
						[ "$line" ] && echo "allow   $line;" >>$HOME_DIR/conf/cdn_only.conf
					done
					echo "deny    all;" >>$HOME_DIR/conf/cdn_only.conf
					rm -f /tmp/ips4 /tmp/ips6
					Prompt "需要重启nginx后生效"
					;;
				2)
					rm -f $HOME_DIR/conf/cdn_only.conf
					Prompt "需要重启nginx后生效"
					;;
				3)
					ipset create cdn_only4 hash:net family inet
					ipset create cdn_only6 hash:net family inet6
					echo -e "$(</tmp/ips4)\n" | while IFS= read -r line; do
						[ "$line" ] && ipset add cdn_only4 $line
					done
					echo -e "$(</tmp/ips6)\n" | while IFS= read -r line; do
						[ "$line" ] && ipset add cdn_only6 $line
					done
					iptables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset #让gfw也尝尝被墙的滋味(tcp连接重置)
					ip6tables -w -t filter -A INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
					Prompt "iptables规则添加完毕！"
					;;
				4)
					iptables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only4 src -j REJECT --reject-with tcp-reset
					ip6tables -w -t filter -D INPUT -p tcp -m multiport --dport 80,443 -m set ! --match-set cdn_only6 src -j REJECT --reject-with tcp-reset
					ipset destroy cdn_only4
					ipset destroy cdn_only6
					Prompt "iptables规则清理完成！"
					;;
				esac
			}
			;;
		19)
			iptables -t filter -D INPUT -p icmp -j DROP 2>/dev/null
			iptables -t filter -A INPUT -p icmp -j DROP
			;;
		*)
			break
			;;
		esac
		Press_any_key_to_continue
		clear
	done
}

Exit() {
	kill -9 $NOW_PID
}

if [ "$1" = "daemon" ]; then
	Daemon
elif [ "$1" = "start" ]; then
	Start
elif [ "$1" = "restart" ]; then
	Stop
	Start
elif [ "$1" = "stop" ]; then
	Stop
else
	first=0
	while true; do
		((first++))
		[ $first -le 1 ] && Check
		clear
		Author
		Status
		cat <<EOF
  1. 端口列表->>
  2. 启动运行
  3. 停止运行
  4. 卸载删除
  5. 版本更新
  6. 速度测试
  7. 高级功能->>
EOF
		read -p $'请选择 \e[95m1-7\e[0m: ' -n1 action
		echo
		case $action in
		1)
			User_list_display
			;;
		2)
			Start
			;;
		3)
			Stop
			;;
		4)
			Uninstall
			;;
		5)
			Update_core
			;;
		6)
			Speed_test
			;;
		7)
			Advanced_features
			;;
		*)
			break
			;;
		esac
	done
fi
