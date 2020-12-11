#!/bin/bash

NOW_PID=$$
HOME_DIR=/etc/ssmanager
URL="https://github.com/yiguihai/shadowsocks_install/raw/master"
export PATH=${PATH}:${HOME_DIR}/bin:${PWD}

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
	table
	rc4-md5
	aes-128-ctr
	aes-192-ctr
	aes-256-ctr
	aes-128-cfb
	aes-192-cfb
	aes-256-cfb
	aes-128-ofb
	aes-192-ofb
	aes-256-ofb
	camellia-128-ctr
	camellia-192-ctr
	camellia-256-ctr
	camellia-128-cfb
	camellia-192-cfb
	camellia-256-cfb
	camellia-128-ofb
	camellia-192-ofb
	camellia-256-ofb
	rc4
	chacha20-ietf
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
	ipv4=$(ip -4 -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p')
	if [ ! -s /tmp/myaddr ]; then
		addr=$(wget -qO- -t2 -T3 -U 'curl/7.65.0' https://myip.ipip.net)
		addr=${addr##*\来\自\于}
		addr=${addr:1}
		[ "$addr" ] && echo $addr >/tmp/myaddr
	else
		addr=$(cat /tmp/myaddr)
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
	a=$(ss-tool /run/ss-manager.socket ping 2>/dev/null)
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
		Introduction "请输入域名以申请证书为空则使用自签证书，申请证书次数有限制，申请完保存好 $HOME_DIR/ssl 目录文件，防止丢失方便下次使用。"
		read -p "(默认: lucky.me): " tls_common_name
		if [ "$tls_common_name" ]; then
			if [ -x ${HOME}/.acme.sh/acme.sh ]; then
				${HOME}/.acme.sh/acme.sh --upgrade
			else
				wget -O - https://get.acme.sh | sh
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
	tls_common_name=$(cat ${HOME_DIR}/ssl/my_host)
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
			*)
				$common_install $i
				;;
			esac
		fi
	done
	if [ ! -d $HOME_DIR ]; then
		mkdir -p $HOME_DIR || Exit
	fi
	for i in bin acl conf temp ssl web; do
		if [ ! -d $HOME_DIR/$i ]; then
			mkdir -p $HOME_DIR/$i || Exit
		fi
	done
	if [ ! -s $HOME_DIR/acl/server_block.acl ]; then
		Wget_get_files $HOME_DIR/acl/server_block.acl $URL/acl/server_block.acl
	fi
	if command_exists systemctl; then
		if [ ! -s /etc/systemd/system/ss-main.service ]; then
			Wget_get_files /etc/systemd/system/ss-main.service $URL/init.d/ss-main.service
			chmod 0644 /etc/systemd/system/ss-main.service
			systemctl enable ss-main.service
			systemctl daemon-reload
		fi
	else
		echo -e "\033[31m缺少systemctl支持!\033[0m"
		Uninstall
	fi
	local i=0
	for x in ${Binary_file_list[@]}; do
		((i++))
		if [[ ! -f $HOME_DIR/bin/$x || ! -x $HOME_DIR/bin/$x ]]; then
			Wget_get_files $HOME_DIR/bin/$x $URL/bin/$x
			chmod +x $HOME_DIR/bin/$x
			[ "$x" = "ss-main" -a ! -x /usr/local/bin/$x ] && ln -s $HOME_DIR/bin/$x /usr/local/bin/$x
			Progress_Bar $i ${#Binary_file_list[@]}
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
		else
			echo -e "\033[7;31;43m守护脚本未运行\033[0m"
			Stop
		fi
	else
		if [[ "$(ssmanager -V)" == "shadowsocks"* ]]; then
			echo -e "\033[7;31;43m未运行\033[0m"
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
		local v2ray_paths=$(md5sum /proc/sys/kernel/random/uuid | cut -d " " -f 1)
		until [ $v2ray_path ]; do
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
	local sport=$(Generate_random_numbers 1024 65535)
	while true; do
		Introduction "请输入Shadowsocks远程端口"
		read -p "(默认: $sport): " -n5 server_port
		[ -z "$server_port" ] && server_port=$sport
		if is_number $server_port && [ $server_port -gt 0 -a $server_port -le 65535 ]; then
			if is_number $(Used_traffic $server_port); then
				Prompt "端口正常使用中，无法添加！删除后重试。"
				Exit
			fi
			if [ "$(netstat -ln | grep LISTEN | grep ":$server_port ")" ]; then
				Prompt "端口被其他进程占用请重新输入！"
				Exit
			fi
			if [ -s $HOME_DIR/port.list ]; then
				echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
					IFS='|'
					for l in $line; do
						if [ "${l#*^}" = "$server_port" ]; then
							Prompt "端口已存在于端口列表中，请删除后重试。"
							Exit
						fi
					done
				done
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
			if [ ${local_address##*:} = $1 -o ${local_address##*:} = $1 ]; then
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
		echo
		echo '序号,端口,传输插件,流量,使用率,客户端数量,状态' >$temp_file
		netstat -anp46 >$net_file
		local serial=0
		echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
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
				fi
				[ -z "$total" ] && local total=0
				#1024*1024=1048576
				echo "${serial:-0},${server_port:-0},$plugin,$((used / 1048576))/$((total / 1048576)) MB,$((used * 100 / total)) %,$quantity,${status:=停止}" >>$temp_file
			fi
			unset -v quantity used status
		done
		printTable ',' "$(cat $temp_file)"
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
	rm -f $net_file $temp_file
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
		ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"obfs-server\",\"plugin_opts\":\"obfs=$obfs\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^obfs-server|plugin_opts^obfs=$obfs|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "obfs-local;obfs=$obfs;obfs-host=checkappexec.microsoft.com")"
		;;
	kcptun)
		local kcp_nocomps kcp_acknodelays
		[ "$kcp_nocomp" = "true" ] && kcp_nocomps=';nocomp'
		[ "$kcp_acknodelay" = "true" ] && kcp_acknodelays=';acknodelay'
		if [[ $extra_parameters =~ ^[Yy]$ ]]; then
			ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun-server\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun-server|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp;nodelay=$kcp_nodelay;interval=$kcp_interval;resend=$kcp_resend;nc=$kcp_nc$kcp_nocomps$kcp_acknodelays")"
		else
			ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"kcptun-server\",\"plugin_opts\":\"key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps\"}" >/dev/null
			echo "server_port^$server_port|password^$password|method^$method|plugin^kcptun-server|plugin_opts^key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps|total^$((total * 1048576))" >>$HOME_DIR/port.list
			plugin_url="/?plugin=$(Url_encode "kcptun;key=$kcp_key;crypt=$kcp_crypt;mode=$kcp_mode;mtu=$kcp_mtu;sndwnd=$kcp_sndwnd;rcvwnd=$kcp_rcvwnd;datashard=$kcp_datashard;parityshard=$kcp_parityshard;dscp=$kcp_dscp$kcp_nocomps")"
		fi
		;;
	simple-tls)
		local tls_pds
		[ "$tls_pd" = "true" ] && tls_pds=';pd'
		ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"simple-tls\",\"plugin_opts\":\"s;key=$tls_key;cert=$tls_cert$tls_pds\"}" >/dev/null
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
		ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"${qui:=tcp_and_udp}\",\"plugin\":\"v2ray-plugin\",\"plugin_opts\":\"$v2ray_modes\"}" >/dev/null
		echo "server_port^$server_port|password^$password|method^$method|plugin^v2ray-plugin|plugin_opts^$v2ray_modes|total^$((total * 1048576))" >>$HOME_DIR/port.list
		plugin_url="/?plugin=$(Url_encode "v2ray-plugin;$v2ray_client")"
		;;
	*)
		ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\"}" >/dev/null
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
	echo
	echo -e "[\033[41;37mFBI WARNING\033[0m]\033[0;33m以上链接信息拿笔记好！！！\033[0m"
	echo
	if [ "$qrv4" ]; then
	    ssurl -d "$qrv4"
		qrencode -m 2 -l L -t ANSIUTF8 -k "$qrv4"
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
		echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
			Parsing_User "$line"
			if is_number $server_port && is_number $total; then
				if [[ $server_port -ne $port && $server_port -gt 0 && $server_port -lt 65535 && $password && $method && $total -gt 0 ]]; then
					echo "server_port^$server_port|password^$password|method^$method|plugin^$plugin|plugin_opts^$plugin_opts|total^$total" >>$temp_file
				fi
				if [ $server_port -eq $port ]; then
					ss-tool /run/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
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
			ss-tool /run/ss-manager.socket "remove: {\"server_port\":$port}" >/dev/null
			break
		fi
	done
}

Daemon() {
	echo $NOW_PID >/run/ss-daemon.pid
	while true; do
		if [ -r /run/ss-daemon.pid ]; then
			read PID </run/ss-daemon.pid
			if is_number $PID && [ $NOW_PID -eq $PID ]; then
				echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
					Parsing_User "$line"
					local flow=$(Used_traffic $server_port)
					if is_number $server_port && is_number $flow && is_number $total; then
						if [ ${flow:-0} -ge ${total:-0} ]; then
							Delete_users "$server_port" >/dev/null
						fi
						unset -v flow
					fi
				done
			else
				Exit
			fi
			sleep 1
		else
			Exit
		fi
	done
}

Start() {
	echo
	ssmanager \
		--log-without-time \
		--daemonize \
		--manager-address /run/ss-manager.socket \
		--acl $HOME_DIR/acl/server_block.acl \
		--daemonize-pid /run/ss-manager.pid \
		-U
	if [ -s $HOME_DIR/port.list ]; then
		echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
			Parsing_User "$line"
			local using=$(Used_traffic $server_port)
			if is_number $server_port && is_number $total && [ -z $using ] && [ $password -a $method ]; then
				if [ "$plugin" -a "$plugin_opts" ]; then
					echo -e "正在打开\033[32m $server_port \033[0m端口服务 传输插件 $plugin"
					if [[ $plugin == "kcptun-server" || $plugin_opts == *quic* ]]; then
						ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"mode\":\"tcp_only\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					else
						ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\",\"plugin\":\"$plugin\",\"plugin_opts\":\"$plugin_opts\"}" >/dev/null
					fi
				else
					echo -e "正在打开\033[32m $server_port \033[0m端口服务"
					ss-tool /run/ss-manager.socket "add: {\"server_port\":$server_port,\"password\":\"$password\",\"method\":\"$method\"}" >/dev/null
				fi
			fi
			unset -v using
		done
	else
		Prompt "没有找到端口列表文件..."
	fi
	(setsid ss-main daemon >/dev/null 2>&1 &)
	echo
}

Stop() {
	for i in /run/ss-manager.pid /run/ss-daemon.pid; do
		[ -s $i ] && read kpid <$i
		[ -d /proc/${kpid:=abcdefg} ] && kill $kpid && rm -f $i
	done
}

Update_core() {
	local temp_file=$(mktemp)
	Wget_get_files $temp_file $URL/update
	sed -i "s=*bin=$HOME_DIR/bin=" $temp_file
	echo
	sha512sum -c $temp_file
	if [ $? -ne 0 ]; then
		for x in ${Binary_file_list[@]} nginx; do
			rm -f $HOME_DIR/bin/$x
		done
		Check
		Prompt "请重新运行脚本以完成后续升级！"
		rm -f $temp_file
		Exit
	else
		rm -f $temp_file
		Prompt "未发现任何更新！"
		Press_any_key_to_continue
	fi
}

Uninstall() {
	Introduction "确定要卸载吗? (Y/N)"
	read -p "(默认: N): " -n1 delete
	if [[ $delete =~ ^[Yy]$ ]]; then
		Stop
		Close_traffic_forward
		rm -rf $HOME_DIR
		rm -f $0
		systemctl disable ss-main.service
		systemctl daemon-reload
		rm -f /etc/systemd/system/ss-main.service
		rm -f /run/ss-daemon.pid /run/ss-manager.pid /tmp/ss-client.socket /tmp/ssr-redir.conf /tmp/ss-debug.conf /run/ssr-redir.pid
		rm -f /usr/local/bin/ss-main
		Prompt "已全部卸载干净！"
		Exit
	else
		Prompt "已取消操作..."
	fi
	Press_any_key_to_continue
}

Speed_test() (
	if [ ! -f $HOME_DIR/bin/iperf3 ] || [ ! -x $HOME_DIR/bin/iperf3 ]; then
		Wget_get_files $HOME_DIR/bin/iperf3 $URL/tools/iperf3
		chmod +x $HOME_DIR/bin/iperf3
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
		ssserver --log-without-time --config $server_file --daemonize-pid $server_pid --daemonize
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
		sslocal --log-without-time --config $client_file --protocol tunnel --forward-addr 127.0.0.1:5201 --daemonize-pid $client_pid --daemonize
		temp=$(mktemp)
		#env \
		#PROXYCHAINS_CONF_FILE=$conf \
		#LD_PRELOAD_LD_PRELOAD=/usr/local/lib/libproxychains4.so \
		iperf3 --client 127.0.0.1 --port 1080 --version4 --logfile $temp --bytes 100M --zerocopy #iperf3用脚本运行太快了所以要sleep一会让其正常处理好数据防止出错，被这个坑了好久百思不得其解
		until [ "$(grep 'iperf Done.' $temp)" ]; do
			sleep 1
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
	[[ $link != "ssr://"* || -z $link ]] && continue
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
	pkill -F /run/ssr-redir.pid && rm -f /run/ssr-redir.pid
}

Start_traffic_forward() {
	[ ! -s /tmp/ssr-redir.conf ] && continue
	ssr-redir -c /tmp/ssr-redir.conf -f /run/ssr-redir.pid
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
	echo "server_port 1234 method aes-128-gcm password admin"
	ssserver --log-without-time --config /tmp/ss-debug.conf -v
}

Start_nginx_program() {
	Create_certificate

	if [ ! -f $HOME_DIR/bin/nginx ] || [ ! -x $HOME_DIR/bin/nginx ]; then
		Wget_get_files $HOME_DIR/bin/nginx $URL/tools/nginx
		chmod +x $HOME_DIR/bin/nginx
	fi
	if [ ! -d /var/log/nginx ]; then
		mkdir -p /var/log/nginx
	else
		rm -rf /var/log/nginx/*
	fi
	if [ ! -d /var/lib/nginx ]; then
		mkdir -p /var/lib/nginx
	else
		rm -rf /var/lib/nginx/*
	fi
	for i in client-body proxy fastcgi scgi uwsgi; do
		if [ ! -d /var/lib/nginx/$i ]; then
			mkdir -p /var/lib/nginx/$i
		fi
	done

	if [ -s $HOME_DIR/port.list ]; then
		rm -f $HOME_DIR/conf/v2ray_list.conf
		echo -e "$(cat $HOME_DIR/port.list)\n" | while IFS= read -r line; do
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
		Wget_get_files $HOME_DIR/conf/mime.types $URL/nginx/conf/mime.types
	fi
	for i in v2safe.conf security.conf v2ray-plugin.conf proxy.conf nginx.conf general.conf; do
		if [ ! -s $HOME_DIR/conf/$i ]; then
			Wget_get_files $HOME_DIR/conf/$i $URL/nginx/myself/$i
		fi
	done
	for i in 50x.html index.html; do
		if [ ! -s $HOME_DIR/web/$i ]; then
			Wget_get_files $HOME_DIR/web/$i $URL/nginx/html/$i
		fi
	done
	sed -i "/server_name/c\    server_name         $tls_common_name;" $HOME_DIR/conf/v2ray-plugin.conf
	if ! nginx -c $HOME_DIR/conf/nginx.conf -t; then
		Prompt "请检查nginx配置是否有误"
	else
		nginx -c $HOME_DIR/conf/nginx.conf
		Prompt "请将你的客户端v2ray插件websocket-http模式的节点服务器选项改为 \"你的域名或者CDN节点IP\" 端口改为 \"80\" 现在访问你的域名 http://$tls_common_name 应该可以看到nginx的首页了"
	fi
}

Advanced_features() {
	#https://lncn.org/ 免费节点
	if [ ! -f $HOME_DIR/bin/ssr-redir ] || [ ! -x $HOME_DIR/bin/ssr-redir ]; then
		Wget_get_files $HOME_DIR/bin/ssr-redir $URL/tools/ssr-redir
		chmod +x $HOME_DIR/bin/ssr-redir
	fi
	if [ "$common_install" ]; then
		for i in iptables ipset curl git; do
			if ! command_exists $i; then
				$common_install $i
			fi
		done
	fi
	while true; do
		Introduction "高级功能需熟读本脚本源码后再使用，否则后果自负！"
		local srd
		if [ -s /run/ssr-redir.pid ]; then
			read srd </run/ssr-redir.pid
		fi
		if [ -d /proc/${srd:=ssr-dir} ]; then
			echo -e "\033[1mssr-redir运行中 PID: \033[0m\033[7m$srd\033[0m"
		fi
		if [ -s /run/nginx.pid ]; then
			read ngx </run/nginx.pid
		fi
		if [ -d /proc/${ngx:=nginxx} ]; then
			echo -e "\033[1mnginx运行中 PID: \033[0m\033[7m$ngx\033[0m"
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
—————————————— CDN中转+Nginx分流 ——————————————
13. 开启Nginx
14. 关闭Nginx
15. 更新证书
16. 更换网站模板
EOF
		read -p $'请选择 \e[95m1-16\e[0m: ' -n2 action
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
			local google_ipv4_ranges=$(curl --silent --connect-timeout 5 https://md5calc.com/google/ip | grep -oE '([0-9]+\.){3}[0-9]+?\/[0-9]+?' | tr '\n' '@') && {
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
			Start_nginx_program
			;;
		14)
			pkill -F /run/nginx.pid && rm -f /run/nginx.pid
			;;
		15)
			Introduction "确定要更新吗?注意申请次数限制 (Y/N)"
			read -p "(默认: N): " -n1 delete
			if [[ $delete =~ ^[Yy]$ ]]; then
				rm -f $HOME_DIR/ssl/*
				Create_certificate
			else
				Prompt "已取消操作..."
			fi
			;;
		16)
			cat <<EOF
为防止伪装站点千篇一律，特意准备了以下模板
1. Mikutap
2. Flappy Winnie
3. FlappyFrog
4. bao
5. ninja
EOF
			read -p $'请选择 \e[95m1-5\e[0m: ' -n1 action
			is_number $action && [ $action -ge 1 -a $action -le 5 ] && {
				rm -rf $HOME_DIR/web
				case $action in
				1)
					git clone --depth 1 https://github.com/HFIProgramming/mikutap $HOME_DIR/web
					;;
				2)
					git clone --depth 1 https://github.com/hahaxixi/hahaxixi.github.io $HOME_DIR/web
					;;
				3)
					git clone --depth 1 https://github.com/hahaxixi/FlappyFrog $HOME_DIR/web
					;;
				4)
					git clone --depth 1 https://github.com/hahaxixi/bao $HOME_DIR/web
					;;
				5)
					git clone --depth 1 https://github.com/hahaxixi/ninja $HOME_DIR/web
					;;
				esac
			}
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
  5. 更新核心
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
			Press_any_key_to_continue
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
