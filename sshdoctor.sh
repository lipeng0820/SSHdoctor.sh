#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "请以root身份运行此脚本。" 
    exit 1
fi

if [[ -e /etc/debian_version ]]; then
    LOGFILE="/var/log/auth.log"
elif [[ -e /etc/redhat-release ]]; then
    LOGFILE="/var/log/secure"
else
    echo "不支持的操作系统"
    exit 1
fi

# 护驾
decrypt_key() {
    echo "$1" | openssl enc -aes-256-cbc -a -d -salt -pass pass:"$2" -pbkdf2
}

# 定义用于生成SSH登录报告的函数
generate_ssh_report() {
    echo "======== SSH 尝试登录统计 ========"

    # 总尝试次数
    TOTAL_ATTEMPTS=$(grep "Failed password" $LOGFILE | wc -l)
    echo "总尝试登录次数: $TOTAL_ATTEMPTS"
    echo
    echo "======== 扫描次数TOP20的IP ========"
    grep "Failed password" $LOGFILE | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -20
}

# 定义用于检查端口是否被使用的函数
is_port_used() {
    ss -tuln | grep -q ":$1 "
}

# 定义用于管理ufw的函数
manage_ufw() {
    # 检查ufw是否已安装
    if ! command -v ufw &> /dev/null; then
        echo "ufw未安装，正在为您安装..."
        if [[ -e /etc/debian_version ]]; then
            apt update && apt install -y ufw
        elif [[ -e /etc/redhat-release ]]; then
            yum install -y ufw
        else
            echo "不支持的操作系统"
            exit 1
        fi
    fi

    clear
    if ufw status verbose | grep "^Status: active" > /dev/null; then
        echo "防火墙状态: 启用"
        ALLOWED_PORTS=$(ufw status | sed -n '/^To/,/^$/p' | grep ALLOW | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
        DENIED_PORTS=$(ufw status | sed -n '/^To/,/^$/p' | grep DENY | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
    else
        echo "防火墙状态: 关闭"
        ALLOWED_PORTS="无"
        DENIED_PORTS="无"
    fi

    # 如果变量为空，则设置为"无"
    [ -z "$ALLOWED_PORTS" ] && ALLOWED_PORTS="无"
    [ -z "$DENIED_PORTS" ] && DENIED_PORTS="无"

    echo "当前已放行（Allow）的端口为: $ALLOWED_PORTS"
    echo "当前已禁止（Deny）的端口为: $DENIED_PORTS"
    echo "1. 批量放行10000-10100端口"
    echo "2. 批量禁用10000-10100端口"
    echo "3. 手动放行端口"
    echo "4. 手动禁用端口"
    echo "5. 返回上一级"
    echo "请选择一个操作:"
    read -r ufw_choice

    case $ufw_choice in
    1)  
        for port in $(seq 10000 10100); do
            ufw allow "$port"
        done
        echo "已批量放行10000-10100端口"
        ;;
    2)  
        for port in $(seq 10000 10100); do
            ufw deny "$port"
        done
        echo "已批量禁用10000-10100端口"
        ;;
    3)  
        echo "请输入要放行的端口(使用英文逗号','隔开):"
        read -r ports
        IFS=',' read -ra ADDR <<< "$ports"
        for port in "${ADDR[@]}"; do
            if [[ $port -ge 10000 && $port -le 65535 ]]; then
                ufw allow "$port"
            else
                echo "端口 $port 无效，已忽略"
            fi
        done
        ;;
    4)  
        echo "请输入要禁用的端口(使用英文逗号','隔开):"
        read -r ports
        IFS=',' read -ra ADDR <<< "$ports"
        for port in "${ADDR[@]}"; do
            if [[ $port -ge 10000 && $port -le 65535 ]]; then
                ufw deny "$port"
            else
                echo "端口 $port 无效，已忽略"
            fi
        done
        ;;
    5)
        ;;
    *)  
        echo "无效选择!"
        read -rp "按任意键返回上一级..." key
        ;;
    esac
}

MAIN_MENU=true
while $MAIN_MENU; do
    clear
    echo "==== 主菜单 ===="
    echo "1. 查看本机SSH登录报告"
    echo "2. 启用/关闭SSH登录功能"
    echo "3. 启用/关闭ufw系统防火墙"
    echo "4. 更改SSH端口"
    echo "0. 退出脚本"
    echo "请选择一个操作:"
    read -r choice

    case $choice in
    1)  
        clear
        generate_ssh_report
        echo
        echo "1. 保存报告至根目录"
        echo "2. 清空当前登录尝试系统日志"
        echo "3. 返回上一级"
        echo "请选择一个操作:"
        read -r subchoice

        case $subchoice in
        1)  
            generate_ssh_report > "$HOME/analyze_ssh_attempts.log"
            echo "报告已保存到 $HOME/analyze_ssh_attempts.log"
            read -rp "按任意键返回上一级..." key
            ;;
        2)  
            echo "警告: 清空系统登录日志是一个危险操作!"
            echo "您确定要继续吗? (Y/N)"
            read -r confirm
            if [[ $confirm == 'Y' || $confirm == 'y' ]]; then
                cp $LOGFILE $LOGFILE.bak
                echo "备份日志为 $LOGFILE.bak"
                > $LOGFILE
                echo "登录日志已清空"
            fi
            read -rp "按任意键返回上一级..." key
            ;;
        3)  
            ;;
        *)  
            echo "无效选择!"
            read -rp "按任意键返回上一级..." key
            ;;
        esac
        ;;

    2)
        clear
        if grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config; then
            echo "当前登录模式为: SSH登录"
        else
            echo "当前登录模式为: 私钥登录"
        fi
        echo "1. 关闭SSH登录（使用lipeng16的公钥）"
        echo "2. 开启SSH登录"
        echo "3. 返回上一级"
        echo "请选择一个操作:"
        read -r subchoice

        case $subchoice in
        1)  
            # 关闭密码登录
            sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
            sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
            
            # 确保root只能使用密钥登录
            sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
            sed -i 's/^#PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config
            
            mkdir -p "$HOME/.ssh"
            
            # 提示用户输入解密密码
            echo "请输入解密公钥的密码："
            read -s DECRYPTION_PASSWORD

            # 解密并启用私钥登录
            ENCRYPTED_KEY="U2FsdGVkX1/3gT7ZnUKfwayYSWBNnavgKuc3k/YRKGPdguaNwNQBFM5CA9m2s18r
            VXwz0RSPWCnil2p+GKwylTLv+6s1JQRnTauCCMJpUp7pgol283cV4ckJuHPNDVe4
            i9ZtIcIU53D6idgDRAHE+bpU79Y9C1cYZJ/7DtaInt/cXFHzWsDpJ71njwffY0Ih
            Sks+QdLd7Spe2TAK8edw+V1q8lzKM9HJFy67amp2yAy2O+MFjWlK+zbJ3ihTLZ3p
            3VKlNyykKn65Ey07RTRx3yVsCDjafSapWkOGDghmUKvZHtZPE3CwQ7CICUfHnfhU
            LLNl7GTqMX3wOLKksAWjddfdXVKiDr/C94cG71Ne5sZaN8VWGxlPuVcmxlbipdTs
            fslY0N/R12ca+FcX8DqAlmOVC0A5bbVI4gd/NPM+kkzqA6MryL8UaDHTIsdNeiVw
            s2XvgxYsa5GnMcdKATxiEGdL8uOqx6kvjd3YMiZUdzljTn8vdvuL+yQjYRLDPWvS
            21jfuH0dSSKbKYuOZR8V4r7SbjMqeldAhWAG+o6xINPGP15t2z5S+Fy0VCP15Em8"
            DECRYPTED_KEY=$(decrypt_key "$ENCRYPTED_KEY" "$DECRYPTION_PASSWORD")
            echo "$DECRYPTED_KEY" >> "$HOME/.ssh/authorized_keys"
            chmod 600 "$HOME/.ssh/authorized_keys"

            # 重启SSH服务
            if [[ -e /etc/debian_version ]]; then
                systemctl restart ssh
            elif [[ -e /etc/redhat-release ]]; then
                systemctl restart sshd
            fi
            echo "已关闭SSH密码登录并启用lipeng16的私钥登录"
            read -rp "按任意键返回上一级..." key
            ;;
        2)  
            # 开启密码登录
            sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config

            # 重启SSH服务
            if [[ -e /etc/debian_version ]]; then
                systemctl restart ssh
            elif [[ -e /etc/redhat-release ]]; then
                systemctl restart sshd
            fi
            echo "已开启SSH登录"
            read -rp "按任意键返回上一级..." key
            ;;
        3)  
            ;;
        *)  
            echo "无效选择!"
            read -rp "按任意键返回上一级..." key
            ;;
        esac
        ;;

    3)
        manage_ufw
        read -rp "按任意键返回上一级..." key
        ;;

    4)
        clear
        current_port=$(sshd -T | grep "port " | awk '{print $2}')
        echo "当前端口号: $current_port"
        echo "1. 更改端口号"
        echo "2. 恢复默认端口号22"
        echo "3. 返回上一级"
        echo "请选择一个操作:"
        read -r subchoice

        case $subchoice in
        1)  
            if ! is_port_used 12322; then
                echo "提示: 端口12322当前未被使用，您可以考虑使用它作为SSH端口"
            fi
            while true; do
                echo "请输入一个在10000-65535范围内的端口号:"
                read -r new_port

                if [[ $new_port -ge 10000 && $new_port -le 65535 ]]; then
                    if ! is_port_used "$new_port"; then
                        sed -i "s/^Port [0-9]*$/Port $new_port/" /etc/ssh/sshd_config
                        if [[ -e /etc/debian_version ]]; then
                            systemctl restart ssh
                        elif [[ -e /etc/redhat-release ]]; then
                            systemctl restart sshd
                        fi
                        echo "SSH端口已更改为 $new_port"
                        break
                    else
                        echo "端口 $new_port 已被使用，请选择其他端口"
                    fi
                else
                    echo "无效的端口号，请重新输入"
                fi
            done
            read -rp "按任意键返回上一级..." key
            ;;
        2)  
            sed -i "s/^Port.*/Port 22/g" /etc/ssh/sshd_config
            if [[ -e /etc/debian_version ]]; then
                systemctl restart ssh
            elif [[ -e /etc/redhat-release ]]; then
                systemctl restart sshd
            fi
            echo "SSH端口已恢复为默认的22"
            read -rp "按任意键返回上一级..." key
            ;;
        3)  
            ;;
        *)  
            echo "无效选择!"
            read -rp "按任意键返回上一级..." key
            ;;
        esac
        ;;
    0)
        MAIN_MENU=false
        ;;
    *)
        echo "无效选择!"
        read -rp "按任意键继续..." key
        ;;
    esac
done
