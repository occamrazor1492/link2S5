import streamlit as st
import json
import os
import base64
import socket
import time
import subprocess
import requests
from urllib.parse import urlparse, unquote, parse_qs

# ==========================================
# 🔐 核心安全参数 (请核对 SSH 端口)
# ==========================================
ADMIN_IP = "38.246.242.146"  # 你的白名单 IP
PANEL_PORT = 8501            # 面板端口
SSH_PORT = 22                # ⚠️ 必须核对！如果改过 SSH 端口请务必修改此处

# --- 全局路径配置 ---
DB_NODES = "nodes_db.json"
DB_FORWARD = "forward_db.json"
DB_FIREWALL = "firewall_db.json"
SINGBOX_CONFIG = "/etc/sing-box/config.json"

# ==========================================
# 核心工具函数
# ==========================================

def run_cmd(cmd):
    """执行 Shell 命令并返回结果"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0, result.stdout + result.stderr
    except Exception as e:
        return False, str(e)

def init_panel_security():
    """
    【核心防御逻辑】
    实施 "Default Deny" 策略：
    1. 先允许必要的 (Lo, SSH, Established, ICMP)
    2. 跳转到面板锁链
    3. 跳转到业务防火墙链
    4. ⚠️ 最后丢弃所有其他包 (DROP ALL)
    """
    # ----------------------
    # 1. 准备自定义链
    # ----------------------
    run_cmd("iptables -N PANEL_GUARD 2>/dev/null")
    run_cmd("iptables -F PANEL_GUARD")
    run_cmd("iptables -N STREAMLIT_FW 2>/dev/null")
    # 注意：这里不清空 STREAMLIT_FW，因为业务规则可能在运行中动态加载，
    # 但如果是初始化，可以清空，我们在 apply_firewall_rules 里会重写它。
    
    # ----------------------
    # 2. 重置 INPUT 链结构 (危险操作，需按顺序)
    # ----------------------
    # 为了防止断连，我们采用 "先加白名单，最后加 DROP" 的策略，而不是直接改 Policy
    
    # [A] 允许 Established/Related (至关重要！否则 VPS 无法访问外部网络/更新/时间同步)
    run_cmd("iptables -D INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 1 -m state --state ESTABLISHED,RELATED -j ACCEPT")
    
    # [B] 允许本地回环 Lo
    run_cmd("iptables -D INPUT -i lo -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 2 -i lo -j ACCEPT")
    
    # [C] 允许 SSH (防失联)
    run_cmd(f"iptables -D INPUT -p tcp --dport {SSH_PORT} -j ACCEPT 2>/dev/null")
    run_cmd(f"iptables -I INPUT 3 -p tcp --dport {SSH_PORT} -j ACCEPT")

    # [D] 允许 ICMP (Ping) - 可选，方便检测延迟
    run_cmd("iptables -D INPUT -p icmp -j ACCEPT 2>/dev/null")
    run_cmd("iptables -I INPUT 4 -p icmp -j ACCEPT")

    # [E] 插入面板锁链 (Layer 1)
    run_cmd("iptables -D INPUT -j PANEL_GUARD 2>/dev/null")
    run_cmd("iptables -I INPUT 5 -j PANEL_GUARD")

    # [F] 插入业务防火墙链 (Layer 2)
    run_cmd("iptables -D INPUT -j STREAMLIT_FW 2>/dev/null")
    run_cmd("iptables -I INPUT 6 -j STREAMLIT_FW")
    
    # [G] ⚠️ 兜底规则：拒绝所有其他流量 (DROP ALL)
    # 先删除可能存在的旧 DROP 规则，确保只有一条且在最后
    run_cmd("iptables -D INPUT -j DROP 2>/dev/null")
    run_cmd("iptables -A INPUT -j DROP")

    # ----------------------
    # 3. 配置面板锁 (PANEL_GUARD)
    # ----------------------
    run_cmd(f"iptables -A PANEL_GUARD -p tcp --dport {PANEL_PORT} -s {ADMIN_IP} -j ACCEPT")
    # 如果不匹配上面，就 return 回 INPUT 链，然后被最后的 DROP 杀掉
    # 但为了更明确，我们可以在这里直接 DROP 面板端口的其他连接
    run_cmd(f"iptables -A PANEL_GUARD -p tcp --dport {PANEL_PORT} -j DROP")

def check_connectivity(server, port, timeout=2):
    try:
        with socket.create_connection((server, port), timeout=timeout): return True, "Online"
    except: return False, "Offline"

def load_db(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f: return json.load(f)
    return []

def save_db(filepath, data):
    with open(filepath, "w") as f: json.dump(data, f, indent=2)

# ==========================================
# 模块 1: Sing-box 解析 (保留)
# ==========================================
class NodeParser:
    @staticmethod
    def parse_vmess(link, remark):
        try:
            data = json.loads(base64.b64decode(link[8:] + '==').decode())
            outbound = {
                "type": "vmess", "server": data['add'], "server_port": int(data['port']),
                "uuid": data['id'], "security": data.get('scy', 'auto'), "alter_id": int(data.get('aid', 0))
            }
            if data.get('net') == "ws":
                outbound["transport"] = {"type": "ws", "path": data.get('path', '/'), "headers": {"Host": data.get('host', '')}}
            return outbound, remark
        except: return None, remark
    
    @staticmethod
    def parse_vless(link, remark):
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        final_remark = unquote(parsed.fragment) if parsed.fragment else remark
        outbound = {
            "type": "vless", "server": parsed.hostname, "server_port": int(parsed.port),
            "uuid": parsed.username, "flow": params.get('flow', [None])[0]
        }
        if params.get('security', [''])[0] in ['reality', 'tls']:
            outbound["tls"] = {"enabled": True, "server_name": params.get('sni', [None])[0], "utls": {"enabled": True, "fingerprint": params.get('fp', ['chrome'])[0]}}
            if params.get('security', [''])[0] == 'reality':
                outbound["tls"]["reality"] = {"enabled": True, "public_key": params.get('pbk', [''])[0], "short_id": params.get('sid', [''])[0]}
        return outbound, final_remark

    @staticmethod
    def parse_hy2(link, remark):
        parsed = urlparse(link)
        final_remark = unquote(parsed.fragment) if parsed.fragment else remark
        outbound = {
            "type": "hysteria2", "server": parsed.hostname, "server_port": int(parsed.port),
            "password": parsed.username, "tls": {"enabled": True, "server_name": parse_qs(parsed.query).get('sni', [None])[0], "insecure": True}
        }
        return outbound, final_remark

    @staticmethod
    def parse_ss(link, remark):
        try:
            if '#' in link: final_remark = unquote(link.split('#')[1]); link = link.split('#')[0]
            else: final_remark = remark
            payload = link.split('ss://')[1]
            if '@' in payload:
                u, s = payload.split('@')
                info = base64.b64decode(u + '==').decode().split(':')
                server, port = s.split(':')
                return {"type": "shadowsocks", "server": server, "server_port": int(port), "method": info[0], "password": info[1]}, final_remark
            else:
                d = base64.b64decode(payload + '==').decode().split('@')
                info = d[0].split(':')
                server, port = d[1].split(':')
                return {"type": "shadowsocks", "server": server, "server_port": int(port), "method": info[0], "password": info[1]}, final_remark
        except: return None, remark

def process_singbox_import(text):
    nodes = []
    for line in text.split('\n'):
        line = line.strip()
        if not line or line.startswith('#'): continue
        res = None
        if line.startswith('vmess://'): res, rem = NodeParser.parse_vmess(line, "新节点")
        elif line.startswith('vless://'): res, rem = NodeParser.parse_vless(line, "新节点")
        elif line.startswith('hysteria2://'): res, rem = NodeParser.parse_hy2(line, "新节点")
        elif line.startswith('ss://'): res, rem = NodeParser.parse_ss(line, "新节点")
        if res:
            res['remark'] = rem
            res['assigned_port'] = 0 
            nodes.append(res)
    return nodes

# ==========================================
# 模块 2: 端口转发逻辑
# ==========================================
def apply_iptables_forward(rules):
    run_cmd("iptables -t nat -N STREAMLIT_FWD 2>/dev/null") 
    run_cmd("iptables -t nat -F STREAMLIT_FWD")
    run_cmd("iptables -t nat -C PREROUTING -j STREAMLIT_FWD 2>/dev/null || iptables -t nat -I PREROUTING -j STREAMLIT_FWD")
    run_cmd("iptables -t nat -C POSTROUTING -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -j MASQUERADE")
    for r in rules:
        if r.get('enabled', True):
            dest = f"{r['remote_ip']}:{r['remote_port']}"
            run_cmd(f"iptables -t nat -A STREAMLIT_FWD -p tcp --dport {r['local_port']} -j DNAT --to-destination {dest}")
            run_cmd(f"iptables -t nat -A STREAMLIT_FWD -p udp --dport {r['local_port']} -j DNAT --to-destination {dest}")

# ==========================================
# 模块 3: 业务防火墙逻辑 (Default Deny 模式)
# ==========================================
def apply_firewall_rules(rules):
    run_cmd("iptables -F STREAMLIT_FW") # 清空业务链
    
    # 在这个模式下，STREAMLIT_FW 只需要全是 ACCEPT 规则。
    # 因为如果包没有被 ACCEPT，它会返回到 INPUT 链，
    # 最终被 INPUT 链底部的 "DROP ALL" 规则杀掉。
    
    port_rules = {}
    for r in rules:
        if not r.get('enabled', True): continue
        if r['port'] not in port_rules: port_rules[r['port']] = []
        if r.get('allow_ip'): port_rules[r['port']].append(r['allow_ip'])
        else: port_rules[r['port']].append("ALL")

    for port, ips in port_rules.items():
        if "ALL" in ips:
            run_cmd(f"iptables -A STREAMLIT_FW -p tcp --dport {port} -j ACCEPT")
            run_cmd(f"iptables -A STREAMLIT_FW -p udp --dport {port} -j ACCEPT")
        else:
            for ip in ips:
                run_cmd(f"iptables -A STREAMLIT_FW -p tcp --dport {port} -s {ip} -j ACCEPT")
                run_cmd(f"iptables -A STREAMLIT_FW -p udp --dport {port} -s {ip} -j ACCEPT")
            # 不需要再加 DROP，因为默认兜底就是 DROP

# ==========================================
# 程序入口
# ==========================================
st.set_page_config(page_title="VPS 堡垒机控制台", layout="wide", page_icon="🛡️")

# 启动安全初始化 (每次运行脚本都会确保 DROP ALL 在最后)
init_panel_security()

st.title("🛡️ VPS 堡垒机 (Default Deny 模式)")

if 'nodes_db' not in st.session_state: st.session_state.nodes_db = load_db(DB_NODES)
if 'forward_db' not in st.session_state: st.session_state.forward_db = load_db(DB_FORWARD)
if 'firewall_db' not in st.session_state: st.session_state.firewall_db = load_db(DB_FIREWALL)

with st.sidebar:
    st.error(f"🛑 默认策略: 拒绝所有入站流量")
    st.success(f"✅ 白名单: SSH({SSH_PORT}), 面板({PANEL_PORT})")
    st.header("⚙️ 基础配置")
    auth_user = st.text_input("Socks5 账号", "admin")
    auth_pass = st.text_input("Socks5 密码", "pass123", type="password")
    
    with st.expander("🚑 紧急：更新面板白名单IP"):
        new_admin = st.text_input("新 IP", value=ADMIN_IP)
        if st.button("更新"):
            run_cmd(f"iptables -R PANEL_GUARD 1 -p tcp --dport {PANEL_PORT} -s {new_admin} -j ACCEPT")
            st.warning("规则已更新。")

tab1, tab2, tab3 = st.tabs(["🔄 Sing-box 中转", "🔀 纯端口转发", "🧱 业务防火墙"])

# --- TAB 1: Sing-box ---
with tab1:
    with st.expander("📥 导入"):
        raw_input = st.text_area("粘贴链接", height=100)
        if st.button("导入"):
            st.session_state.nodes_db.extend(process_singbox_import(raw_input))
            save_db(DB_NODES, st.session_state.nodes_db); st.rerun()
    if st.button("🧹 清空"): st.session_state.nodes_db = []; save_db(DB_NODES, []); st.rerun()

    for idx, node in enumerate(st.session_state.nodes_db):
        status = "🟢" if node.get('is_online') else ("🔴" if node.get('is_online') is False else "⚪")
        p_val = node.get('assigned_port') if node.get('assigned_port') != 0 else "未设置"
        with st.expander(f"{status} 端口: {p_val} ➜ {node.get('remark', '未命名')}"):
            c1, c2, c3 = st.columns([3, 1.5, 1])
            c1.caption(f"目标: {node['server']}:{node['server_port']}")
            new_p = c2.number_input("Socks5端口", value=int(node.get('assigned_port', 0)), key=f"sb_{idx}")
            if new_p != node.get('assigned_port'): node['assigned_port'] = new_p; save_db(DB_NODES, st.session_state.nodes_db)
            if c3.button("删除", key=f"del_{idx}"): st.session_state.nodes_db.pop(idx); save_db(DB_NODES, st.session_state.nodes_db); st.rerun()

    if st.button("🚀 部署 Sing-box", type="primary"):
        ports = [n['assigned_port'] for n in st.session_state.nodes_db if n['assigned_port']!=0]
        if len(ports) != len(set(ports)): st.error("端口冲突")
        elif any(p == 0 for p in ports) or len(ports) != len(st.session_state.nodes_db): st.error("有节点未设置端口")
        else:
            inb, outb, rules = [], [], []
            online = 0
            prog = st.progress(0)
            for i, n in enumerate(st.session_state.nodes_db):
                alive, lat = check_connectivity(n['server'], n['server_port'])
                n['is_online'] = alive
                if alive:
                    tag = str(n['assigned_port'])
                    inb.append({"type":"socks","tag":"in_"+tag,"listen":"0.0.0.0","listen_port":n['assigned_port'],"users":[{"username":auth_user,"password":auth_pass}]})
                    n_c = {k:v for k,v in n.items() if k not in ['remark','is_online','assigned_port']}
                    n_c['tag'] = "out_"+tag
                    outb.append(n_c); rules.append({"inbound":["in_"+tag],"outbound":"out_"+tag})
                    online += 1
                prog.progress((i+1)/len(st.session_state.nodes_db))
            save_db(DB_NODES, st.session_state.nodes_db)
            if online:
                with open(SINGBOX_CONFIG, "w") as f: json.dump({"log":{"level":"info"},"inbounds":inb,"outbounds":outb,"route":{"rules":rules}}, f, indent=2)
                os.system("pkill -9 sing-box; systemctl restart sing-box")
                st.success(f"已部署 {online} 个节点"); st.warning("⚠️ 请记得在[业务防火墙]中放行这些端口！"); time.sleep(1); st.rerun()
            else: st.error("无可用节点")

# --- TAB 2: Forward ---
with tab2:
    with st.form("fwd"):
        c1, c2, c3 = st.columns(3)
        lp = c1.number_input("本地端口", 20000); rip = c2.text_input("IP"); rp = c3.number_input("端口", 443)
        if st.form_submit_button("添加"):
            st.session_state.forward_db.append({"local_port":lp,"remote_ip":rip,"remote_port":rp,"enabled":True}); save_db(DB_FORWARD, st.session_state.forward_db); st.rerun()
    for idx, r in enumerate(st.session_state.forward_db):
        c1, c2, c3 = st.columns([1,4,1])
        if c1.checkbox("启用", r['enabled'], key=f"fen_{idx}") != r['enabled']: r['enabled'] = not r['enabled']; save_db(DB_FORWARD, st.session_state.forward_db)
        c2.code(f"{r['local_port']} -> {r['remote_ip']}:{r['remote_port']}")
        if c3.button("删", key=f"fdel_{idx}"): st.session_state.forward_db.pop(idx); save_db(DB_FORWARD, st.session_state.forward_db); st.rerun()
    if st.button("⚡ 应用转发"): apply_iptables_forward(st.session_state.forward_db); st.success("已更新，请记得防火墙放行该端口！")

# --- TAB 3: Firewall ---
with tab3:
    st.info("💡 提示：所有未在此处列出的端口，默认都会被丢弃。")
    with st.form("fw"):
        c1, c2 = st.columns([1,3])
        p = c1.number_input("放行端口", 10001)
        ip = c2.text_input("允许IP (留空则允许所有)")
        if st.form_submit_button("添加规则"):
            st.session_state.firewall_db.append({"port":p,"allow_ip":ip,"enabled":True}); save_db(DB_FIREWALL, st.session_state.firewall_db); st.rerun()
    for idx, r in enumerate(st.session_state.firewall_db):
        c1, c2, c3 = st.columns([1,4,1])
        if c1.checkbox("启用", r['enabled'], key=f"wen_{idx}") != r['enabled']: r['enabled'] = not r['enabled']; save_db(DB_FIREWALL, st.session_state.firewall_db)
        c2.text(f"端口: {r['port']} | {'允许: '+r['allow_ip'] if r['allow_ip'] else '⚠️ 允许所有'}")
        if c3.button("删", key=f"wdel_{idx}"): st.session_state.firewall_db.pop(idx); save_db(DB_FIREWALL, st.session_state.firewall_db); st.rerun()
    if st.button("🛡️ 应用规则"): apply_firewall_rules(st.session_state.firewall_db); st.success("规则已生效")
    
    with st.expander("🔍 验证：查看底层规则"):
        st.code(run_cmd("iptables -L INPUT -n --line-numbers")[1])