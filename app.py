import streamlit as st
import json
import os
import base64
import socket
import time
import subprocess
from urllib.parse import urlparse, unquote, parse_qs

# --- 文件路径配置 ---
DB_FILE = "nodes_db.json"
SINGBOX_CONFIG = "/etc/sing-box/config.json"

# --- 连通性检测逻辑 ---
def check_connectivity(server, port, timeout=2):
    try:
        start_time = time.time()
        with socket.create_connection((server, port), timeout=timeout):
            latency = int((time.time() - start_time) * 1000)
            return True, f"{latency}ms"
    except Exception:
        return False, "不可达"

# --- 节点解析引擎 ---
class NodeParser:
    @staticmethod
    def parse_vmess(link, remark):
        try:
            data = json.loads(base64.b64decode(link[8:] + '==').decode())
            outbound = {
                "type": "vmess", "server": data['add'], "server_port": int(data['port']),
                "uuid": data['id'], "security": data.get('scy', 'auto'),
                "alter_id": int(data.get('aid', 0))
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
        security = params.get('security', [''])[0]
        if security in ['reality', 'tls']:
            outbound["tls"] = {"enabled": True, "server_name": params.get('sni', [None])[0], "utls": {"enabled": True, "fingerprint": params.get('fp', ['chrome'])[0]}}
            if security == 'reality':
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
            if '#' in link:
                final_remark = unquote(link.split('#')[1])
                link = link.split('#')[0]
            else: final_remark = remark
            payload = link.split('ss://')[1]
            if '@' in payload:
                userinfo_part, server_part = payload.split('@')
                userinfo = base64.b64decode(userinfo_part + '==').decode()
                method, password = userinfo.split(':')
                server, port = server_part.split(':')
            else:
                decoded = base64.b64decode(payload + '==').decode()
                userinfo, server_part = decoded.split('@')
                method, password = userinfo.split(':')
                server, port = server_part.split(':')
            return {"type": "shadowsocks", "server": server, "server_port": int(port), "method": method, "password": password}, final_remark
        except: return None, remark

def process_input(text):
    nodes = []
    lines = text.split('\n')
    remark_buffer = []
    for line in lines:
        line = line.strip()
        if not line: continue
        if line.startswith('#'):
            remark_buffer.append(line.lstrip('#').strip())
            continue
        current_remark = " | ".join(remark_buffer) if remark_buffer else "新节点"
        res = None
        if line.startswith('vmess://'): res, actual_remark = NodeParser.parse_vmess(line, current_remark)
        elif line.startswith('vless://'): res, actual_remark = NodeParser.parse_vless(line, current_remark)
        elif line.startswith('hysteria2://'): res, actual_remark = NodeParser.parse_hy2(line, current_remark)
        elif line.startswith('ss://'): res, actual_remark = NodeParser.parse_ss(line, current_remark)
        
        if res:
            res['remark'] = actual_remark
            res['assigned_port'] = 0 # 初始为0，提醒用户手动输入
            nodes.append(res)
            remark_buffer = []
    return nodes

# --- Streamlit 界面 ---
st.set_page_config(page_title="Sing-box Manual Port Relay", layout="wide")
st.title("🛡️ Sing-box 手动指定端口中转站")

if os.path.exists(DB_FILE):
    with open(DB_FILE, "r") as f: st.session_state.db = json.load(f)
else: st.session_state.db = []

with st.sidebar:
    st.header("⚙️ 认证配置")
    auth_user = st.text_input("Socks5 账号", "admin")
    auth_pass = st.text_input("Socks5 密码", "pass123", type="password")
    
    st.divider()
    st.header("📥 批量导入")
    raw_input = st.text_area("粘贴链接", height=200)
    if st.button("📥 导入", use_container_width=True):
        new_nodes = process_input(raw_input)
        st.session_state.db.extend(new_nodes)
        with open(DB_FILE, "w") as f: json.dump(st.session_state.db, f, indent=2)
        st.rerun()
    
    if st.button("🗑️ 清空所有节点", type="secondary", use_container_width=True):
        st.session_state.db = []
        if os.path.exists(DB_FILE): os.remove(DB_FILE)
        st.rerun()

# --- 列表管理 ---
st.subheader(f"节点列表 ({len(st.session_state.db)})")

for idx, node in enumerate(st.session_state.db):
    status = node.get('is_online', None)
    icon = "⚪" if status is None else ("🟢" if status else "🔴")
    display_port = node.get('assigned_port') if node.get('assigned_port') != 0 else "未设置"
    
    with st.expander(f"{icon} 监听端口: {display_port} ➜ {node['remark']} [{node.get('latency', '')}]"):
        col_main, col_port, col_del = st.columns([3, 1.5, 1])
        
        with col_main:
            st.write(f"目标: `{node['server']}:{node['server_port']}` | 类型: `{node['type']}`")
        
        with col_port:
            # 用户在此处手动输入并锁定端口
            new_p = st.number_input("指定 Socks5 端口", value=node.get('assigned_port', 0), key=f"p_input_{idx}", min_value=0, max_value=65535)
            if new_p != node.get('assigned_port'):
                node['assigned_port'] = new_p
                with open(DB_FILE, "w") as f: json.dump(st.session_state.db, f, indent=2)
                st.toast(f"端口已更新为 {new_p}")
        
        with col_del:
            if st.button("删除节点", key=f"del_{idx}"):
                st.session_state.db.pop(idx)
                with open(DB_FILE, "w") as f: json.dump(st.session_state.db, f, indent=2)
                st.rerun()

# --- 部署逻辑 ---
st.divider()
if st.button("🚀 强制检测并同步应用", type="primary", use_container_width=True):
    # 检查是否有重复端口或未设置端口
    all_ports = [n.get('assigned_port') for n in st.session_state.db if n.get('assigned_port') != 0]
    if len(all_ports) != len(set(all_ports)):
        st.error("❌ 错误：检测到重复的端口设置，请修改后再部署！")
    elif any(n.get('assigned_port') == 0 for n in st.session_state.db):
        st.error("❌ 错误：存在未设置端口的节点，请填写端口号！")
    else:
        inbounds, outbounds, rules = [], [], []
        progress = st.progress(0)
        
        for i, n in enumerate(st.session_state.db):
            is_alive, lat_msg = check_connectivity(n['server'], n['server_port'])
            n['is_online'], n['latency'] = is_alive, lat_msg
            
            if is_alive:
                port = n['assigned_port']
                tag_in, tag_out = f"in_{port}", f"out_{port}"
                inbounds.append({
                    "type": "socks", "tag": tag_in, "listen": "0.0.0.0", "listen_port": port,
                    "users": [{"username": auth_user, "password": auth_pass}]
                })
                n_cfg = {k: v for k, v in n.items() if k not in ['remark', 'is_online', 'latency', 'assigned_port']}
                n_cfg['tag'] = tag_out
                outbounds.append(n_cfg)
                rules.append({"inbound": [tag_in], "outbound": tag_out})
            
            progress.progress((i + 1) / len(st.session_state.db))

        with open(DB_FILE, "w") as f: json.dump(st.session_state.db, f, indent=2)

        if not inbounds:
            st.error("所有节点均不可达，未更新配置。")
        else:
            config = {"log": {"level": "info"}, "inbounds": inbounds, "outbounds": outbounds, "route": {"rules": rules}}
            with open(SINGBOX_CONFIG, "w") as f: json.dump(config, f, indent=2)
            
            os.system("pkill -9 sing-box")
            time.sleep(0.5)
            os.system("systemctl restart sing-box")
            st.success("✅ 部署完成！仅在线节点已按指定端口开启。")
            st.rerun()

# --- 日志与预览 ---
st.divider()
tab1, tab2 = st.tabs(["📝 实时日志", "📄 配置预览"])
with tab1:
    st.code(os.popen("journalctl -u sing-box -n 20 --no-pager").read(), language="text")
with tab2:
    if os.path.exists(SINGBOX_CONFIG):
        with open(SINGBOX_CONFIG, "r") as f: st.json(json.load(f))