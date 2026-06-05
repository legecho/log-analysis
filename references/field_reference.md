# inforsec_qax_v10 字段参考

表名：`log.inforsec_qax_v10_all`  
来源：2026-05-15 实际查询结果，共 52 个字段

---

## 终端 & 网络基础信息

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `computer_name` | 终端主机名 | `LPT015846` |
| `ip` | 终端 IP | `10.134.12.51` |
| `mac` | 终端 MAC | `98-43-FA-41-87-19` |
| `report_ip` | 上报 IP | `172.17.65.165` |
| `group_name` | 终端所属组 | `独立组网` |
| `os_type` | 操作系统类型 | `1`（Windows） |
| `uuid` | 终端 UUID | `AE386035-472F-4FF8-B285-6CD34BCBE38B` |
| `user_session_id` | 用户会话 ID | `1` |
| `user_logon_id` | 用户登录 SID | `S-1-5-21-...-1008` |

---

## 事件元数据

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `timestamp` | 事件时间戳（UTC，ClickHouse 存储） | `2026-05-15 04:06:45` |
| `event_creation_date` | 事件创建时间（UTC，精确到毫秒） | `2026-05-15 04:05:48.895000000` |
| `event_type` | 事件类型 | `process_terminate` / `process_creation` |
| `type` | 日志分类 | `process_details` |
| `gid` | 事件 GID | `52a6b788d0000259` |
| `_log_increment_id` | 日志自增 ID | `2055137787253944321` |
| `mid` | 消息 ID（SHA256 级别） | `36fe8c47...` |
| `client_id` | 客户端 ID | `9505720-15bf1374649e1e73b5aaca0f6c54773a` |
| `asset_id` | 资产 ID | `2977686126002700609` |
| `asset_oid` | 资产 OID | `2715545271076390177` |

---

## 当前进程

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `process_name` | 进程文件名 | `cmd.exe` |
| `process_path` | 进程完整路径 | `C:\Windows\SysWOW64\cmd.exe` |
| `process_command_line` | 进程命令行 | `cmd.exe /C wmic path win32_VideoController get caption` |
| `process_id` | PID | `4360` |
| `process_guid` | 进程 GUID | `76920b8a8262f4d11a4cd84b97921fdf` |
| `process_md5` | 进程文件 MD5 | `d966dba31d7b62cad2decae92c5a8d12` |
| `process_sha1` | 进程文件 SHA1 | `0ab2ff188e8e6d624b60f6c164c4759a09079fe5` |
| `process_sign` | 数字签名 | `Microsoft Windows` |
| `process_user` | 运行用户 | `LPT015846\ctrip` |
| `process_integrity_level` | 完整性级别 | `High` |
| `process_current_directory` | 当前工作目录 | `C:\Windows\system32\` |
| `process_create_time` | 进程创建时间（Unix ms） | `1778817948485` |
| `process_terminate_time` | 进程结束时间（Unix ms） | `1778817948895` |
| `process_company` | 文件厂商 | `Microsoft Corporation` |
| `process_description` | 文件描述 | `Windows Command Processor` |
| `process_product` | 产品名称 | `Microsoft® Windows® Operating System` |
| `process_version` | 文件版本 | `10.0.19041.4355` |
| `process_internal_name` | 内部名称 | `cmd` |
| `process_original_name` | 原始文件名 | `Cmd.Exe` |
| `process_copyright` | 版权信息 | `© Microsoft Corporation. All rights reserved.` |

---

## 父进程

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `process_parent_name` | 父进程文件名 | `tndc32.exe` |
| `process_parent_path` | 父进程完整路径 | `C:\Program Files (x86)\LhpSafeView\Utils\tndc32.exe` |
| `process_parent_command_line` | 父进程命令行 | `"C:\Program Files (x86)\LhpSafeView\Utils\tndc32.exe" --dll=...` |
| `process_parent_id` | 父进程 PID | `2456` |
| `process_parent_guid` | 父进程 GUID | `b4a9a0b71bf4c895570bb84f335a5e83` |
| `process_parent_sign` | 父进程数字签名 | `Chengdu Qilu Technology Co. Ltd.` |
| `process_parent_internal_name` | 父进程内部名称 | `Extention` |
| `process_parent_original_name` | 父进程原始文件名 | `Extention.exe` |

---

## 父父进程（祖父进程）

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `process_pparent_name` | 父父进程文件名 | `SafeViewTray.exe` |
| `process_pparent_path` | 父父进程完整路径 | `C:\Program Files (x86)\LhpSafeView\SafeViewTray.exe` |
| `process_pparent_command_line` | 父父进程命令行 | `"C:\Program Files (x86)\LhpSafeView\SafeViewTray.exe" /autorun --from=task` |

---

## 根进程

| 字段名 | 说明 | 示例值 |
|---|---|---|
| `process_root_id` | 根进程 PID | `9736` |
| `process_root_guid` | 根进程 GUID | `c69dbeb9bd4e8e7f441802f56c487e1d` |

---

## 快捷参数对照（kibana_extract.py）

| CLI 参数 | 对应字段 | 匹配方式 |
|---|---|---|
| `--computer-name` | `computer_name` | 精确 |
| `--event-type` | `event_type` | 精确 |
| `--process-name` | `process_name` | 精确 |
| `--process-parent-name` | `process_parent_name` | 精确 |
| `--process-path-like` | `process_path` | LIKE |
| `--cmd-like` | `process_command_line` | LIKE |
| `--ip` | `ip` | 精确 |
| `--dst-ip` | `dst_ip_addr` | 精确 |
| `--dst-port` | `dst_port` | 精确 |
| `--group-name` | `group_name` | 精确 |
| `--process-md5` | `process_md5` | 精确 |
| `--process-user` | `process_user` | 精确 |
| `--protocol` | `network_protocol` | 精确 |
| `--log-type` | `type` | 精确 |
| `--dns-host` | `dns_host_name` | 精确 |
| `--report-ip` | `report_ip` | 精确 |

> **无快捷参数的字段**（需用 `--field "字段名=值"` 或 `--field "字段名 LIKE '%值%'"`）：
> `process_pparent_path`、`process_pparent_name`、`process_pparent_command_line`、
> `process_parent_path`、`process_parent_command_line`、`process_sha1`、`process_sign`、
> `process_parent_sign`、`process_integrity_level`、`process_guid`、`process_root_id` 等
