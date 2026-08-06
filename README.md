# ZTE EPG Public

把运营商（山东联通 · 中兴 IPTV）的 EPG 节目单转换为标准 **XMLTV** 格式，定时发布到 GitHub，让任意支持 XMLTV 的软件（DIYP、百川、TiviMate、IPTV Pro 等）直接填入公共链接即可使用。

> 频道与节目单数据来自运营商 IPTV 平台，仅供个人学习研究使用，请勿用于商业用途。

## 公共链接

| 类型 | 链接 |
| --- | --- |
| GitHub Raw（gz） | `https://raw.githubusercontent.com/<你的用户名>/zte-epg-public/main/epg.xml.gz` |
| GitHub Raw（xml） | `https://raw.githubusercontent.com/<你的用户名>/zte-epg-public/main/epg.xml` |
| jsDelivr CDN（gz，推荐） | `https://cdn.jsdelivr.net/gh/<你的用户名>/zte-epg-public@main/epg.xml.gz` |
| jsDelivr CDN（xml） | `https://cdn.jsdelivr.net/gh/<你的用户名>/zte-epg-public@main/epg.xml` |

把上面的链接填进软件的「EPG 地址」即可。gz 版体积更小（约 320KB，xml 约 5MB），加载更快；部分老软件不支持 gz，可改用 xml 链接。

## 数据说明

- 更新频率：每天 06:00 和 18:00（北京时间）自动拉取，覆盖最近 7 天节目单。
- 节目单约 175 个频道（CCTV 全系列、各卫视、山东本地台、付费频道等），3 万+ 条节目。
- 频道 id 为运营商内部 channelcode（如 `ch00000000000000001128`），display-name 为中文频道名。部分软件需要按频道名匹配，多数软件自动匹配 `display-name`，无法匹配的可在软件内手动绑定。

## 本地手动运行

```bash
pip install -r requirements.txt
ZTE_ENCRYPT_KEY=xxxx ZTE_USER_ID=xxxx ZTE_STB_ID=xxxx \
ZTE_MAC=xx:xx:xx:xx:xx:xx ZTE_MODEL=E900V21C \
python3 collect_epg.py
```

运行完生成 `epg.xml` 和 `epg.xml.gz`。

## 部署到自己的仓库

1. Fork / 复制本仓库，设为 **公开仓库**。
2. 在仓库 `Settings → Secrets and variables → Actions` 添加以下 Secrets（凭证取自你的运营商账号，务必保密，**不要写进代码**）：

| Secret | 说明 |
| --- | --- |
| `ZTE_EAS_IP` | 鉴权网关 IP（如 `124.132.240.38`） |
| `ZTE_EAS_PORT` | 鉴权网关端口（默认 `8080`） |
| `ZTE_ENCRYPT_KEY` | DES 加密密钥 |
| `ZTE_USER_ID` | 用户 ID |
| `ZTE_STB_ID` | 机顶盒 ID |
| `ZTE_MAC` | 机顶盒 MAC |
| `ZTE_MODEL` | 机顶盒型号（如 `E900V21C`） |

3. 首次可到 `Actions → Update EPG → Run workflow` 手动触发一次验证。
4. 之后每天自动运行，`epg.xml.gz` 会自动更新并提交。

> 公开仓库的 Secrets 只对仓库 owner/管理员可见，fork 分支的 Pull Request 无法读取，安全机制由 GitHub 保障。但请勿把凭证写进 README、issue 或任何提交内容。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ZTE_EAS_IP` | `124.132.240.38` | 鉴权网关 IP |
| `ZTE_EAS_PORT` | `8080` | 鉴权网关端口 |
| `ZTE_ENCRYPT_KEY` | 无 | DES 加密密钥（必填） |
| `ZTE_USER_ID` | 无 | 用户 ID（必填） |
| `ZTE_STB_ID` | 无 | 机顶盒 ID |
| `ZTE_MAC` | 无 | 机顶盒 MAC |
| `ZTE_MODEL` | 无 | 机顶盒型号 |
| `ZTE_CUSTOM_STR` | `$CTC` | 自定义串 |
| `ZTE_OUTPUT_DIR` | `.` | 输出目录 |
| `ZTE_DAYS` | `7` | 拉取天数 |
| `ZTE_MAX_CONCURRENCY` | `10` | 并发数 |

## 工作原理

```
运营商 IPTV 服务器
   │  3 步鉴权（getencrypttoken → auth.jsp → funcportalauth）
   │  拉取 getchannelprogram（175 频道 × 7 天）
   ▼
collect_epg.py ──→ epg.xml / epg.xml.gz（标准 XMLTV）
   │
   ▼
GitHub Actions（每天 06:00 / 18:00）──→ 推送到公开仓库
   │
   ▼
任意软件填入 raw / jsDelivr 链接即可用
```

鉴权流程移植自 FongMi TV（ZTESpider），请求需带 `Content-Type: application/x-www-form-urlencoded`，否则服务器返回 `errorcode=50991006`。

## 免责声明

本项目仅用于个人学习研究，数据版权归运营商所有。请遵守当地法律法规，勿将本项目用于商业或非法用途。
