"""
ClawCloud 自动登录脚本
- 自动检测区域跳转（如 ap-southeast-1.run.claw.cloud）
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- Telegram 通知
"""

import base64
import os
import re
import sys
import time
from urllib.parse import urlparse

import requests
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
DEVICE_VERIFY_WAIT = 60
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))

# 指定区域：例如 ap-northeast-1
FORCED_REGION = (os.environ.get("CLAW_REGION") or "").strip() or None

# 多区域访问（仅访问，不作为成功判定）：例如 "us-east-1,ap-northeast-1"
REGION_LIST_RAW = (os.environ.get("CLAW_REGIONS") or "").strip()

# 入口 URL：如果指定区域，就从该区域 /signin 启动（很关键）
if FORCED_REGION:
    SIGNIN_URL = f"https://{FORCED_REGION}.run.claw.cloud/signin"
else:
    SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"


class Telegram:
    """Telegram 通知"""

    def __init__(self):
        self.token = os.environ.get("TG_BOT_TOKEN")
        self.chat_id = os.environ.get("TG_CHAT_ID")
        self.ok = bool(self.token and self.chat_id)

    def send(self, msg):
        if not self.ok:
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                data={"chat_id": self.chat_id, "text": msg, "parse_mode": "HTML"},
                timeout=30,
            )
        except Exception as e:
            print(f"Telegram发送消息失败: {e}")

    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            with open(path, "rb") as f:
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendPhoto",
                    data={"chat_id": self.chat_id, "caption": caption[:1024]},
                    files={"photo": f},
                    timeout=60,
                )
        except Exception as e:
            print(f"Telegram发送图片失败: {e}")

    def flush_updates(self):
        """刷新 offset 到最新，避免读到旧消息"""
        if not self.ok:
            return 0
        try:
            r = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"timeout": 0},
                timeout=10,
            )
            data = r.json()
            if data.get("ok") and data.get("result"):
                return data["result"][-1]["update_id"] + 1
        except Exception as e:
            print(f"刷新Telegram offset失败: {e}")
        return 0

    def wait_code(self, timeout=120):
        """
        等待你在 TG 里发 /code 123456
        只接受来自 TG_CHAT_ID 的消息
        """
        if not self.ok:
            return None

        offset = self.flush_updates()
        deadline = time.time() + timeout
        pattern = re.compile(r"^/code\s+(\d{6,8})$")

        while time.time() < deadline:
            try:
                r = requests.get(
                    f"https://api.telegram.org/bot{self.token}/getUpdates",
                    params={"timeout": 20, "offset": offset},
                    timeout=30,
                )
                data = r.json()
                if not data.get("ok"):
                    time.sleep(2)
                    continue

                for upd in data.get("result", []):
                    offset = upd["update_id"] + 1
                    msg = upd.get("message") or {}
                    chat = msg.get("chat") or {}
                    if str(chat.get("id")) != str(self.chat_id):
                        continue

                    text = (msg.get("text") or "").strip()
                    m = pattern.match(text)
                    if m:
                        return m.group(1)
            except Exception as e:
                print(f"等待Telegram验证码异常: {e}")

            time.sleep(2)

        return None


class SecretUpdater:
    """GitHub Secret 更新器"""

    def __init__(self):
        self.token = os.environ.get("REPO_TOKEN")
        self.repo = os.environ.get("GITHUB_REPOSITORY")
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")

    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public

            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
            }

            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers,
                timeout=30,
            )
            if r.status_code != 200:
                print(f"获取公钥失败，状态码: {r.status_code}")
                return False

            key_data = r.json()
            pk = public.PublicKey(key_data["key"].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())

            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={
                    "encrypted_value": base64.b64encode(encrypted).decode(),
                    "key_id": key_data["key_id"],
                },
                timeout=30,
            )
            return r.status_code in [201, 204]
        except Exception as e:
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    def __init__(self):
        self.username = os.environ.get("GH_USERNAME")
        self.password = os.environ.get("GH_PASSWORD")
        self.gh_session = os.environ.get("GH_SESSION", "").strip()

        self.tg = Telegram()
        self.secret = SecretUpdater()

        self.shots = []
        self.logs = []
        self.n = 0

        self.detected_region = None
        self.region_base_url = None

        self.forced_region = FORCED_REGION
        self.forced_base_url = f"https://{self.forced_region}.run.claw.cloud" if self.forced_region else None

        self.region_list = []
        if REGION_LIST_RAW:
            self.region_list = [x.strip() for x in REGION_LIST_RAW.split(",") if x.strip()]

    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        self.logs.append(line)

    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except Exception as e:
            print(f"截图失败: {e}")
        return f

    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=3000):
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except Exception:
                continue
        self.log(f"未找到可点击的元素: {desc}", "ERROR")
        return False

    def wait_for_url_contains_any(self, page, needles, timeout=120000) -> bool:
        deadline = time.time() + (timeout / 1000.0)
        while time.time() < deadline:
            u = page.url or ""
            if any(n in u for n in needles):
                return True
            time.sleep(0.2)
        return False

    def is_signin_url(self, url: str) -> bool:
        u = (url or "").lower()
        if "/signin" in u:
            return True
        if "github.com" not in u and "/login" in u:
            return True
        return False

    def is_run_cloud_url(self, url: str) -> bool:
        return bool(re.match(r"^https://[a-z]+-[a-z]+-\d+\.run\.claw\.cloud", url or ""))

    def detect_region(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.netloc

            if host.endswith(".run.claw.cloud") and host != "run.claw.cloud":
                region = host.replace(".run.claw.cloud", "")
                self.detected_region = region
                self.region_base_url = f"https://{host}"
                self.log(f"检测到区域(run.claw.cloud): {region}", "SUCCESS")
                self.log(f"区域 URL: {self.region_base_url}", "INFO")
                return region

            return None
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None

    def get_base_url(self):
        # 指定区域优先，其次检测到的区域，否则使用当前 SIGNIN_URL 对应域名
        if self.forced_base_url:
            return self.forced_base_url
        if self.region_base_url:
            return self.region_base_url
        # 从 SIGNIN_URL 推断 base
        try:
            p = urlparse(SIGNIN_URL)
            return f"{p.scheme}://{p.netloc}"
        except Exception:
            return "https://us-east-1.run.claw.cloud"

    def get_session(self, context):
        """提取 GitHub user_session"""
        try:
            for c in context.cookies():
                if c.get("name") == "user_session" and "github.com" in (c.get("domain") or ""):
                    return c.get("value")
        except Exception as e:
            self.log(f"提取Cookie失败: {e}", "WARN")
        return None

    def save_cookie(self, value):
        if not value:
            return
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")

        if self.secret.update("GH_SESSION", value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存")
        else:
            self.tg.send(
                f"""🔑 <b>新 Cookie</b>

请更新 Secret <b>GH_SESSION</b> (点击查看):
<tg-spoiler>{value}</tg-spoiler>
"""
            )
            self.log("已通过 Telegram 发送 Cookie", "SUCCESS")

    # ======== 关键新增：识别 “run.claw.cloud 根路径登录页/欢迎页” ========
    def is_clawcloud_welcome_login_ui(self, page) -> bool:
        """
        你的截图就是这种页面：Welcome + GitHub/Google 按钮。
        这个页面 URL 往往是 /（不含 /signin），如果不识别就会误判“已登录”
        """
        selectors = [
            'text=Welcome to ClawCloud Run',
            'text=Welcome to ClawCloud',
            'button:has-text("GitHub")',
            'a:has-text("GitHub")',
            'button:has-text("Google")',
            'a:has-text("Google")',
        ]
        for sel in selectors:
            try:
                if page.locator(sel).first.is_visible(timeout=800):
                    return True
            except Exception:
                continue
        return False

    def assert_runcloud_logged_in(self, page) -> bool:
        """
        最终判定（你要求的规则 + 修复误判）：
        1) URL 是 *.run.claw.cloud
        2) 不在 /signin
        3) 页面不是 Welcome 登录页（有 GitHub/Google 按钮等）
        """
        url = page.url or ""
        if not self.is_run_cloud_url(url):
            return False
        if self.is_signin_url(url):
            return False
        # 关键：排除根路径 Welcome 登录页
        if self.is_clawcloud_welcome_login_ui(page):
            return False
        return True

    # ======== GitHub 登录/2FA/OAuth（保留你原来的逻辑，略微增强 OAuth 按钮选择） ========
    def wait_device(self, page):
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")

        self.tg.send(
            f"""⚠️ <b>需要设备验证</b>

请在 {DEVICE_VERIFY_WAIT} 秒内批准：
1️⃣ 检查邮箱点击链接
2️⃣ 或在 GitHub App 批准"""
        )
        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")

        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                url = page.url or ""
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒) {url}", "INFO")

                if "github.com/login/oauth/authorize" in url:
                    self.log("设备验证通过，跳转到OAuth授权页！", "SUCCESS")
                    self.tg.send("✅ <b>设备验证通过，跳转到OAuth授权</b>")
                    return True

                if "verified-device" not in url and "device-verification" not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    self.tg.send("✅ <b>设备验证通过</b>")
                    return True

                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state("domcontentloaded", timeout=10000)
                except Exception as e:
                    self.log(f"刷新页面失败: {e}", "WARN")

        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ <b>设备验证超时</b>")
        return False

    def wait_two_factor_mobile(self, page):
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(
            f"""⚠️ <b>需要两步验证（GitHub Mobile）</b>

请打开手机 GitHub App 批准本次登录（会让你确认一个数字）。
等待时间：{TWO_FACTOR_WAIT} 秒"""
        )
        if shot:
            self.tg.photo(shot, "两步验证页面（数字在图里）")

        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            url = page.url or ""

            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                self.tg.send("✅ <b>两步验证通过</b>")
                return True

            if "github.com/login" in url:
                self.log("两步验证后回到了登录页，需重新登录", "ERROR")
                return False

            if i % 30 == 0 and i != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state("domcontentloaded", timeout=30000)
                except Exception as e:
                    self.log(f"刷新两步验证页面失败: {e}", "WARN")

        self.log("两步验证超时", "ERROR")
        self.tg.send("❌ <b>两步验证超时</b>")
        return False

    def handle_2fa_code_input(self, page):
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")

        self.tg.send(
            f"""🔐 <b>需要验证码登录</b>

用户 {self.username} 正在登录，请在 Telegram 里发送：
<code>/code 你的6位验证码</code>

等待时间：{TWO_FACTOR_WAIT} 秒"""
        )
        if shot:
            self.tg.photo(shot, "两步验证页面")

        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        if not code:
            self.log("等待验证码超时", "ERROR")
            self.tg.send("❌ <b>等待验证码超时</b>")
            return False

        selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name="app_otp"]',
            'input[name="otp"]',
            "input#app_totp",
            "input#otp",
            'input[inputmode="numeric"]',
        ]

        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.fill(code)
                    time.sleep(1)

                    for btn_sel in ['button:has-text("Verify")', 'button[type="submit"]', 'input[type="submit"]']:
                        try:
                            btn = page.locator(btn_sel).first
                            if btn.is_visible(timeout=1000):
                                btn.click()
                                break
                        except Exception:
                            continue
                    else:
                        page.keyboard.press("Enter")

                    time.sleep(2)
                    try:
                        page.wait_for_load_state("networkidle", timeout=30000)
                    except Exception:
                        pass

                    if "github.com/sessions/two-factor/" not in (page.url or ""):
                        self.log("验证码验证通过！", "SUCCESS")
                        self.tg.send("✅ <b>验证码验证通过</b>")
                        return True

                    self.log("验证码可能错误", "ERROR")
                    self.tg.send("❌ <b>验证码可能错误，请检查后重试</b>")
                    return False
            except Exception:
                continue

        self.log("没找到验证码输入框", "ERROR")
        self.tg.send("❌ <b>没找到验证码输入框</b>")
        return False

    def oauth(self, page):
        """OAuth 授权页（增强按钮匹配，避免文案变化）"""
        if "github.com/login/oauth/authorize" not in (page.url or ""):
            return

        self.log("处理 OAuth...", "STEP")
        self.shot(page, "oauth")

        # 常见授权按钮
        btns = [
            'button[name="authorize"]',
            'button:has-text("Authorize")',
            'button:has-text("Authorize")',
            'input[name="authorize"]',
            'input[type="submit"]',
        ]
        clicked = self.click(page, btns, "OAuth 授权")  # 复用 click
        if not clicked:
            # 有时会是 “Continue” 或 “Allow”
            self.click(page, ['button:has-text("Continue")', 'button:has-text("Allow")'], "OAuth Continue/Allow")

        time.sleep(2)
        try:
            page.wait_for_load_state("networkidle", timeout=30000)
        except Exception:
            pass

    def login_github(self, page, context):
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")

        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False

        self.shot(page, "github_已填写")

        try:
            page.locator('input[type="submit"], button[type="submit"]').first.click()
        except Exception as e:
            self.log(f"点击提交按钮失败: {e}", "ERROR")

        time.sleep(2)
        try:
            page.wait_for_load_state("networkidle", timeout=30000)
        except Exception:
            pass
        self.shot(page, "github_登录后")

        url = page.url or ""
        self.log(f"当前: {url}", "INFO")

        if "verified-device" in url or "device-verification" in url:
            if not self.wait_device(page):
                return False

        if "two-factor" in (page.url or ""):
            self.log("需要两步验证！", "WARN")
            self.shot(page, "两步验证")

            if "two-factor/mobile" in (page.url or ""):
                if not self.wait_two_factor_mobile(page):
                    return False
            else:
                if not self.handle_2fa_code_input(page):
                    return False

        return True

    def wait_redirect(self, page, wait=120):
        """
        等待重定向：
        只要跳到 run.claw.cloud，且不是 signin，并且不是 Welcome 登录页，才算成功
        """
        self.log("等待重定向...", "STEP")

        for i in range(wait):
            url = page.url or ""
            if i % 5 == 0:
                self.log(f"重定向检测: {url} (第{i}秒)", "INFO")

            if "github.com/login/oauth/authorize" in url:
                self.oauth(page)

            if self.is_run_cloud_url(url):
                self.detect_region(url)

                # 关键：这里直接用“最终判定”规则，避免 root 登录页误判
                if self.assert_runcloud_logged_in(page):
                    self.log("重定向到 run.claw.cloud 且通过登录态判定", "SUCCESS")
                    return True

                # 如果仍然是 signin 或 welcome 登录页，继续触发登录
                if self.is_signin_url(url) or self.is_clawcloud_welcome_login_ui(page):
                    self.log("到达 run.claw.cloud，但仍是未登录页面（signin/welcome），尝试重新触发 GitHub 登录", "WARN")
                    # 在 ClawCloud 页面再点一次 GitHub
                    self.click(
                        page,
                        ['button:has-text("GitHub")', 'a:has-text("GitHub")', '[data-provider="github"]'],
                        "ClawCloud 页面触发 GitHub 登录",
                    )
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=30000)
                    except Exception:
                        pass

            time.sleep(1)

        self.log("重定向超时", "ERROR")
        return False

    def keepalive(self, page):
        """
        保活访问（仅访问）
        """
        self.log("保活...", "STEP")

        main_base = self.get_base_url()
        self.log(f"主区域 URL: {main_base}", "INFO")

        visit_bases = [main_base]
        if self.region_list:
            for r in self.region_list:
                u = f"https://{r}.run.claw.cloud"
                if u not in visit_bases:
                    visit_bases.append(u)

        for base_url in visit_bases:
            for url, name in [(f"{base_url}/", "控制台"), (f"{base_url}/apps", "应用")]:
                try:
                    page.goto(url, timeout=60000, wait_until="domcontentloaded")
                    try:
                        page.wait_for_load_state("networkidle", timeout=30000)
                    except Exception:
                        pass
                    cur = page.url or ""
                    self.log(f"已访问: {name} ({url}) -> {cur}", "SUCCESS")
                    if "run.claw.cloud" in cur:
                        self.detect_region(cur)
                    time.sleep(1)
                except Exception as e:
                    self.log(f"访问 {name} 失败: {e}", "WARN")

        self.shot(page, "完成")

    def notify(self, ok, err=""):
        if not self.tg.ok:
            return

        region_show = self.forced_region or self.detected_region or "未检测"
        msg = f"""<b>🤖 ClawCloud 自动登录</b>

<b>状态:</b> {"✅ 成功" if ok else "❌ 失败"}
<b>用户:</b> {self.username}
<b>区域:</b> {region_show}
<b>时间:</b> {time.strftime('%Y-%m-%d %H:%M:%S')}"""

        if err:
            msg += f"\n<b>错误:</b> {err}"

        msg += "\n\n<b>日志:</b>\n" + "\n".join(self.logs[-6:])
        self.tg.send(msg)

        if self.shots:
            if not ok:
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                self.tg.photo(self.shots[-1], "完成")

    def run(self):
        print("\n" + "=" * 50)
        print("🚀 ClawCloud 自动登录（修复误判版）")
        print("=" * 50 + "\n")

        self.log(f"用户名: {self.username}", "INFO")
        self.log(f"Session: {'有' if self.gh_session else '无'}", "INFO")
        self.log(f"密码: {'有' if self.password else '无'}", "INFO")
        self.log(f"入口: {SIGNIN_URL}", "INFO")
        if self.forced_region:
            self.log(f"已指定区域: {self.forced_region}", "INFO")

        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            context = browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                ),
            )
            page = context.new_page()

            try:
                # 预加载 GitHub Cookie（只对 github.com 生效）
                if self.gh_session:
                    try:
                        context.add_cookies(
                            [
                                {"name": "user_session", "value": self.gh_session, "domain": "github.com", "path": "/"},
                                {"name": "logged_in", "value": "yes", "domain": "github.com", "path": "/"},
                            ]
                        )
                        self.log("已加载 GH Session Cookie", "SUCCESS")
                    except Exception as e:
                        self.log(f"加载 Cookie 失败: {e}", "WARN")

                # 1) 打开 ClawCloud 登录页（指定区域时是该区域 /signin）
                self.log("步骤1: 打开 ClawCloud 登录页", "STEP")
                page.goto(SIGNIN_URL, timeout=60000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=60000)
                except Exception:
                    pass
                time.sleep(1)
                self.shot(page, "clawcloud_open")
                self.log(f"当前 URL: {page.url}", "INFO")

                # 2) 点击 GitHub
                self.log("步骤2: 点击 GitHub", "STEP")
                if not self.click(
                    page,
                    ['button:has-text("GitHub")', 'a:has-text("GitHub")', '[data-provider="github"]'],
                    "GitHub",
                ):
                    self.notify(False, "找不到 GitHub 按钮")
                    sys.exit(1)

                # 等待跳到 GitHub / OAuth / 或回到 run.claw.cloud
                if not self.wait_for_url_contains_any(
                    page,
                    ["github.com/login", "github.com/session", "github.com/login/oauth/authorize", ".run.claw.cloud"],
                    timeout=120000,
                ):
                    self.shot(page, "click_github_no_jump")
                    self.notify(False, "点击 GitHub 后未跳转")
                    sys.exit(1)

                try:
                    page.wait_for_load_state("domcontentloaded", timeout=120000)
                except Exception:
                    pass
                self.shot(page, "after_click_github")
                url = page.url or ""
                self.log(f"当前: {url}", "INFO")

                # 3) GitHub 登录 / OAuth
                self.log("步骤3: GitHub 认证", "STEP")
                if "github.com/login" in url or "github.com/session" in url:
                    if not self.login_github(page, context):
                        self.shot(page, "github_login_failed")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                if "github.com/login/oauth/authorize" in (page.url or ""):
                    self.oauth(page)

                # 4) 等待重定向并通过“非signin + 非welcome页”判定
                self.log("步骤4: 等待重定向并判定登录态", "STEP")
                if not self.wait_redirect(page):
                    self.shot(page, "redirect_failed")
                    self.notify(False, "重定向失败/仍未登录")
                    sys.exit(1)

                self.shot(page, "redirect_ok")

                # 5) 最终强判定
                self.log("步骤5: 最终判定", "STEP")
                if not self.assert_runcloud_logged_in(page):
                    self.shot(page, "final_check_failed")
                    self.notify(False, "最终仍是未登录页面（signin/welcome）")
                    sys.exit(1)

                self.log("判定成功：run.claw.cloud 且非 signin 且非 welcome 登录页", "SUCCESS")

                # 6) 保活访问（可选多区域）
                self.keepalive(page)

                # 7) 更新 GH_SESSION（仅 GitHub Cookie，不等于 ClawCloud 登录 Cookie）
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 GH_SESSION", "WARN")

                self.notify(True)
                print("\n✅ 成功！\n")

            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.shot(page, "exception")
                import traceback

                traceback.print_exc()
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()

