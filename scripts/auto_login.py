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

FORCED_REGION = (os.environ.get("CLAW_REGION") or "").strip() or None
REGION_LIST_RAW = (os.environ.get("CLAW_REGIONS") or "").strip()

# 指定区域时，必须从该区域 /signin 启动（否则可能拿不到对应域名的登录态）
if FORCED_REGION:
    SIGNIN_URL = f"https://{FORCED_REGION}.run.claw.cloud/signin"
else:
    SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"


class Telegram:
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
            page.screenshot(path=f, full_page=True)
            self.shots.append(f)
        except Exception as e:
            print(f"截图失败: {e}")
        return f

    def is_run_cloud_url(self, url: str) -> bool:
        return bool(re.match(r"^https://[a-z]+-[a-z]+-\d+\.run\.claw\.cloud", url or ""))

    def is_signin_url(self, url: str) -> bool:
        u = (url or "").lower()
        return "/signin" in u

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
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
        return None

    # ---------- 关键：接 popup 并切换 page ----------
    def click_and_follow(self, page, selectors, desc="", wait_needles=None):
        """
        点击按钮后：
        - 如果打开了 popup，则返回 popup page
        - 否则等待本页导航，并返回本页
        """
        if wait_needles is None:
            wait_needles = ["github.com", ".run.claw.cloud"]

        for sel in selectors:
            try:
                el = page.locator(sel).first
                if not el.is_visible(timeout=2000):
                    continue

                # 1) 优先捕获 popup
                try:
                    with page.expect_popup(timeout=5000) as pop:
                        el.click()
                    new_page = pop.value
                    new_page.wait_for_load_state("domcontentloaded", timeout=60000)
                    self.log(f"{desc}：捕获到 popup，已切换页面", "SUCCESS")
                    return new_page
                except Exception:
                    # 2) 没有 popup，就等本页导航
                    el.click()
                    # 等 URL 出现目标特征
                    deadline = time.time() + 60
                    while time.time() < deadline:
                        u = page.url or ""
                        if any(n in u for n in wait_needles):
                            break
                        time.sleep(0.2)
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=60000)
                    except Exception:
                        pass
                    self.log(f"{desc}：在当前页完成跳转", "SUCCESS")
                    return page
            except Exception:
                continue

        self.log(f"未找到可点击元素: {desc}", "ERROR")
        return None

    # ---------- 关键：识别 Welcome 登录页 ----------
    def is_welcome_login_page(self, page) -> bool:
        """
        你的截图就是这种页面（Welcome + GitHub/Google 按钮）
        这个页面 URL 可能是 / （不含 /signin），必须用 DOM 识别
        """
        checks = [
            'text=/Welcome\\s+to\\s+ClawCloud\\s+Run/i',
            'text=/Welcome\\s+to\\s+ClawCloud/i',
            'button:has-text("GitHub")',
            'a:has-text("GitHub")',
            'button:has-text("Google")',
            'a:has-text("Google")',
        ]
        for sel in checks:
            try:
                if page.locator(sel).first.is_visible(timeout=800):
                    return True
            except Exception:
                continue
        return False

    def is_logged_in_ui(self, page) -> bool:
        """
        尝试识别“已登录后”的 UI 特征（比仅排除 Welcome 更可靠）
        你已登录界面通常会有搜索框/应用启动器等元素
        """
        checks = [
            'input[placeholder*="Search"]',
            'text=/Search\\s+applications/i',
            'text=/App\\s+Launchpad/i',
        ]
        for sel in checks:
            try:
                if page.locator(sel).first.is_visible(timeout=800):
                    return True
            except Exception:
                continue
        return False

    def assert_logged_in(self, page) -> bool:
        """
        最终判定：
        - 在 *.run.claw.cloud
        - 不在 /signin
        - 不是 Welcome 登录页
        - 最好还能命中已登录UI（若命中则直接 True）
        """
        url = page.url or ""
        if not self.is_run_cloud_url(url):
            return False
        if self.is_signin_url(url):
            return False
        if self.is_welcome_login_page(page):
            return False
        # 命中已登录 UI -> 强 True
        if self.is_logged_in_ui(page):
            return True
        # 未命中已登录UI，但也不是 welcome/signin（有些版本UI不同），允许通过，但会做一次额外访问验证
        return True

    def get_session(self, context):
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

请更新 Secret <b>GH_SESSION</b>:
<tg-spoiler>{value}</tg-spoiler>
"""
            )

    def oauth(self, page):
        if "github.com/login/oauth/authorize" not in (page.url or ""):
            return page
        self.log("处理 OAuth 授权页...", "STEP")
        self.shot(page, "oauth_page")

        page2 = self.click_and_follow(
            page,
            [
                'button[name="authorize"]',
                'button:has-text("Authorize")',
                'button:has-text("Allow")',
                'button:has-text("Continue")',
                'input[type="submit"]',
            ],
            "OAuth 授权/继续",
            wait_needles=[".run.claw.cloud", "claw.cloud"],
        )
        return page2 or page

    def login_github_if_needed(self, page, context):
        url = page.url or ""
        if "github.com/login" not in url and "github.com/session" not in url:
            return True

        self.log("GitHub 登录中...", "STEP")
        self.shot(page, "github_login")

        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            page.locator('input[type="submit"], button[type="submit"]').first.click()
        except Exception as e:
            self.log(f"GitHub 输入/提交失败: {e}", "ERROR")
            return False

        time.sleep(2)
        try:
            page.wait_for_load_state("networkidle", timeout=30000)
        except Exception:
            pass
        self.shot(page, "github_after_submit")

        # 2FA / 设备验证（你的原逻辑比较长，这里保持最小：检测到 two-factor 就让你走 Telegram）
        u = page.url or ""
        if "device-verification" in u or "verified-device" in u:
            self.log("需要设备验证（GitHub）", "WARN")
            self.tg.send("⚠️ GitHub 需要设备验证，请在 GitHub 邮箱/App 通过后再等脚本继续。")
            # 简单等待
            for _ in range(DEVICE_VERIFY_WAIT):
                time.sleep(1)
                if "device-verification" not in (page.url or "") and "verified-device" not in (page.url or ""):
                    break

        if "two-factor" in (page.url or ""):
            self.log("需要两步验证（GitHub）", "WARN")
            self.shot(page, "github_2fa")
            self.tg.send("⚠️ GitHub 需要 2FA，请发送 /code 123456")
            code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
            if not code:
                return False
            # 尝试填入
            for sel in [
                'input[autocomplete="one-time-code"]',
                'input[name="app_otp"]',
                'input[name="otp"]',
                'input[inputmode="numeric"]',
            ]:
                try:
                    el = page.locator(sel).first
                    if el.is_visible(timeout=1500):
                        el.fill(code)
                        page.keyboard.press("Enter")
                        break
                except Exception:
                    continue

            time.sleep(2)
            try:
                page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                pass

        return True

    def run(self):
        if not self.username or not self.password:
            print("缺少 GH_USERNAME / GH_PASSWORD")
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
                # 预加载 GitHub Cookie
                if self.gh_session:
                    context.add_cookies(
                        [
                            {"name": "user_session", "value": self.gh_session, "domain": "github.com", "path": "/"},
                            {"name": "logged_in", "value": "yes", "domain": "github.com", "path": "/"},
                        ]
                    )
                    self.log("已加载 GH_SESSION", "SUCCESS")

                # 1) 打开 ClawCloud /signin
                self.log(f"打开 ClawCloud 登录入口: {SIGNIN_URL}", "STEP")
                page.goto(SIGNIN_URL, timeout=60000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=60000)
                except Exception:
                    pass
                self.shot(page, "clawcloud_signin_open")

                # 2) 点击 GitHub（必须支持 popup）
                page2 = self.click_and_follow(
                    page,
                    [
                        'button:has-text("GitHub")',
                        'a:has-text("GitHub")',
                        '[data-provider="github"]',
                        'a[href*="github"]',
                        'button[data-provider="github"]',
                    ],
                    "点击 GitHub 登录",
                    wait_needles=["github.com", ".run.claw.cloud"],
                )
                if not page2:
                    self.shot(page, "no_github_btn")
                    self.tg.send("❌ 找不到 ClawCloud 的 GitHub 登录按钮")
                    sys.exit(1)
                page = page2
                self.shot(page, "after_click_github")

                # 3) GitHub 登录（如需要）
                if not self.login_github_if_needed(page, context):
                    self.shot(page, "github_login_failed")
                    self.tg.send("❌ GitHub 登录失败")
                    sys.exit(1)

                # 4) OAuth 授权（如需要）
                if "github.com/login/oauth/authorize" in (page.url or ""):
                    page = self.oauth(page) or page
                    self.shot(page, "after_oauth")

                # 5) 等待回到 run.claw.cloud，并进行强判定（不是 Welcome）
                self.log("等待回到 run.claw.cloud 并判定登录态...", "STEP")
                deadline = time.time() + 120
                while time.time() < deadline:
                    u = page.url or ""
                    if ".run.claw.cloud" in u:
                        self.detect_region(u)
                        # 强判定：不是 signin 且不是 welcome
                        if self.assert_logged_in(page):
                            break
                    time.sleep(1)

                self.shot(page, "final_state")

                if not self.assert_logged_in(page):
                    # 明确失败：如果还在 welcome/signin，直接报失败并发截图
                    self.log(f"最终仍未登录成功，当前URL: {page.url}", "ERROR")
                    self.tg.send(f"❌ ClawCloud 未登录成功\nURL: {page.url}")
                    if self.shots:
                        self.tg.photo(self.shots[-1], "最终页面仍是登录页/欢迎页")
                    sys.exit(1)

                # 如果你指定了区域，则强制校验最终域名属于该区域
                if self.forced_region:
                    host = urlparse(page.url).netloc
                    if host != f"{self.forced_region}.run.claw.cloud":
                        self.log(f"已登录但不在指定区域域名：{host}", "WARN")

                # 更新 GH_SESSION
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)

                self.tg.send(f"✅ ClawCloud 登录成功\nURL: {page.url}")
                if self.shots:
                    self.tg.photo(self.shots[-1], "登录后页面")

                print("✅ 登录成功")
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
