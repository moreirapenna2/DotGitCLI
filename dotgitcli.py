import re, requests, sys, urllib3
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WS_SEARCH = re.compile(r'(ws)(s)?://')
WS_REPLACE = "http$2://"

GIT_PATH = "/.git/"
GIT_HEAD_PATH = GIT_PATH + "HEAD"
GIT_CONFIG_PATH = GIT_PATH + "config"
GIT_HEAD_HEADER = "ref: refs/heads/"

SVN_PATH = "/.svn/"
SVN_DB_PATH = SVN_PATH + "wc.db"
SVN_DB_HEADER = "SQLite"

HG_PATH = "/.hg/"
HG_MANIFEST_PATH = HG_PATH + "store/00manifest.i"
HG_MANIFEST_HEADERS = [
    "\u0000\u0000\u0000\u0001",
    "\u0000\u0001\u0000\u0001",
    "\u0000\u0002\u0000\u0001",
    "\u0000\u0003\u0000\u0001",
]

ENV_PATH = "/.env"
ENV_SEARCH = "^[A-Z_]+=|^[#\\n\\r ][\\s\\S]*^[A-Z_]+="

GIT_OBJECTS_SEARCH = "[a-f0-9]{40}"
GIT_CONFIG_SEARCH = "url = (.*(github\\.com|gitlab\\.com).*)"

SECURITYTXT_PATHS = [
    "/.well-known/security.txt",
    "/security.txt",
]
SECURITYTXT_SEARCH = "Contact: "

def isValidUrl(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def checkGit(url, session):
    to_check = url + GIT_HEAD_PATH
    search = re.compile(GIT_OBJECTS_SEARCH)

    try:
        response = session.get(to_check, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            text = response.text
            if text != False and (text.startswith(GIT_HEAD_HEADER) or search.match(text)):
                # .git found
                print(f"[+] Found an exposed .git: {to_check}")
                return True
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def checkSvn(url, session):
    to_check = url + SVN_DB_PATH

    try:
        response = session.get(to_check, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            text = response.text
            if text != False and text.startswith(SVN_DB_HEADER):
                # .svn found
                print(f"[+] Found an exposed .svn: {to_check}")
                return True
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def checkHg(url, session):
    to_check = url + HG_MANIFEST_PATH

    try:
        response = session.get(to_check, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            text = response.text
            if text != False and (
                text.startswith(HG_MANIFEST_HEADERS[0]) or
                text.startswith(HG_MANIFEST_HEADERS[1]) or
                text.startswith(HG_MANIFEST_HEADERS[2]) or
                text.startswith(HG_MANIFEST_HEADERS[3])
            ):
                # .hg found
                print(f"[+] Found an exposed .hg: {to_check}")
                return True
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def checkEnv(url, session):
    to_check = url + ENV_PATH
    search = re.compile(ENV_SEARCH)

    try:
        response = session.get(to_check, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            text = response.text
            if text != False and search.search(text):
                # .env found
                print(f"[+] Found an exposed .env: {to_check}")
                print(text)
                return True
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def escapeRegExp(string, session):
    return re.sub(r'[.*+?^${}()|[\]\\]', '\\$&', string)

def isOpenSource(url, session):
    configUrl = checkGitConfig(url, session)

    if configUrl != False:
        str = configUrl.replace("github.com:", "github.com/")
        str = str.replace("gitlab.com:", "gitlab.com/")
        if str.startswith("ssh://"):
            str = str[6:]
        if str.startswith("git@"):
            str = str[4:]
        if str.endswith(".git"):
            str = str[:-4]
        if not str.startswith("http"):
            str = "https://" + str

        if isValidUrl(str):
            return checkOpenSource(str, session)

    return False

def checkGitConfig(url, session):
    to_check = url + GIT_CONFIG_PATH
    search = re.compile(GIT_CONFIG_SEARCH)

    try:
        response = session.get(to_check, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            text = response.text
            if text != False:
                print(f"[+] Found an exposed .git/config: {to_check}")
                print(text)
                result = search.search(text)
                if result:
                    result = result.group(1)
                    return result
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def checkOpenSource(url, session):
    try:
        response = session.get(url, allow_redirects=False, timeout=10)

        if response.status_code == 200:
            print(f"[+] Found an open source project: {url}")
            return True
    except requests.exceptions.Timeout:
        # Timeouts if the request takes longer than X seconds
        print("Timeout error")

    return False

def checkSecuritytxt(url, session):
    for element in SECURITYTXT_PATHS:
        to_check = url + element
        search = re.compile(SECURITYTXT_SEARCH)

        try:
            response = session.get(to_check, allow_redirects=False, timeout=10)

            if response.status_code == 200:
                text = response.text
                if text != False:
                    result = search.search(text)
                    if result:
                        print(f"[+] Found an exposed security.txt: {to_check}")
                        print(text)
                        return True
                    return True
        except requests.exceptions.Timeout:
            # Timeouts if the request takes longer than X seconds
                print("Timeout error")
    return False

def __main__():
    # Check if a URL it sent as parameter on args
    args = sys.argv
    if len(args) < 2:
        print("Usage: python3 dotgitcli.py <URL> <PROXY (optional)> --no-verify (optional)")
        sys.exit()

    url = args[1]
    if not isValidUrl(url):
        print("Invalid URL")
        sys.exit()

    if url.endswith("/"):
        url = url[:-1]
    print(f"Checking {url}...")

    found = False
    with requests.Session() as session:
        # Check if a proxy is provided as an optional argument
        if len(args) > 2:
            for arg in args[2:]:
                if arg.startswith("http://") or arg.startswith("https://"):
                    proxy_url = arg
                    session.proxies = {
                        'http': proxy_url,
                        'https': proxy_url
                    }
                    print(f"Using proxy: {proxy_url}")

        # Check if --no-verify is provided as an optional argument
        if "--no-verify" in args:
            session.verify = False

        # Changed headers to avoid 403 Forbidden
        session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        }

        found = checkGit(url, session) or found
        found = checkSvn(url, session) or found
        found = checkHg(url, session) or found
        found = checkEnv(url, session) or found
        found = isOpenSource(url, session) or found
        found = checkSecuritytxt(url, session) or found

    if not found:
        print("No exposed .git, .svn, .hg, .env, open source project or security.txt found")

if __name__ == "__main__":
    __main__()