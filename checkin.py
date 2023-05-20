import requests, time, re, rsa, json, base64
from urllib import parse

s = requests.Session()
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/76.0"

username = ""
password = ""

if username == "" or password == "":
    username = input("账号：")
    password = input("密码：")

g_conf = {}


def loadRsaKey():
    global g_conf
    r = s.post(
        "https://open.e.189.cn/api/logbox/config/encryptConf.do", {"appId": "cloud"}
    ).json()
    g_conf["pubKey"] = r["data"]["pubKey"]


def loadAppConf(r):
    global g_conf
    g_conf["lt"] = re.findall(r"lt=([a-zA-Z0-9]+)", r.url)[0]
    g_conf["reqId"] = re.findall(r"reqId=([a-zA-Z0-9]+)", r.url)[0]

    r = s.post(
        "https://open.e.189.cn/api/logbox/oauth2/appConf.do",
        data={
            "version": "2.0",
            "appKey": "cloud",
        },
        headers={
            "referer": f"https://open.e.189.cn/api/logbox/separate/web/index.html?appId=cloud&lt={g_conf['lt']}&reqId={g_conf['reqId']}",
            "lt": g_conf["lt"],
            "reqid": g_conf["reqId"],
            "origin": "https://open.e.189.cn",
            "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        },
    ).json()
    g_conf.update(r["data"])


def main():
    login(username, password)
    rand = str(round(time.time() * 1000))
    surl = f"https://api.cloud.189.cn/mkt/userSign.action?rand={rand}&clientType=TELEANDROID&version=8.6.3&model=SM-G930K"
    url = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN&activityId=ACT_SIGNIN"
    url2 = f"https://m.cloud.189.cn/v2/drawPrizeMarketDetails.action?taskId=TASK_SIGNIN_PHOTOS&activityId=ACT_SIGNIN"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 5.1.1; SM-G930K Build/NRD90M; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/74.0.3729.136 Mobile Safari/537.36 Ecloud/8.6.3 Android/22 clientId/355325117317828 clientModel/SM-G930K imsi/460071114317824 clientChannelId/qq proVersion/1.0.6",
        "Referer": "https://m.cloud.189.cn/zhuanti/2016/sign/index.jsp?albumBackupOpened=1",
        "Host": "m.cloud.189.cn",
        "Accept-Encoding": "gzip, deflate",
    }
    response = s.get(surl, headers=headers)
    netdiskBonus = response.json()["netdiskBonus"]
    if response.json()["isSign"] == "false":
        print(f"签到成功！获得{netdiskBonus}M空间")
    else:
        print(f"今天已经签到过了，获得{netdiskBonus}M空间")
    lott(url, headers)
    lott(url2, headers)


BI_RM = list("0123456789abcdefghijklmnopqrstuvwxyz")


def int2char(a):
    return BI_RM[a]


b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64tohex(a):
    d = ""
    e = 0
    c = 0
    for i in range(len(a)):
        if list(a)[i] != "=":
            v = b64map.index(list(a)[i])
            if 0 == e:
                e = 1
                d += int2char(v >> 2)
                c = 3 & v
            elif 1 == e:
                e = 2
                d += int2char(c << 2 | v >> 4)
                c = 15 & v
            elif 2 == e:
                e = 3
                d += int2char(c)
                d += int2char(v >> 2)
                c = 3 & v
            else:
                e = 0
                d += int2char(c << 2 | v >> 4)
                d += int2char(15 & v)
    if e == 1:
        d += int2char(c << 2)
    return d


def rsa_encode(string):
    rsa_key = (
        f"-----BEGIN PUBLIC KEY-----\n{g_conf['pubKey']}\n-----END PUBLIC KEY-----"
    )
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(rsa_key.encode())
    result = b64tohex(
        (base64.b64encode(rsa.encrypt(f"{string}".encode(), pubkey))).decode()
    )
    return result


def calculate_md5_sign(params):
    return hashlib.md5("&".join(sorted(params.split("&"))).encode("utf-8")).hexdigest()


def tryGet(l, index, default=""):
    if len(l) >= index + 1:
        return l[index]
    else:
        return default


def login(username, password):
    url = "https://cloud.189.cn/api/portal/loginUrl.action?redirectURL=https://cloud.189.cn/web/redirect.html?returnURL=/main.action"
    r = s.get(url)
    # captchaToken = tryGet(re.findall(r"captchaToken' value='(.+?)'", r.text), 0)
    # lt = tryGet(re.findall(r'lt = "(.+?)"', r.text), 0)
    # returnUrl = tryGet(re.findall(r"returnUrl = '(.+?)'", r.text), 0)
    # paramId = tryGet(re.findall(r'paramId = "(.+?)"', r.text), 0)
    loadAppConf(r)
    user = username
    loadRsaKey()
    username = rsa_encode(username)
    password = rsa_encode(password)
    url = "https://open.e.189.cn/api/logbox/oauth2/loginSubmit.do"
    headers = {
        "User-Agent": ua,
        "Referer": "https://open.e.189.cn/",
        "lt": g_conf["lt"],
        "REQID": g_conf["reqId"],
    }
    data = {
        "appKey": "cloud",
        "accountType": "01",
        "version": "2.0",
        "userName": f"{{NRP}}{username}",
        "password": f"{{NRP}}{password}",
        "validateCode": "",
        "captchaToken": "",
        "returnUrl": g_conf["returnUrl"],
        "mailSuffix": g_conf["mailSuffix"],
        "paramId": g_conf["paramId"],
        "dynamicCheck": "FALSE",
        "clientType": "1",
        "cb_SaveName": "0",
        "isOauth2": False,
    }
    r = s.post(url, data=data, headers=headers, timeout=6)
    print(f"{user[0:2]}* **** **{user[9:11]} :", end=" ")
    if r.json()["result"] == 0:
        print(r.json()["msg"])
    else:
        raise Exception(r.json()["msg"])
    redirect_url = r.json()["toUrl"]
    r = s.get(redirect_url)
    return s


def lott(url, headers):
    response = s.get(url, headers=headers)
    respJson = response.json()

    if "errorCode" in respJson:
        print("抽奖错误：" + response.text)
    else:
        if "description" in respJson:
            print("抽奖获得 " + respJson["description"])
        else:
            print("抽奖异常：" + response.text())


if __name__ == "__main__":
    main()
