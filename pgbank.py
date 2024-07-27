
import hashlib
import requests
import json
import base64
import random
import string
import base64
import json
import os
import hashlib
import time
import uuid
import base64
from datetime import datetime
import re
from bs4 import BeautifulSoup
from lxml import html
import urllib.parse
from urllib.parse import quote

class PGBank:
    def __init__(self, username, password, account_number):
        self.session = requests.Session()
        self.is_login = False
        self.file = f"data/{username}.txt"
        self._IBDeviceId = ""
        self.dse_sessionId = ""
        self.balance = None
        self.referer_url = ""
        self.load_account_url = ""
        self.dse_processorId = ""
        self.account_cif = None
        self.dse_pageId = 0
        self.available_balance = 0
        self.transactions = []
        self.accounts_list = {}
        self.fingerprint = self.generate_random_numeric_string(10)
        self.url = {
    "solve_captcha": "https://captcha.pay2world.vip/pgbank",
    "getCaptcha": "https://biz.pgbank.com.vn/servlet/ImageServlet",
    "login": "https://home.pgbank.com.vn/V2018/login.aspx",
    "getHistories": "https://home.pgbank.com.vn/V2018/pages/transelect.aspx",
}
        self.lang =  "vi"
        self.request_id = None
        self._timeout = 60
        self.init_guid()
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            self.browserId = hashlib.md5(self.username.encode()).hexdigest()
            self.save_data()
            
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': getattr(self, 'sessionId', '')
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)
    def generate_random_numeric_string(self,length=10):
        """Generate a random numeric string of given length."""
        return ''.join([str(random.randint(0, 9)) for _ in range(length)])
    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.sessionId = data.get('sessionId', '')
        
    def init_guid(self):
        self._IBDeviceId = self.generate_device_id()
        
    def generate_device_id(self):
        # Generate a random UUID
        random_uuid = uuid.uuid4()
        
        # Convert the UUID to a string
        uuid_str = str(random_uuid)
        
        # Create a hash object
        hash_object = hashlib.sha256()
        
        # Update the hash object with the UUID string
        hash_object.update(uuid_str.encode('utf-8'))
        
        # Get the hexadecimal digest of the hash
        hex_digest = hash_object.hexdigest()
        
        # Return the first 32 characters of the hex digest
        return hex_digest[:32]
    
    def curlGet(self, url):
        # print('curlGet')
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Referer': 'https://www.google.com/',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=0, i',
        'TE': 'trailers'
        }
        response = self.session.get(url, headers=headers,allow_redirects=True)
        self.referer_url = url
        try:
            return response.json()
        except:
            response = response.text
            # dse_pageId = self.extract_dse_pageId(response)
            # if dse_pageId:
            #     self.dse_pageId = dse_pageId
            # # else:
            # #     print('error_page',url)
            return response
        return result
    
    def curlPost(self, url, data ,headers = None):
        # print('curlPost')
        if not headers:
            headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://biz.pgbank.com.vn',
            "Referer": self.referer_url if self.referer_url else "",
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
            }

        response = self.session.post(url, headers=headers, data=data)
        self.referer_url = url
        try:
            return response.json()
        except:
            response = response.text
            # dse_pageId = self.extract_dse_pageId(response)
            # if dse_pageId:
            #     self.dse_pageId = dse_pageId
            # else:
            #     print('error_page',url)
            return response
        return result

    def generate_request_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)) + '|' + str(int(datetime.now().timestamp()))
    def check_error_message(self,html_content):
        pattern = r'<span><font class=\'text-err_login\'>(.*?)</font></span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def check_error_message_details(self,html_content):
        pattern = r'<span><font class=\'text-err_login__desc\'>(.*?)</font></span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def check_exit_login(self,html_content):
        return True if 'để tài khoản đã đăng nhập thoát khỏi hệ thống' in html_content else None
    def check_error_captcha(self,html_content):
        return True if 'Mã xác thực không chính xác' in html_content else None
    def extract_tokenNo(self,html_content):
        pattern = r'src="/IBSRetail/servlet/CmsImageServlet\?attachmentId=1&&tokenNo=([a-f0-9-]+)"'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_account_cif(self,html_content):
        pattern = r'<option value="(.+)" >'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract___VIEWSTATE(self,html_content):
        pattern = r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="(.*)" />'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract___EVENTVALIDATION(self,html_content):
        pattern = r'<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="(.*)" />'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract___VIEWSTATEGENERATOR(self,html_content):
        pattern = r'<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="(.*)" />'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_captcha_url(self,html_content):
        html_content = self.session.get('https://home.pgbank.com.vn/V2018/api/ApiEbank/GetImgVerify?imgcheck=1').json()
        url = html_content['url']
        return "https://home.pgbank.com.vn/V2018/"+str(url) if 'url' in html_content else None
    def check_captcha(self,html_content):
        pattern = r'<img id="ctl00_imgVerify" class="img-responsive" src="(.*)" style="border-style:Solid;border-width:0px;" />'
        match = re.search(pattern, html_content)
        return True if match else False
    def check_captcha_1(self,html_content):
        html_content = self.session.get('https://home.pgbank.com.vn/V2018/api/ApiEbank/GetImgVerify?imgcheck=1').json()
        url = html_content['url']
        return "https://home.pgbank.com.vn/V2018/"+str(url) if 'url' in html_content else None
    def extract_account_number(self,html_content):
        pattern = r'<span class="lblLabel" style="color:Black;">Số tài khoản/Số thẻ</span>: <span style="color: black"><strong>(.*) </strong></span>'
        match = re.search(pattern, html_content)
        return match.group(1).strip() if match else None
    def extract_by_pattern(self,html_content,pattern):
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_load_account(self,html_content):
        pattern = r'/Request?&dse_sessionId=(.)*&dse_applicationId=-1&dse_pageId=(.)*&dse_operationName=corpUserLoginProc&dse_processorState=initial&dse_nextEventName=loadAccounts'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_balance(self,html_content):
        pattern = r'<span class="lblLabel" style="color:Black;">Số dư khả dụng</span>: <span style="color: black"><strong>               (.*) VND</strong></span><br />'
        match = re.search(pattern, html_content)
        return int(match.group(1).replace(',','').strip()) if match else None
    def get_total_transaction(self,html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        h4_element = soup.find('h4')
        if h4_element:
            h4_text = h4_element.get_text(strip=True)
        return int(h4_text.replace('Tổng số bản ghi','').strip()) if h4_element else 0
    def extract_page_url(self,html_content,page):
        soup = BeautifulSoup(html_content, 'html.parser')
        div = soup.find('div', class_='so-trang')
        href = None
        if div:
            a_tag = div.find('a', string=str(page)+' ')
            if a_tag:
                href = a_tag['href']
        return 'https://biz.pgbank.com.vn'+href if href else None
    def extract_transaction_history(self,html_string):
        # Parse the HTML content
        soup = BeautifulSoup(html_string, 'html.parser')
        
        # Find the table by ID
        table = soup.find('table', id='grdAccount_DXMainTable')
        
        if not table:
            raise ValueError("Table with ID 'grdAccount_DXMainTable' not found.")
        
        transactions = []
        
        # Iterate over each row in the table body
        rows = table.find_all('tr', class_='dxgvDataRow_Aqua1')
        
        for row in rows:
            # Extract cells from the row
            cells = row.find_all('td')
            if len(cells) < 5:
                continue  # Skip rows that don't have enough cells
            
            # Extract relevant data from each cell
            date = cells[0].get_text(strip=True)
            description = cells[1].get_text(strip=True)
            amount = cells[2].get_text(strip=True)
            time = cells[3].get_text(strip=True)
            
            # Append the extracted data to the transactions list
            transactions.append({
                'date': date,
                'time': time,
                'remark': description,
                'amount': float(amount.replace(',','')),
                
            })
        
        return transactions
    def createTaskCaptcha(self, base64_img):
        payload = json.dumps({
        "image_base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }

        response = requests.request("POST", self.url['solve_captcha'], headers=headers, data=payload)
        try:
            return response.json()
        except:
            return response.text
    def solveCaptcha(self,url):
        response = self.session.get(url)
        base64_captcha_img = base64.b64encode(response.content).decode('utf-8')
        result = self.createTaskCaptcha(base64_captcha_img)
        # captchaText = self.checkProgressCaptcha(json.loads(task)['taskId'])
        if 'prediction' in result and result['prediction']:
            captcha_value = result['prediction']
            return {"status": True, "captcha": captcha_value}
        else:
            return {"status": False, "msg": "Error getTaskResult"}
    def process_redirect(self,response):
        
        pattern = r'dse_sessionId=(.*?)&dse_applicationId=(.*?)&dse_pageId=(.*?)&dse_operationName=(.*?)&dse_errorPage=(.*?)&dse_processorState=(.*?)&dse_nextEventName=(.*?)\';'
        pattern_url = r'window.location.href = \'(.*?)\';'
        match = re.search(pattern, response)
        match_url = re.search(pattern_url, response)
        self.dse_sessionId = str(match.group(1))
        if match_url:
            return 'https://biz.pgbank.com.vn'+match_url.group(1)
        else:
            return None
    def process_change_session(self,response):
        pattern = r'dse_sessionId=(.*?)&dse_applicationId=(.*?)&dse_pageId=(.*?)&dse_operationName=(.*?)&dse_processorState=(.*?)&dse_nextEventName=(.*?)\';'
        pattern_url = re.compile(r'/Request\?&dse_sessionId=[^&]+&dse_applicationId=-1&dse_pageId=[^&]+&dse_operationName=corpUserLoginProc&dse_processorState=initial&dse_nextEventName=loadAccounts')
        match = re.search(pattern, response)
        match_url = re.search(pattern_url, response)
        self.dse_sessionId = str(match.group(1))
        if match_url:
            return 'https://biz.pgbank.com.vn'+match_url.group(0)
        else:
            return None
    def doLogin(self):
        st = time.time()
        self.session = requests.Session()
        response = self.curlGet(self.url['login'])
        #print(time.time()-st)
        __EVENTVALIDATION = self.extract___EVENTVALIDATION(response)
        __VIEWSTATE = self.extract___VIEWSTATE(response)
        __VIEWSTATEGENERATOR = self.extract___VIEWSTATEGENERATOR(response)
        payload_dict = {
            '__LASTFOCUS': '',
            '__VIEWSTATE': __VIEWSTATE,
            '__VIEWSTATEGENERATOR': __VIEWSTATEGENERATOR,
            '__EVENTTARGET': '',
            '__EVENTARGUMENT': '',
            '__EVENTVALIDATION': __EVENTVALIDATION,
            'ctl00$txtloginName': self.username,
            'ctl00$txtPassword': self.password,
            'ctl00$btnLogin': 'Đăng nhập'
        }
        is_captcha = self.check_captcha(response)
        if is_captcha:
            captcha_url = self.extract_captcha_url(response)
            if(captcha_url):
                solveCaptcha = self.solveCaptcha(captcha_url)
                if not solveCaptcha["status"]:
                    return solveCaptcha
                payload_dict['ctl00$txtCaptcha'] = solveCaptcha["captcha"]
        #print(time.time()-st)
        headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://home.pgbank.com.vn',
        'priority': 'u=0, i',
        'referer': 'https://home.pgbank.com.vn/V2018/login.aspx',
        'sec-ch-ua': '"Not)A;Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
        }
        # Convert the dictionary to payload format
        payload_converted = '&'.join(f'{quote(k)}={quote(v)}' for k, v in payload_dict.items())
        
        response = self.curlPost(self.url['login'],payload_converted,headers)
        #print(time.time()-st)
        # with open('payload2.html', 'w', encoding='utf-8') as file:
        #     file.write(response)
        if 'Số dư khả dụng' in response:
            self.is_login = True
            self.balance = self.extract_balance(response)
            account_number = self.extract_account_number(response)
            accounts = {
                "account_number": account_number,
                "balance": self.balance
            }
            self.accounts_list = accounts
            return {
                'code': 200,
                'success': True,
                'message': 'Đăng nhập thành công',
                'data':self.accounts_list
            }
        elif 'Tài khoản không tồn tại hoặc không hợp lệ.' in response:
                return {
                            'code': 404,
                            'success': False,
                            'message': 'Tài khoản không tồn tại hoặc không hợp lệ.',
                            }
        elif 'Sai tên hoặc mật khẩu' in response:
                return {
                            'code': 444,
                            'success': False,
                            'message': 'Tài khoản hoặc mật khẩu không đúng',
                            }
        elif 'Mã Tiếp tục không hợp lệ' in response:
                return {
                    'code': 422,
                    'success': False,
                    'message': 'Mã Tiếp tục không hợp lệ',
                    }
        elif 'Tài khoản của quý khách đã bị khóa' in response:
                return {
                    'code': 449,
                    'success': False,
                    'message': 'Blocked account!'                    
                    }
        else:
            return {
                    'code': 520,
                    'success': False,
                    'message': "Unknown Error!"
            }
    def get_balance(self,account_number):
        login = self.doLogin()
        if not login['success']:
            return login
        account = self.accounts_list
        if account.get('account_number'):
            if account.get('account_number') == account_number:
                return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':account_number,
                                    'balance':account.get('balance')
                        }}
            else:
                return {'code':404,'success': False, 'message': 'account_number not found!'} 
        else:
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 
    def saveData(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': self.sessionId,
            'mobileId': self.mobileId,
            'clientId': self.clientId,
            'cif': self.cif,
            'E': self.E,
            'res': self.res,
            'tranId': self.tranId,
            'browserToken': self.browserToken,
            'browserId': self.browserId,
        }
        with open(f"data/{self.username}.txt", "w") as file:
            json.dump(data, file)

    def parseData(self):
        with open(f"data/{self.username}.txt", "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data.get("account_number", "")
            self.sessionId = data.get("sessionId", "")
            self.mobileId = data.get("mobileId", "")
            self.clientId = data.get("clientId", "")
            self.token = data.get("token", "")
            self.accessToken = data.get("accessToken", "")
            self.authToken = data.get("authToken", "")
            self.cif = data.get("cif", "")
            self.res = data.get("res", "")
            self.tranId = data.get("tranId", "")
            self.browserToken = data.get("browserToken", "")
            self.browserId = data.get("browserId", "")
            self.E = data.get("E", "")

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self,url):
        response = self.session.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result
        
    def getinfoAccount(self):
        param = "_selectedAccType="
        url = "https://biz.pgbank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpQueryTransactionInfomationProc&dse_processorState=firstAndResultPage&dse_processorId="+self.dse_processorId+"&dse_nextEventName=getAccountList"
        
        headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
  'Accept': '*/*',
  'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
  'Accept-Encoding': 'gzip, deflate, br, zstd',
  'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
  'X-Requested-With': 'XMLHttpRequest',
  'Origin': 'https://biz.pgbank.com.vn',
  'Connection': 'keep-alive',
  'Referer': 'https://biz.pgbank.com.vn/Request',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin'
}
        response = self.curlPost(url,param,headers)
        return (response)

    def getinfoAccountCA(self):
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = "_selectedAccType=CA"
        url = "https://biz.pgbank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpQueryTransactionInfomationProc&dse_processorState=firstAndResultPage&dse_processorId="+self.dse_processorId+"&dse_nextEventName=getAccountList"
        
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': '*/*',
        'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://biz.pgbank.com.vn',
        'Connection': 'keep-alive',
        'Referer': 'https://biz.pgbank.com.vn/Request',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Priority': 'u=0'
        }
        response = self.curlPost(url,param,headers)
        return (response)
    
    def get_transactions_by_page(self,url,page,limit):
        response = self.curlGet(url)
        transaction_history = self.extract_transaction_history(response)

        if page*10 < limit:
            if transaction_history:
                self.transactions += transaction_history
            page=page+1
            
            page_url = self.extract_page_url(response,page)
            if page_url:
                return self.get_transactions_by_page(page_url,page,limit)
        else:
            if transaction_history:
                self.transactions += transaction_history[:limit - (page-1)*10]
        return True

    def getHistories(self, fromDate="16/06/2023", toDate="16/06/2023", account_number=''):
        self.transactions = []
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = {}
        url = "https://home.pgbank.com.vn/V2018/Pages/TranSelect.aspx"
        
        response = self.curlGet(url)
        with open("111.html", "w", encoding="utf-8") as file:
            file.write(response)
        __EVENTVALIDATION = self.extract___EVENTVALIDATION(response)
        __VIEWSTATE = self.extract___VIEWSTATE(response)
        __VIEWSTATEGENERATOR = self.extract___VIEWSTATEGENERATOR(response)
        payload_dict = {
            '__EVENTTARGET': '',
            '__EVENTARGUMENT': '',
            '__VIEWSTATE': __VIEWSTATE,
            '__VIEWSTATEGENERATOR': __VIEWSTATEGENERATOR,
            '__EVENTVALIDATION': __EVENTVALIDATION,
            'ctl00$HolderBody$ucTranSelect$drplstUCM_CIF': self.extract_by_pattern(response,r'<option selected="selected" value="(.*)">'),
            'ctl00$HolderBody$ucTranSelect$rdo1': '0',
            'ctl00$HolderBody$ucTranSelect$tbxDateStart$State': '{&quot;rawValue&quot;:&quot;'+str(datetime.strptime(fromDate, "%d/%m/%Y").timestamp() * 1000 + 25200000)+'&quot;}',
            'ctl00$HolderBody$ucTranSelect$tbxDateStart':fromDate,
            'ctl00$HolderBody$ucTranSelect$tbxDateStart$DDDState':'{&quot;windowsState&quot;:&quot;0:0:-1:0:0:0:-10000:-10000:1:0:0:0&quot;}',
            'ctl00$HolderBody$ucTranSelect$tbxDateStart$DDD$C':'{&quot;visibleDate&quot;:&quot;'+str(datetime.strptime(fromDate, "%d/%m/%Y").strftime("%m/%d/%Y"))+'&quot;,&quot;selectedDates&quot;:[&quot;'+str(datetime.strptime(fromDate, "%d/%m/%Y").strftime("%m/%d/%Y"))+'&quot;]}',
            'ctl00$HolderBody$ucTranSelect$tbxDateStart$DDD$C$FNPState':'{&quot;windowsState&quot;:&quot;0:0:-1:0:0:0:-10000:-10000:1:0:0:0&quot;}',
            'ctl00$HolderBody$ucTranSelect$tbxDateEnd$State':'{&quot;rawValue&quot;:&quot;'+str(datetime.strptime(toDate, "%d/%m/%Y").timestamp() * 1000 + 25200000)+'&quot;}',
            'ctl00$HolderBody$ucTranSelect$tbxDateEnd':toDate,
            'ctl00$HolderBody$ucTranSelect$tbxDateEnd$DDDState':'{&quot;windowsState&quot;:&quot;0:0:-1:0:0:0:-10000:-10000:1:0:0:0&quot;}',
            'ctl00$HolderBody$ucTranSelect$tbxDateEnd$DDD$C':'{&quot;visibleDate&quot;:&quot;'+str(datetime.strptime(toDate, "%d/%m/%Y").strftime("%m/%d/%Y"))+'&quot;,&quot;selectedDates&quot;:[&quot;'+str(datetime.strptime(toDate, "%d/%m/%Y").strftime("%m/%d/%Y"))+'&quot;]}',
            'ctl00$HolderBody$ucTranSelect$tbxDateEnd$DDD$C$FNPState':'{&quot;windowsState&quot;:&quot;0:0:-1:0:0:0:-10000:-10000:1:0:0:0&quot;}',
            'ctl00$HolderBody$ucTranSelect$txtFromamount':'',
            'ctl00$HolderBody$ucTranSelect$txtToAmount':'',
            'ctl00$HolderBody$ucTranSelect$rblDateType':'T',
            'ctl00$HolderBody$ucTranSelect$btnShowReport':'Thực hiện',
            'ctl00$dumpValue':self.fingerprint,
            'DXScript':'',
            'DXCss':'',
        }
        # print(payload_dict)
        # for k, v in payload_dict.items():
        #     print(k,v)
        #     payload_converted = '&'.join(f'{quote(k)}={quote(v)}')
            
        payload_converted = '&'.join(f'{quote(k)}={quote(v)}' for k, v in payload_dict.items())
        headers = {
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-US,en;q=0.9',
        'cache-control': 'max-age=0',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://home.pgbank.com.vn',
        'priority': 'u=0, i',
        'referer': 'https://home.pgbank.com.vn/V2018/pages/transelect.aspx',
        'sec-ch-ua': '"Not)A;Brand";v="99", "Microsoft Edge";v="127", "Chromium";v="127"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0'
        }
        response = self.curlPost(self.url['getHistories'],payload_converted,headers)
        # with open("222.html", "w", encoding="utf-8") as file:
        #     file.write(response)
        # return 1
        transactions =  self.extract_transaction_history(response)
        if  transactions:
            return {'code':200,'success': True, 'message': 'Thành công',
                    'data':{
                        'transactions':transactions,
            }}
        else:
            return {'code':200,'success': True, 'message': 'Thành công',
                    'data':{
                        'message': 'No data',
                        'transactions':[],
            }}

