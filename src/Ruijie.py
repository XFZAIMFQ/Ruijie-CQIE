import configparser
import json
import logging
import os
import re
import time
from urllib.parse import quote, unquote

import requests

CERTIFICATION_ADDRESS = '10.253.3.84'
LOG_FILENAME = f'../log/{time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime(time.time()))}.log'
CONFIG_FILENAME = '../config/config.ini'


class Ruijie:
    def __init__(self):
        # user_info
        self.username = ''
        self.password = ''
        self.carrier = ''
        self.save_password = False
        # query_info
        self.queryString = ''
        self.page_info = {}
        self.optional_carrier = ''
        # public_key
        self.passwordEncrypt = True
        self.publicKeyExponent = ''
        self.publicKeyModulus = ''
        # cookies
        self.mac = ''
        self.encryptedPassword = True

        self.login_url = ''
        self.userIndex = ''

        self.AutoLoginFlag = False

        # 读取信息
        if not self.detect_env:
            logging.error('不在校园网环境中')

        if not self.detect_login:
            self.update_base_info()
        else:
            self.AutoLoginFlag = True

    def set_login_info(self, username: str, password: str, carrier: str, save_password: bool):
        """
        设置登录信息
        :param username:
        :param password:
        :param carrier:
        :param save_password:
        :return:
        """
        self.username = username
        self.password = password
        self.carrier = carrier
        self.save_password = save_password

    def post(self, method: str, data, cookie_is=True):
        url = f'http://{CERTIFICATION_ADDRESS}/eportal/InterFace.do?method={method}'
        headers = {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        if cookie_is:
            cookies = self.url_encode(self.get_cookie())
        else:
            cookies = ''
        encoded_data = self.url_encode(data)
        response = requests.post(url, headers=headers, data=encoded_data, cookies=cookies, verify=False)
        if response.status_code != 200:
            logging.error(f'请求 {url} 失败')
        return response

    def url_encode(self, data):
        """
        URL编码处理
        :param data:
        :return:
        """
        return {key: quote(str(value), safe='') for key, value in data.items()}

    def get_cookie(self):
        cookies = {
            'servicesJsonStr': self.username + '@%%username@%%' + self.optional_carrier,
            'EPORTAL_COOKIE_DOMAIN': '',
            'EPORTAL_COOKIE_USERNAME': self.username,
            'EPORTAL_COOKIE_SERVER': self.carrier,
            'EPORTAL_COOKIE_SERVER_NAME': self.carrier,
            'EPORTAL_COOKIE_SAVEPASSWORD': 'true',
            'EPORTAL_COOKIE_OPERATORPWD': '',
            'EPORTAL_COOKIE_NEWV': 'true',
            'EPORTAL_COOKIE_PASSWORD': self.encrypted_password(self.password, self.mac, self.page_info.get('publicKeyExponent'),
                                                               self.page_info.get('publicKeyModulus')),
            'EPORTAL_AUTO_LAND': '',
            'EPORTAL_USER_GROUP': '',
        }
        return cookies

    def read_info(self):
        """
        读取信息
        :return:
        """
        config = configparser.ConfigParser()
        config.read(CONFIG_FILENAME, encoding='utf-8')
        # user_info
        self.username = config['user_info']['username']
        self.password = config['user_info']['password']
        self.carrier = config['user_info']['carrier']
        self.save_password = config['user_info']['save_password']
        # public_key
        # self.passwordEncrypt = config['public_key']['passwordEncrypt']
        # self.publicKeyExponent = config['public_key']['publicKeyExponent']
        # self.publicKeyModulus = config['public_key']['publicKeyModulus']
        # # cookies
        # self.cookies = config['cookies']
        # # other
        # self.mac = config['other']['mac']
        # self.encryptedPassword = config['other']['encryptedPassword']

    def save_info(self):
        """
        保存信息
        :return:
        """
        config = configparser.ConfigParser()
        config['user_info'] = {
            'username': self.username,
            'password': self.password,
            'carrier': self.carrier,
            'save_password': self.save_password
        }
        # config['public_key'] = {
        #     'passwordEncrypt': self.page_info.get('passwordEncrypt') if self.page_info != {} else '',
        #     'publicKeyExponent': self.page_info.get('publicKeyExponent') if self.page_info != {} else '',
        #     'publicKeyModulus': self.page_info.get('publicKeyModulus') if self.page_info != {} else ''
        # }
        # config['cookies'] = self.get_cookie() if self.page_info != {} else {}
        # config['other'] = {
        #     'mac': self.mac,
        #     'encryptedPassword': self.page_info.get('encryptedPassword') if self.page_info != {} else ''
        # }
        with open(CONFIG_FILENAME, 'w', encoding='utf-8') as configfile:
            config.write(configfile)

    def detect_env(self):
        """
        检测是否在校园网环境中
        :return:
        """
        # 禁止重定向
        response = requests.get(f'http://{CERTIFICATION_ADDRESS}', allow_redirects=False)
        if response.status_code == 302:
            return True
        return False

    def detect_login(self):
        """
        检测是否已经登录
        :return:
        """
        response = requests.get(f"http://{CERTIFICATION_ADDRESS}")
        if response.status_code == 200 and ("success.jsp" in response.url):
            # 获取 userIndex
            self.userIndex = self.get_query_string_by_name(response.url, 'userIndex')
            return True
        return False

    def login(self):
        """
        登录
        :return:
        """
        login_data = {
            'userId': self.username,
            'password': self.encrypted_password(self.password, self.mac, self.page_info.get('publicKeyExponent'), self.page_info.get('publicKeyModulus')),
            'service': self.carrier,
            'queryString': self.queryString,
            'operatorPwd': '',
            'operatorUserId': '',
            'validcode': '',
            'passwordEncrypt': self.page_info.get('passwordEncrypt'),
        }
        response = self.post('login', login_data, False)
        response.encoding = 'utf-8'
        if response.status_code == 200:
            response_data = json.loads(response.text)
            if response_data['result'] == 'success':
                self.userIndex = response_data.get('userIndex')
                logging.info('登录成功')
                return True
            else:
                logging.error(unquote(response_data.get('message')))
        logging.error(f'登录失败 status_code {response.status_code}')
        return False

    def logout(self):
        """
        退出登录
        :return:
        """
        data = {'userIndex': self.userIndex}
        response = self.post('logout', data, False)
        if response.status_code == 200:
            response_data = json.loads(response.text)
            if response_data.get('result') == 'success':
                logging.info('退出登录成功')
                return True
            else:
                logging.error(f'退出登录失败, message:{unquote(response_data.get("message"))}')
                return False
        logging.error(f'退出登录失败 status_code {response.status_code}')
        return False

    def switch_service(self, serviceName):
        """
        切换服务
        :return:
        """
        data = {'userIndex': self.userIndex, 'serviceName': quote(serviceName)}
        response = self.post('switchService', data)
        if response.status_code == 200:
            response_data = json.loads(response.text)
            if response_data.get('result') == 'success':
                logging.info(f'切换服务成功, serviceName:{serviceName}')
                return True
            else:
                logging.error(f'切换服务失败, message:{unquote(response_data.get("message"))}')
                return False
        logging.error(f'切换服务失败 status_code {response.status_code}')
        return False

    def encrypted_password(self, password: str, mac_string: str, public_key_exponent, public_key_modulus):
        """
        加密密码
        :param password:
        :param mac_string:
        :param public_key_exponent:
        :param public_key_modulus:
        :return:
        """
        passwordMac = password + ">" + mac_string
        s = self.rsa_encrypt(passwordMac, public_key_exponent, public_key_modulus)
        return quote(quote(s))

    def rsa_encrypt(self, string: str, public_key_exponent, public_key_modulus):
        # 将16进制字符串转换为整数
        e = int(public_key_exponent, 16)
        n = int(public_key_modulus, 16)
        # 将消息转换为整数
        m = self._bytes_to_long(string.encode())
        # 执行RSA加密: c = m^e mod n
        c = pow(m, e, n)
        # 将结果转换为16进制字符串
        result = hex(c)[2:].zfill(256)  # 去掉'0x'前缀，补齐256位
        return result

    def _bytes_to_long(self, byte_string):
        """
        将字节串转换为整数
        每个字节按大端序转换（最高有效字节在左边）
        """
        result = 0
        for byte in byte_string:
            result = (result << 8) | byte
        return result

    def get_login_url(self):
        """
        获取登录地址
        :return:
        """
        url = "http://123.123.123.123"
        response = requests.get(url)
        if response.status_code != 200 or response.text == '':
            return False
        login_url = response.text.split("'")[1]
        self.queryString = login_url.split('?')[1]
        self.mac = self.get_query_string_by_name(login_url, 'mac')
        return login_url

    def get_query_string_by_name(self, url, name):
        """
        通过名称获取查询字符串
        :param url:
        :param name:
        :return:
        """
        match = re.search(r'[?&]' + re.escape(name) + r'=([^&]*)', url)
        return match.group(1) if match else ('111111111' if name == 'mac' else '')

    def update_base_info(self):
        """
        获取基础信息
        :param :
        :return:
        """
        # 获得 url mac queryString
        self.login_url = self.get_login_url()
        # 获得 pageInfo
        data = {'queryString': self.queryString}
        response = self.post('pageInfo', data, False)
        if response and response.text != '':
            self.page_info = json.loads(response.text)
        else:
            logging.error('获取 pageInfo 信息失败')
            return False
        # 获得 Services
        data = {'username': self.username, 'queryString': '?' + self.queryString}
        response = self.post('getServices', data, False)
        if response and response.text != '':
            self.optional_carrier = response.text
        else:
            logging.error('获取 getServices 信息失败')
            return False


class LOG:
    def __init__(self):
        pass

    def log(self):
        pass


def main():
    os.makedirs(os.path.dirname(LOG_FILENAME), exist_ok=True)
    logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', encoding='utf-8')

    ruijie = Ruijie()
    if os.path.exists(CONFIG_FILENAME):
        ruijie.read_info()
    else:
        ruijie.save_info()
    ruijie.update_base_info()
    ruijie.save_info()
    ruijie.login()

    # if not ruijie.detect_env:
    #     logging.error('不在校园网环境中')
    #     return False
    # if ruijie.detect_login:
    #     logging.info('已经登录')


if __name__ == '__main__':
    main()
