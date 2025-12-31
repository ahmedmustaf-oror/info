import AccountPersonalShow_pb2
import main_pb2
import FreeFire_pb2
import httpx
import asyncio
import json
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from typing import Tuple
import binascii
import time
from cachetools import TTLCache
from Crypto.Util.Padding import pad as crypto_pad
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB51"
USERAGENT = "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0"
SUPPORTED_REGIONS = ["ME"]  # فقط منطقة ME

# Cache للـ JWT tokens (يدوم 4 ساعات)
jwt_cache = TTLCache(maxsize=10, ttl=4 * 60 * 60)  # 4 ساعات
last_request_time = 0
REQUEST_DELAY = 2  # تأخير 2 ثانية بين الطلبات

def pad(text: bytes) -> bytes:
    """دالة padding الخاصة بنا"""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    padding = bytes([padding_length] * padding_length)
    return text + padding

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = pad(plaintext)
    ciphertext = aes.encrypt(padded_plaintext)
    return ciphertext

async def create_jwt(region: str) -> Tuple[str, str, str]:
    try:
        print(f"🔐 محاولة إنشاء JWT للمنطقة: {region}")
        
        # التحقق من الـ cache أولاً
        cache_key = f"jwt_{region}"
        if cache_key in jwt_cache:
            print(f"✅ استخدام JWT من الـ cache للمنطقة: {region}")
            token = jwt_cache[cache_key]
        else:
            # تعريف UID و Password لمنطقة ME فقط
            region_credentials = {
                'ME': ("4133952616", "2FA793DA92CE371D34EAD9CDC2D0BD5FBA1C205AF58B559B352C132D1EF5D7C5")
            }
            
            if region not in region_credentials:
                raise Exception(f"❌ Region {region} not supported")
            
            uid, password = region_credentials[region]
            
            # استخدام الـ API الجديد لاستخراج JWT
            print(f"🌐 جلب JWT من API خارجي لـ UID: {uid}")
            
            # استخدام HTTPS و follow redirects
            api_url = f"http://jwtapi.spcfy.eu/get?uid={uid}&password={password}"
            
            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(api_url, timeout=30.0)
                
                if response.status_code != 200:
                    # محاولة مع HTTP إذا فشل HTTPS
                    print(f"⚠️  محاولة مع HTTP بدلاً من HTTPS...")
                    api_url = f"http://jwtd5m.spcfy.eu/get?uid={uid}&password={password}"
                    response = await client.get(api_url, timeout=30.0)
                    
                    if response.status_code != 200:
                        raise Exception(f"❌ API returned status {response.status_code} - URL: {api_url}")
                
                data = response.json()
                
                if "token" not in data:
                    raise Exception(f"❌ No token in API response: {data}")
                
                token = data["token"]
                print(f"✅ تم الحصول على JWT من API خارجي")
                print(f"📊 معلومات الإرجاع: Dev={data.get('Dev', 'N/A')}, TEAM={data.get('TEAM', 'N/A')}")
            
            if not token:
                raise Exception("❌ Failed to get JWT token from API")
            
            # تخزين الـ token في الـ cache
            jwt_cache[cache_key] = token
            print(f"✅ تم تخزين JWT في الـ cache للمنطقة: {region}")
        
        print(f"✅ تم الحصول على JWT بنجاح: {token[:50]}...")
        
        # استخراج المنطقة من الـ token (إذا كانت موجودة في payload)
        region_server = "EUROPE"  # القيمة الافتراضية
        try:
            # فك تشفير payload من JWT
            payload_encoded = token.split('.')[1]
            # إضافة padding إذا لزم الأمر
            payload_encoded += '=' * ((4 - len(payload_encoded) % 4) % 4)
            payload_decoded = base64.b64decode(payload_encoded)
            payload = json.loads(payload_decoded)
            
            # استخراج المنطقة من payload
            region_server = payload.get('lock_region', 'EUROPE')
            print(f"🌍 المنطقة من JWT: {region_server}")
        except Exception as e:
            print(f"⚠️  تعذر استخراج المنطقة من JWT: {e}")
            print(f"🌍 استخدام المنطقة الافتراضية: {region_server}")
        
        # رابط السيرفر الافتراضي
        server_url = "https://clientbp.ggblueshark.com"
        print(f"🔗 رابط السيرفر: {server_url}")
        
        return f"Bearer {token}", region_server, server_url
            
    except Exception as e:
        print(f"❌ خطأ في create_jwt: {str(e)}")
        # إزالة الـ token من الـ cache إذا كان فيه خطأ
        cache_key = f"jwt_{region}"
        if cache_key in jwt_cache:
            del jwt_cache[cache_key]
        raise e

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    serialized_data = proto_message.SerializeToString()
    return serialized_data

# دالة محسنة لتحويل البيانات من hex إلى protobuf
def decode_hex_protobuf(hex_data):
    """تحويل البيانات من hex إلى كائن protobuf"""
    try:
        # تحويل hex إلى bytes
        byte_data = binascii.unhexlify(hex_data.replace(' ', ''))
        
        # إنشاء كائن protobuf وتحليل البيانات
        users = AccountPersonalShow_pb2.AccountPersonalShowInfo()
        users.ParseFromString(byte_data)
        
        return users
    except Exception as e:
        print(f"❌ خطأ في تحويل protobuf: {e}")
        raise e

async def GetAccountInformation(ID, UNKNOWN_ID, regionMain="ME", endpoint="/api/clientbp/GetPlayerPersonalShow"):
    try:
        print(f"👤 جلب معلومات الحساب: ID={ID}, Region={regionMain}")
        
        # التحقق من نوع المدخلات
        if not isinstance(ID, str):
            ID = str(ID)
        if not isinstance(UNKNOWN_ID, str):
            UNKNOWN_ID = str(UNKNOWN_ID)
        
        json_data = json.dumps({
            "a": ID,
            "b": UNKNOWN_ID
        })
        
        encoded_result = await json_to_proto(json_data, main_pb2.GetPlayerPersonalShow())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, encoded_result)
        
        regionMain = regionMain.upper()
        if regionMain not in SUPPORTED_REGIONS:
            return {
                "error": "Invalid request",
                "message": f"Unsupported 'region' parameter. Supported regions are: {', '.join(SUPPORTED_REGIONS)}."
            }
        
        token, region, serverUrl = await create_jwt(regionMain)
        print(f"🔑 Token: {token[:50]}...")
        print(f"🌍 Server URL: {serverUrl}")
        
        headers = {
            "Host": "clientbp.ggblueshark.com",
            "X-Unity-Version": "2018.4.11f1",
            "Accept": "*/*",
            "Authorization": token,
            "ReleaseVersion": RELEASEVERSION,
            "X-GA": "v1 1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/octet-stream",
            "User-Agent": USERAGENT,
            "Connection": "keep-alive"
        }
        
        full_url = serverUrl + endpoint
        print(f"🌐 إرسال طلب إلى: {full_url}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(full_url, data=payload, headers=headers)
            print(f"📊 حالة الاستجابة النهائية: {response.status_code}")
            
            if response.status_code != 200:
                raise Exception(f"❌ Server returned status {response.status_code}")
            
            response_content = response.content
            
            # تحويل الرد إلى hex أولاً ثم تحليله
            hex_response = response_content.hex()
            print(f"📦 حجم البيانات المستلمة: {len(hex_response)} حرف hex")
            
            # استخدام الدالة المحسنة لتحويل protobuf
            message_obj = decode_hex_protobuf(hex_response)
            
            # تحويل الكائن protobuf إلى JSON
            message_json = json_format.MessageToJson(message_obj)
            message_data = json.loads(message_json)
            
            print(f"✅ تم جلب معلومات الحساب بنجاح")
            return message_data
            
    except Exception as e:
        print(f"❌ خطأ في GetAccountInformation: {str(e)}")
        raise e

if __name__ == "__main__":
    # اختبار الدوال
    asyncio.run(test_jwt())
    print("\n" + "="*50 + "\n")
    asyncio.run(test_account_info())