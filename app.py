from flask import Flask, request, jsonify
import requests
import hashlib
import json
import os
from datetime import datetime

app = Flask(__name__)

BOT_TOKEN = "8658580899:AAGklJayHDFNGVlSRmRr6oC8J6i_YwLRcKA"
ADMIN_IDS = [8422582044, 1738304576, 8156132438]
ALLOWED_USERS = ADMIN_IDS.copy()

user_states = {}
user_data = {}

def is_allowed(user_id):
    return user_id in ALLOWED_USERS

def encrypt_number(number):
    number_str = str(number)
    hash_object = hashlib.sha256(number_str.encode())
    return hash_object.hexdigest().upper()

def format_time(seconds):
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    time_parts = []
    if days > 0:
        time_parts.append(f"{days} يوم")
    if hours > 0:
        time_parts.append(f"{hours} ساعة")
    if minutes > 0:
        time_parts.append(f"{minutes} دقيقة")
    if seconds > 0 or not time_parts:
        time_parts.append(f"{seconds} ثانية")
    return "، ".join(time_parts)

def send_telegram_message(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML'
    }
    requests.post(url, json=payload)

def show_info_api(token):
    try:
        api = "https://100067.connect.garena.com/game/account_security/bind:get_bind_info?app_id=100067&access_token=" + token
        headers = {
            "User-Agent": "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        response = requests.get(api, headers=headers).json()

        result = []
        if "error" in response:
            result.append(f"❌ خطأ: {response['error']}")
        else:
            email = response.get("email", "")
            email_to_be = response.get("email_to_be", "")
            mobile = response.get("mobile", "")
            mobile_to_be = response.get("mobile_to_be", "")
            request_exec_countdown = response.get("request_exec_countdown", 0)

            if email:
                result.append(f"📧 الإيميل الحالي: {email}")
            if email_to_be:
                result.append(f"🔄 الإيميل قيد الانتظار: {email_to_be}")
            if mobile:
                result.append(f"📱 الهاتف الحالي: {mobile}")
            if mobile_to_be:
                result.append(f"🔄 الهاتف قيد الانتظار: {mobile_to_be}")
            if request_exec_countdown > 0:
                time_remaining = format_time(request_exec_countdown)
                result.append(f"⏰ الوقت المتبقي: {time_remaining}")
            if not result:
                result.append("📭 لم يتم العثور على معلومات")

        return "\n".join(result)
    except Exception as error:
        return f"❌ خطأ: {str(error)}"

def send_otp_for_bind(chat_id, user_id, email):
    try:
        BASE_URL = "https://100067.connect.garena.com/game/account_security/bind"
        APP_ID = "100067"
        COMMON_HEADERS = {
            'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        url = f"{BASE_URL}:send_otp"
        payload = {
            'app_id': APP_ID,
            'access_token': user_data[user_id]['token'],
            'email': email,
            'locale': "ar_EG"
        }

        headers = COMMON_HEADERS.copy()
        headers['Accept'] = "application/json"

        response = requests.post(url, data=payload, headers=headers)

        if response.status_code == 200:
            user_states[user_id] = 'awaiting_otp_bind'
            send_telegram_message(chat_id, "✅ تم إرسال OTP إلى الإيميل بنجاح!\n\n🔢 الرجاء إرسال رمز OTP الذي وصلك على الإيميل:")
        else:
            user_states.pop(user_id, None)
            send_telegram_message(chat_id, f"❌ فشل إرسال OTP: {response.text}")
    except Exception as e:
        user_states.pop(user_id, None)
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")

def complete_bind(chat_id, user_id, otp):
    try:
        token = user_data[user_id]['token']
        code = user_data[user_id]['code']
        email = user_data[user_id]['email']

        send_telegram_message(chat_id, "⏳ جاري ربط الإيميل...")

        BASE_URL = "https://100067.connect.garena.com/game/account_security/bind"
        APP_ID = "100067"
        COMMON_HEADERS = {
            'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        # التحقق من OTP
        url = f"{BASE_URL}:verify_otp"
        payload = {
            'app_id': APP_ID,
            'access_token': token,
            'otp': otp,
            'email': email
        }

        verify_response = requests.post(url, data=payload, headers=COMMON_HEADERS)

        if verify_response.status_code == 200:
            response_data = verify_response.json()
            verifier_token = response_data.get("verifier_token")

            if verifier_token:
                # إنشاء طلب الربط
                url = f"{BASE_URL}:create_bind_request"
                payload = {
                    'app_id': APP_ID,
                    'access_token': token,
                    'verifier_token': verifier_token,
                    'secondary_password': encrypt_number(code),
                    'email': email
                }

                bind_response = requests.post(url, data=payload, headers=COMMON_HEADERS)
                if bind_response.status_code == 200:
                    send_telegram_message(chat_id, f"✅ تم ربط الإيميل بنجاح!\n📧 الإيميل: {email}")
                else:
                    send_telegram_message(chat_id, f"❌ فشل الربط: {bind_response.text}")
            else:
                send_telegram_message(chat_id, "❌ لم يتم العثور على verifier_token")
        else:
            send_telegram_message(chat_id, f"❌ فشل التحقق من OTP: {verify_response.text}")

        user_states.pop(user_id, None)
        user_data.pop(user_id, None)

    except Exception as e:
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")
        user_states.pop(user_id, None)
        user_data.pop(user_id, None)

def send_otp_for_rebind(chat_id, user_id, email):
    try:
        BASE_URL = "https://100067.connect.garena.com/game/account_security/bind"
        APP_ID = "100067"
        COMMON_HEADERS = {
            'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        url = f"{BASE_URL}:send_otp"
        payload = {
            'app_id': APP_ID,
            'access_token': user_data[user_id]['token'],
            'email': email,
            'locale': "ar_EG"
        }

        headers = COMMON_HEADERS.copy()
        headers['Accept'] = "application/json"
        headers['Cookie'] = "datadome=L5aWQatkvEKgi0kcs9RfqX3IJ6EI2JPR7uuWg8LmfZcX8Uc297Z1jzndyNgMh~zookrgYaD3hEHfMo9WNEZL1yyGy20TuVkkdiFFB9NNuHn7LuHs_WXyFF7XvfbntaJL"

        response = requests.post(url, data=payload, headers=headers)

        if response.status_code == 200:
            user_states[user_id] = 'awaiting_otp_rebind'
            send_telegram_message(chat_id, "✅ تم إرسال OTP إلى الإيميل بنجاح!\n\n🔢 الرجاء إرسال رمز OTP الذي وصلك على الإيميل:")
        else:
            user_states.pop(user_id, None)
            send_telegram_message(chat_id, f"❌ فشل إرسال OTP: {response.text}")
    except Exception as e:
        user_states.pop(user_id, None)
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")

def complete_rebind(chat_id, user_id, otp):
    try:
        token = user_data[user_id]['token']
        code = user_data[user_id]['code']
        email = user_data[user_id]['email']

        send_telegram_message(chat_id, "⏳ جاري إعادة ربط الإيميل...")

        BASE_URL = "https://100067.connect.garena.com/game/account_security/bind"
        APP_ID = "100067"
        COMMON_HEADERS = {
            'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }

        # التحقق من الهوية
        url = f"{BASE_URL}:verify_identity"
        payload = {
            'app_id': APP_ID,
            'access_token': token,
            'secondary_password': encrypt_number(code)
        }

        identity_response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        if identity_response.status_code != 200:
            send_telegram_message(chat_id, f"❌ فشل التحقق من الهوية: {identity_response.text}")
            user_states.pop(user_id, None)
            user_data.pop(user_id, None)
            return

        identity_token = identity_response.json().get("identity_token")
        if not identity_token:
            send_telegram_message(chat_id, "❌ لم يتم العثور على identity_token")
            user_states.pop(user_id, None)
            user_data.pop(user_id, None)
            return

        # التحقق من OTP
        url = f"{BASE_URL}:verify_otp"
        payload = {
            'app_id': APP_ID,
            'access_token': token,
            'otp': otp,
            'email': email
        }

        verify_response = requests.post(url, data=payload, headers=COMMON_HEADERS)

        if verify_response.status_code == 200:
            response_data = verify_response.json()
            verifier_token = response_data.get("verifier_token")

            if verifier_token:
                # إنشاء طلب إعادة الربط
                url = f"{BASE_URL}:create_rebind_request"
                payload = {
                    'app_id': APP_ID,
                    'access_token': token,
                    'identity_token': identity_token,
                    'verifier_token': verifier_token,
                    'email': email
                }

                rebind_response = requests.post(url, data=payload, headers=COMMON_HEADERS)
                if rebind_response.status_code == 200:
                    send_telegram_message(chat_id, f"✅ تم إعادة ربط الإيميل بنجاح!\n📧 الإيميل: {email}")
                else:
                    send_telegram_message(chat_id, f"❌ فشل إعادة الربط: {rebind_response.text}")
            else:
                send_telegram_message(chat_id, "❌ لم يتم العثور على verifier_token")
        else:
            send_telegram_message(chat_id, f"❌ فشل التحقق من OTP: {verify_response.text}")

        user_states.pop(user_id, None)
        user_data.pop(user_id, None)

    except Exception as e:
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")
        user_states.pop(user_id, None)
        user_data.pop(user_id, None)

def removemailbytoken(chat_id, token):
    COMMON_HEADERS = {
        'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    url = "https://100067.connect.garena.com/game/account_security/bind:cancel_request"
    payload = {
        'app_id': "100067",
        'access_token': token
    }
    response = requests.post(url, data=payload, headers=COMMON_HEADERS).json()
    if response.get("result") == 0:
        send_telegram_message(chat_id, "✅ تم إلغاء الاستعادة بنجاح")
    else:
        send_telegram_message(chat_id, "❌ حدث خطأ، تأكد من التوكن وأعد المحاولة")

def removemailbycode(chat_id, code, token):
    try:
        url = "https://100067.connect.garena.com/game/account_security/bind:verify_identity"
        payload = {
            'app_id': "100067",
            'access_token': token,
            'secondary_password': encrypt_number(code)
        }
        headers = {
            'User-Agent': "GarenaMSDK/4.0.39(SM-A065F ;Android 15;ar;MA;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }
        response = requests.post(url, data=payload, headers=headers).json()

        if "error" in response:
            send_telegram_message(chat_id, f"❌ خطأ: {response['error']}")
        elif response.get("result") == 0:
            send_telegram_message(chat_id, "✅ تم إلغاء الاستعادة بنجاح")
        else:
            send_telegram_message(chat_id, f"❌ فشل: {response}")
    except Exception as e:
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")

def handle_start(chat_id, user_id, first_name):
    if not is_allowed(user_id):
        send_telegram_message(chat_id, "❌ ليس لديك صلاحية للوصول.")
        return

    welcome = f"""تم تطويره بواسطة محمد بوكرينة

مرحباً {first_name}!

الأوامر المتاحة:
/info - عرض معلومات الحساب
/bind - ربط إيميل جديد
/rebind - إعادة ربط إيميل قديم
/removemail - إلغاء الاستعادة (باستخدام التوكن فقط)
/removemailbycode - إلغاء الاستعادة برمز الأمان
/help - عرض المساعدة
"""
    send_telegram_message(chat_id, welcome)

def handle_help(chat_id, user_id):
    if not is_allowed(user_id):
        return

    help_text = """🤖 المساعدة:

/info - عرض معلومات الحساب
/bind - ربط إيميل جديد
/rebind - إعادة ربط إيميل قديم
/removemail - إلغاء الاستعادة (باستخدام التوكن فقط)
/removemailbycode - إلغاء الاستعادة برمز الأمان
/start - عرض القائمة الرئيسية

ملاحظة:
- ربط جديد: لحساب ليس له إيميل
- ربط قديم: لحساب له إيميل وتريد تغييره
- بعد إرسال الإيميل، سيصلك OTP على الإيميل، قم بنسخه وإرساله للبوت
"""
    send_telegram_message(chat_id, help_text)

def handle_info(chat_id, user_id):
    if not is_allowed(user_id):
        return

    user_states[user_id] = 'awaiting_token_info'
    send_telegram_message(chat_id, "📝 الرجاء إرسال التوكن:")

def handle_bind(chat_id, user_id):
    if not is_allowed(user_id):
        return

    user_states[user_id] = 'awaiting_token_bind'
    send_telegram_message(chat_id, "📧 ربط إيميل جديد\n\nالرجاء إرسال التوكن:")

def handle_rebind(chat_id, user_id):
    if not is_allowed(user_id):
        return

    user_states[user_id] = 'awaiting_token_rebind'
    send_telegram_message(chat_id, "🔄 إعادة ربط إيميل قديم\n\nالرجاء إرسال التوكن:")

def handle_message(chat_id, user_id, text):
    if not is_allowed(user_id):
        return

    if user_id not in user_states:
        return

    state = user_states[user_id]

    # عرض معلومات الحساب
    if state == 'awaiting_token_info':
        user_data[user_id] = {'token': text}
        user_states.pop(user_id, None)

        send_telegram_message(chat_id, "⏳ جاري جلب المعلومات...")
        result = show_info_api(text)
        send_telegram_message(chat_id, f"📊 معلومات الحساب:\n\n{result}")

    # ربط جديد - خطوة 1: استلام التوكن
    elif state == 'awaiting_token_bind':
        user_data[user_id] = {'token': text}
        user_states[user_id] = 'awaiting_code_bind'
        send_telegram_message(chat_id, "🔢 الرجاء إرسال الكود الأمني (6 أرقام):")

    # ربط جديد - خطوة 2: استلام الكود الأمني
    elif state == 'awaiting_code_bind':
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['code'] = text
        user_states[user_id] = 'awaiting_email_bind'
        send_telegram_message(chat_id, "📧 الرجاء إرسال الإيميل الجديد:")

    # ربط جديد - خطوة 3: استلام الإيميل وإرسال OTP
    elif state == 'awaiting_email_bind':
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['email'] = text
        send_telegram_message(chat_id, "🔄 جاري إرسال OTP إلى الإيميل...")
        send_otp_for_bind(chat_id, user_id, text)

    # ربط جديد - خطوة 4: استلام OTP وإتمام الربط
    elif state == 'awaiting_otp_bind':
        complete_bind(chat_id, user_id, text)

    # إعادة ربط - خطوة 1: استلام التوكن
    elif state == 'awaiting_token_rebind':
        user_data[user_id] = {'token': text}
        user_states[user_id] = 'awaiting_code_rebind'
        send_telegram_message(chat_id, "🔢 الرجاء إرسال الكود الأمني (6 أرقام):")

    # إعادة ربط - خطوة 2: استلام الكود الأمني
    elif state == 'awaiting_code_rebind':
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['code'] = text
        user_states[user_id] = 'awaiting_email_rebind'
        send_telegram_message(chat_id, "📧 الرجاء إرسال الإيميل الجديد:")

    # إعادة ربط - خطوة 3: استلام الإيميل وإرسال OTP
    elif state == 'awaiting_email_rebind':
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['email'] = text
        send_telegram_message(chat_id, "🔄 جاري إرسال OTP إلى الإيميل...")
        send_otp_for_rebind(chat_id, user_id, text)

    # إعادة ربط - خطوة 4: استلام OTP وإتمام إعادة الربط
    elif state == 'awaiting_otp_rebind':
        complete_rebind(chat_id, user_id, text)

    # إلغاء الاستعادة بالتوكن فقط
    elif state == 'awaiting_token_removemail':
        user_states.pop(user_id, None)
        removemailbytoken(chat_id, text)

    # إلغاء الاستعادة برمز الأمان - خطوة 1: استلام التوكن
    elif state == 'awaiting_token_removemailbycode':
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['token'] = text
        user_states[user_id] = 'awaiting_code_removemailbycode'
        send_telegram_message(chat_id, "🔢 الرجاء إرسال رمز الأمان (6 أرقام):")

    # إلغاء الاستعادة برمز الأمان - خطوة 2: استلام الرمز وإتمام العملية
    elif state == 'awaiting_code_removemailbycode':
        code = text
        token = user_data[user_id].get('token', '')
        user_states.pop(user_id, None)
        user_data.pop(user_id, None)
        removemailbycode(chat_id, code, token)

@app.route('/webhook', methods=['POST'])
def webhook():
    update = request.get_json()

    if 'message' in update:
        message = update['message']
        chat_id = message['chat']['id']
        user_id = message['from']['id']
        text = message.get('text', '')
        first_name = message['from'].get('first_name', 'User')

        if text.startswith('/'):
            if text == '/start':
                handle_start(chat_id, user_id, first_name)
            elif text == '/help':
                handle_help(chat_id, user_id)
            elif text == '/info':
                handle_info(chat_id, user_id)
            elif text == '/bind':
                handle_bind(chat_id, user_id)
            elif text == '/rebind':
                handle_rebind(chat_id, user_id)
            elif text == '/removemail':
                user_states[user_id] = 'awaiting_token_removemail'
                send_telegram_message(chat_id, "📝 أرسل التوكن الخاص بالحساب لإلغاء الاستعادة:")
            elif text == '/removemailbycode':
                user_states[user_id] = 'awaiting_token_removemailbycode'
                send_telegram_message(chat_id, "📝 أرسل التوكن الخاص بالحساب لإلغاء الاستعادة برمز الأمان:")
        else:
            handle_message(chat_id, user_id, text)

    return 'OK', 200

@app.route('/set_webhook', methods=['GET'])
def set_webhook():
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook"
    webhook_url = request.host_url.rstrip('/') + '/webhook'
    response = requests.post(url, json={'url': webhook_url})
    return jsonify(response.json())

if __name__ == '__main__':
    app.run()
