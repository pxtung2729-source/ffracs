from flask import Flask, request, jsonify
import requests
import hashlib
import json
import os
import subprocess
from datetime import datetime

app = Flask(__name__)

BOT_TOKEN = "8658580899:AAGklJayHDFNGVlSRmRr6oC8J6i_YwLRcKA"
ADMIN_IDS = [8422582044, 8156132438]
ALLOWED_USERS = ADMIN_IDS.copy()

user_states = {}
user_data = {}

def is_allowed(user_id):
    return user_id in ALLOWED_USERS

def is_admin(user_id):
    return user_id in ADMIN_IDS

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

def send_telegram_message(chat_id, text, reply_markup=None):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': text,
        'parse_mode': 'HTML'
    }
    if reply_markup:
        payload['reply_markup'] = json.dumps(reply_markup)
    requests.post(url, json=payload)

def edit_telegram_message(chat_id, message_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/editMessageText"
    payload = {
        'chat_id': chat_id,
        'message_id': message_id,
        'text': text,
        'parse_mode': 'HTML'
    }
    requests.post(url, json=payload)

def answer_callback_query(callback_id, text=None):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery"
    payload = {'callback_query_id': callback_id}
    if text:
        payload['text'] = text
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

def simple_bind_flow_api(token, code, email, otp):
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
            'access_token': token,
            'email': email,
            'locale': "ar_EG"
        }
        
        headers = COMMON_HEADERS.copy()
        headers['Accept'] = "application/json"
        
        send_response = requests.post(url, data=payload, headers=headers)
        if send_response.status_code != 200:
            return f"❌ فشل إرسال OTP: {send_response.text}"
        
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
                    return f"✅ تم ربط الإيميل بنجاح!\n📧 الإيميل: {email}"
                else:
                    return f"❌ فشل الربط: {bind_response.text}"
            else:
                return "❌ لم يتم العثور على verifier_token"
        else:
            return f"❌ فشل التحقق: {verify_response.text}"
    except Exception as e:
        return f"❌ خطأ: {str(e)}"

def email_binding_api(token, code, email, otp):
    try:
        BASE_URL = "https://100067.connect.garena.com/game/account_security/bind"
        APP_ID = "100067"
        COMMON_HEADERS = {
            'User-Agent': "GarenaMSDK/4.0.19P9(J200F ;Android 7.1.2;ar;EG;)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip"
        }
        
        url = f"{BASE_URL}:verify_identity"
        payload = {
            'app_id': APP_ID,
            'access_token': token,
            'secondary_password': encrypt_number(code)
        }
        
        identity_response = requests.post(url, data=payload, headers=COMMON_HEADERS)
        if identity_response.status_code != 200:
            return f"❌ فشل التحقق من الهوية: {identity_response.text}"
        
        identity_token = identity_response.json().get("identity_token")
        if not identity_token:
            return "❌ لم يتم العثور على identity_token"
        
        url = f"{BASE_URL}:send_otp"
        payload = {
            'app_id': APP_ID,
            'access_token': token,
            'email': email,
            'locale': "ar_EG"
        }
        
        headers = COMMON_HEADERS.copy()
        headers['Accept'] = "application/json"
        headers['Cookie'] = "datadome=L5aWQatkvEKgi0kcs9RfqX3IJ6EI2JPR7uuWg8LmfZcX8Uc297Z1jzndyNgMh~zookrgYaD3hEHfMo9WNEZL1yyGy20TuVkkdiFFB9NNuHn7LuHs_WXyFF7XvfbntaJL"
        
        otp_response = requests.post(url, data=payload, headers=headers)
        if otp_response.status_code != 200:
            return f"❌ فشل إرسال OTP: {otp_response.text}"
        
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
                    return f"✅ تم ربط الإيميل بنجاح!\n📧 الإيميل: {email}"
                else:
                    return f"❌ فشل الربط: {rebind_response.text}"
            else:
                return "❌ لم يتم العثور على verifier_token"
        else:
            return f"❌ فشل التحقق: {verify_response.text}"
    except Exception as e:
        return f"❌ خطأ: {str(e)}"

def handle_start(chat_id, user_id, first_name):
    if not is_allowed(user_id):
        send_telegram_message(chat_id, "❌ ليس لديك صلاحية للوصول.")
        return
    
    markup = {
        "inline_keyboard": [
            [{"text": "📊 عرض المعلومات", "callback_data": "account_info"}],
            [{"text": "📧 ربط جديد", "callback_data": "bind_new"}],
            [{"text": "🔄 ربط قديم", "callback_data": "bind_old"}]
        ]
    }
    
    if is_admin(user_id):
        markup["inline_keyboard"].append([{"text": "👑 لوحة الأدمن", "callback_data": "admin_panel"}])
    
    welcome = f"""🤖 مدير حسابات جارينا

مرحباً {first_name}!

الأوامر المتاحة:
/info - عرض معلومات الحساب
/bind - ربط إيميل جديد
/rebind - إعادة ربط إيميل قديم
/help - عرض المساعدة
"""
    send_telegram_message(chat_id, welcome, markup)

def handle_help(chat_id, user_id):
    if not is_allowed(user_id):
        return
    
    help_text = """🤖 المساعدة:

/info - ابدأ عملية عرض معلومات الحساب
/bind - ابدأ عملية ربط إيميل جديد
/rebind - ابدأ عملية إعادة ربط إيميل قديم
/start - عرض القائمة الرئيسية

ملاحظة:
- ربط جديد: لحساب ليس له إيميل
- ربط قديم: لحساب له إيميل وتريد تغييره
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
            send_telegram_message(chat_id, "✅ تم إرسال OTP\n\n🔢 الرجاء إرسال رمز OTP:")
        else:
            user_states.pop(user_id, None)
            send_telegram_message(chat_id, f"❌ فشل إرسال OTP: {response.text}")
    except Exception as e:
        user_states.pop(user_id, None)
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")

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
            send_telegram_message(chat_id, "✅ تم إرسال OTP\n\n🔢 الرجاء إرسال رمز OTP:")
        else:
            user_states.pop(user_id, None)
            send_telegram_message(chat_id, f"❌ فشل إرسال OTP: {response.text}")
    except Exception as e:
        user_states.pop(user_id, None)
        send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")

def handle_callback_query(callback_data):
    callback_id = callback_data['id']
    chat_id = callback_data['message']['chat']['id']
    message_id = callback_data['message']['message_id']
    data = callback_data['data']
    user_id = callback_data['from']['id']
    
    if not is_allowed(user_id):
        answer_callback_query(callback_id, "❌ ليس لديك صلاحية")
        return
    
    if data == 'account_info':
        answer_callback_query(callback_id)
        handle_info(chat_id, user_id)
    
    elif data == 'bind_new':
        answer_callback_query(callback_id)
        handle_bind(chat_id, user_id)
    
    elif data == 'bind_old':
        answer_callback_query(callback_id)
        handle_rebind(chat_id, user_id)
    
    elif data == 'admin_panel':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        
        markup = {
            "inline_keyboard": [
                [{"text": "➕ إضافة مستخدم", "callback_data": "admin_add"},
                 {"text": "➖ حذف مستخدم", "callback_data": "admin_remove"}],
                [{"text": "📋 قائمة المستخدمين", "callback_data": "admin_list"}],
                [{"text": "🖥️ أوامر VPS", "callback_data": "admin_vps"}],
                [{"text": "↩️ رجوع", "callback_data": "back_menu"}]
            ]
        }
        
        try:
            edit_telegram_message(chat_id, message_id, "👑 لوحة الأدمن\n\nاختر الإجراء المطلوب:")
            send_telegram_message(chat_id, "اختر الإجراء:", markup)
        except:
            send_telegram_message(chat_id, "👑 لوحة الأدمن\n\nاختر الإجراء المطلوب:", markup)
    
    elif data == 'admin_list':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        
        admin_list = "\n".join([f"👑 {admin_id} (أدمن)" for admin_id in ADMIN_IDS])
        user_list = "\n".join([f"👤 {user_id}" for user_id in ALLOWED_USERS if user_id not in ADMIN_IDS])
        
        response = f"""📋 قائمة المستخدمين المسموح لهم:

الأدمن ({len(ADMIN_IDS)}):
{admin_list}

المستخدمون ({len(ALLOWED_USERS) - len(ADMIN_IDS)}):
{user_list if user_list else "لا يوجد مستخدمون"}

المجموع: {len(ALLOWED_USERS)} مستخدم
"""
        send_telegram_message(chat_id, response)
    
    elif data == 'admin_add':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        user_states[user_id] = 'awaiting_add_user'
        send_telegram_message(chat_id, "➕ الرجاء إرسال ID المستخدم لإضافته:")
    
    elif data == 'admin_remove':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        user_states[user_id] = 'awaiting_remove_user'
        send_telegram_message(chat_id, "➖ الرجاء إرسال ID المستخدم لحذفه:")
    
    elif data == 'admin_vps':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        
        markup = {
            "inline_keyboard": [
                [{"text": "📝 إرسال أمر", "callback_data": "vps_command"}],
                [{"text": "📊 حالة النظام", "callback_data": "vps_status"}],
                [{"text": "↩️ رجوع", "callback_data": "admin_panel"}]
            ]
        }
        
        try:
            edit_telegram_message(chat_id, message_id, "🖥️ أوامر VPS\n\nاختر الإجراء المطلوب:")
            send_telegram_message(chat_id, "اختر الإجراء:", markup)
        except:
            send_telegram_message(chat_id, "🖥️ أوامر VPS\n\nاختر الإجراء المطلوب:", markup)
    
    elif data == 'vps_command':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        user_states[user_id] = 'awaiting_vps_command'
        send_telegram_message(chat_id, "📝 الرجاء إرسال أمر VPS:")
    
    elif data == 'vps_status':
        if not is_admin(user_id):
            answer_callback_query(callback_id, "❌ أدمن فقط")
            return
        
        answer_callback_query(callback_id)
        
        msg_text = "⏳ جاري جلب حالة النظام..."
        send_telegram_message(chat_id, msg_text)
        
        try:
            commands = [
                ("🖥️ المضيف", "hostname"),
                ("📦 الذاكرة", "free -h"),
                ("💾 التخزين", "df -h"),
                ("🔥 المعالج", "uptime")
            ]
            
            results = []
            for name, cmd in commands:
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        output = result.stdout.strip()[:500]
                        results.append(f"{name}:\n{output}")
                    else:
                        results.append(f"{name}: ❌ فشل")
                except:
                    results.append(f"{name}: ⏱️ timeout")
            
            response = "📊 حالة النظام:\n\n" + "\n\n".join(results)
            send_telegram_message(chat_id, response)
        except Exception as e:
            send_telegram_message(chat_id, f"❌ خطأ: {str(e)}")
    
    elif data == 'back_menu':
        answer_callback_query(callback_id)
        handle_start(chat_id, user_id, callback_data['from'].get('first_name', 'User'))

def handle_message(chat_id, user_id, text, message_id=None):
    if not is_allowed(user_id):
        return
    
    if user_id not in user_states:
        return
    
    state = user_states[user_id]
    
    if state == 'awaiting_token_info':
        user_data[user_id] = {'token': text}
        user_states[user_id] = None
        
        msg_text = "⏳ جاري جلب المعلومات..."
        send_telegram_message(chat_id, msg_text)
        
        result = show_info_api(text)
        send_telegram_message(chat_id, f"📊 معلومات الحساب:\n\n{result}")
    
    elif state == 'awaiting_token_bind':
        user_data[user_id] = {'token': text}
        user_states[user_id] = 'awaiting_code_bind'
        send_telegram_message(chat_id, "🔢 الرجاء إرسال الكود الأمني (6 أرقام):")
    
    elif state == 'awaiting_code_bind':
        user_data[user_id]['code'] = text
        user_states[user_id] = 'awaiting_email_bind'
        send_telegram_message(chat_id, "📧 الرجاء إرسال الإيميل الجديد:")
    
    elif state == 'awaiting_email_bind':
        user_data[user_id]['email'] = text
        send_telegram_message(chat_id, "🔄 جاري إرسال OTP...")
        send_otp_for_bind(chat_id, user_id, text)
    
    elif state == 'awaiting_token_rebind':
        user_data[user_id] = {'token': text}
        user_states[user_id] = 'awaiting_code_rebind'
        send_telegram_message(chat_id, "🔢 الرجاء إرسال الكود الأمني (6 أرقام):")
    
    elif state == 'awaiting_code_rebind':
        user_data[user_id]['code'] = text
        user_states[user_id] = 'awaiting_email_rebind'
        send_telegram_message(chat_id, "📧 الرجاء إرسال الإيميل الجديد:")
    
    elif state == 'awaiting_email_rebind':
        user_data[user_id]['email'] = text
        send_telegram_message(chat_id, "🔄 جاري إرسال OTP...")
        send_otp_for_rebind(chat_id, user_id, text)
    
    elif state == 'awaiting_otp_bind':
        otp = text
        user_states.pop(user_id, None)
        
        token = user_data[user_id]['token']
        code = user_data[user_id]['code']
        email = user_data[user_id]['email']
        
        send_telegram_message(chat_id, "⏳ جاري ربط الإيميل...")
        result = simple_bind_flow_api(token, code, email, otp)
        send_telegram_message(chat_id, result)
    
    elif state == 'awaiting_otp_rebind':
        otp = text
        user_states.pop(user_id, None)
        
        token = user_data[user_id]['token']
        code = user_data[user_id]['code']
        email = user_data[user_id]['email']
        
        send_telegram_message(chat_id, "⏳ جاري إعادة ربط الإيميل...")
        result = email_binding_api(token, code, email, otp)
        send_telegram_message(chat_id, result)
    
    elif state == 'awaiting_add_user':
        if not is_admin(user_id):
            return
        
        try:
            new_user_id = int(text)
            
            if new_user_id in ALLOWED_USERS:
                send_telegram_message(chat_id, f"ℹ️ المستخدم {new_user_id} موجود بالفعل.")
            else:
                ALLOWED_USERS.append(new_user_id)
                send_telegram_message(chat_id, f"✅ تم إضافة المستخدم {new_user_id} بنجاح!")
        except ValueError:
            send_telegram_message(chat_id, "❌ ID المستخدم يجب أن يكون رقماً.")
        
        user_states.pop(user_id, None)
    
    elif state == 'awaiting_remove_user':
        if not is_admin(user_id):
            return
        
        try:
            remove_user_id = int(text)
            
            if remove_user_id in ADMIN_IDS:
                send_telegram_message(chat_id, "❌ لا يمكن حذف أدمن!")
            elif remove_user_id not in ALLOWED_USERS:
                send_telegram_message(chat_id, f"ℹ️ المستخدم {remove_user_id} غير موجود في القائمة.")
            else:
                ALLOWED_USERS.remove(remove_user_id)
                send_telegram_message(chat_id, f"✅ تم حذف المستخدم {remove_user_id} بنجاح!")
        except ValueError:
            send_telegram_message(chat_id, "❌ ID المستخدم يجب أن يكون رقماً.")
        
        user_states.pop(user_id, None)
    
    elif state == 'awaiting_vps_command':
        if not is_admin(user_id):
            return
        
        cmd = text
        user_states.pop(user_id, None)
        
        send_telegram_message(chat_id, f"🖥️ جاري تنفيذ الأمر:\n{cmd}")
        
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout.strip()
                error = result.stderr.strip()
                
                response = f"✅ تم التنفيذ بنجاح:\n\n"
                if output:
                    response += f"📤 المخرجات:\n{output[-2000:]}\n"
                if error:
                    response += f"⚠️ الأخطاء:\n{error[-1000:]}"
            else:
                output = result.stdout.strip()
                error = result.stderr.strip()
                
                response = f"❌ فشل التنفيذ:\n\n"
                if output:
                    response += f"📤 المخرجات:\n{output[-2000:]}\n"
                if error:
                    response += f"⚠️ الأخطاء:\n{error[-1000:]}"
            
            send_telegram_message(chat_id, response)
        except subprocess.TimeoutExpired:
            send_telegram_message(chat_id, "⏱️ انتهى الوقت المحدد للأمر")
        except Exception as e:
            send_telegram_message(chat_id, f"❌ خطأ:\n{str(e)}")

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
        else:
            handle_message(chat_id, user_id, text)
    
    elif 'callback_query' in update:
        handle_callback_query(update['callback_query'])
    
    return 'OK', 200

@app.route('/set_webhook', methods=['GET'])
def set_webhook():
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/setWebhook"
    webhook_url = request.host_url.rstrip('/') + '/webhook'
    response = requests.post(url, json={'url': webhook_url})
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000))
