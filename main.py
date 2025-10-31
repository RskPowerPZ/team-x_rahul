from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import data_pb2
import hardest_pb2
import jwt_generator_pb2
import login_pb2
import MajorLoginReq_pb2
import MajorLoginRes_pb2
import message_pb2
import my_message_pb2
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Init colorama
init(autoreset=True)

# Flask setup
app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})


def get_token(password, uid):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception:
        return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict


def create_additional_protobufs(uid, token_data):
    
    # Create data objects
    nested_six = data_pb2.NestedSix()
    nested_six.six = 6
    
    inner_data = data_pb2.InnerData()
    inner_data.one = 1
    inner_data.two = 2
    inner_data.three = 3
    inner_data.four = 4
    inner_data.five = 5
    inner_data.six.CopyFrom(nested_six)
    
    nested_data = data_pb2.NestedData()
    nested_data.one = 100
    nested_data.two.append(inner_data)
    
    main_data = data_pb2.Data()
    main_data.one = 1000
    main_data.two.append(nested_data)
    
    # Create hardest_pb2 objects
    hardest_obj = hardest_pb2.hardest()
    hardest_obj.field1 = 1
    
    nested2 = hardest_obj.field2
    nested2.uid = int(uid) if uid.isdigit() else 123456
    nested2.region = "US"
    nested2.field3 = 3
    nested2.field4 = 4
    nested2.field5 = b"binary_data"
    nested2.name = "test_user"
    nested2.field7 = 7
    nested2.field8 = 8
    nested2.field10 = "field10_value"
    nested2.field11 = "field11_value"
    nested2.field12 = 12
    nested2.field13 = 13
    nested2.field16 = 16
    
    # Create nested17
    nested17 = nested2.field17
    nested17.field1 = "nested17_field1"
    nested17.field2 = 172
    nested17.filed3 = b"nested17_binary"
    nested17.filed4 = b"more_binary"
    nested17.field6 = 176
    nested17.field7 = b"final_binary"
    nested17.version = "1.0.0"
    nested17.field9 = 179
    nested17.field10 = 1710
    
    nested2.field18 = 18
    nested2.field19 = 19
    
    # Create nested20
    nested20 = nested2.field20.add()
    nested20.field1 = "nested20_field1"
    nested20.field2 = 202
    nested20.region = "EU"
    
    # Create nested23
    nested23 = nested2.field23
    nested23.field2 = 232
    nested23.field3 = 233
    
    nested2.avatar = 1001
    
    # Create nested26 and nested28
    nested2.field26.SetInParent()  # Empty message
    nested2.field28.SetInParent()  # Empty message
    
    # Create jwt_generator object
    jwt_msg = jwt_generator_pb2.Garena_420()
    jwt_msg.account_id = 123456789
    jwt_msg.region = "US"
    jwt_msg.place = "California"
    jwt_msg.location = "Los Angeles"
    jwt_msg.status = "active"
    jwt_msg.token = token_data.get('access_token', '')
    jwt_msg.id = 1
    jwt_msg.api = "v1"
    jwt_msg.number = 42
    
    # Create login_pb2 object
    login_req = login_pb2.LoginReq()
    login_req.account_id = 987654321
    login_req.account_type = 1
    login_req.region = "US"
    login_req.nickname = "test_player"
    login_req.create_at = 1633024800
    login_req.level = 50
    login_req.exp = 100000
    login_req.chat_server = "chat.server.com"
    login_req.voice_server = 8080
    login_req.event_log_url = "https://events.server.com/log"
    
    # Create MajorLoginReq object
    major_login = MajorLoginReq_pb2.MajorLogin()
    major_login.event_time = "2024-12-05 18:15:32"
    major_login.game_name = "free fire"
    major_login.platform_id = 4
    major_login.client_version = "1.108.3"
    major_login.system_software = "Android OS 9"
    major_login.system_hardware = "ASUS_I005DA"
    major_login.telecom_operator = "Verizon Wireless"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1280
    major_login.screen_height = 960
    major_login.screen_dpi = "240"
    major_login.processor_details = "ARMv7 VFPv3 NEON"
    major_login.memory = 5951
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.0"
    major_login.unique_device_id = "device_12345"
    major_login.client_ip = "172.190.111.97"
    major_login.language = "en"
    major_login.open_id = token_data.get('open_id', '')
    major_login.open_id_type = "google"
    major_login.device_type = "Handheld"
    major_login.access_token = token_data.get('access_token', '')
    major_login.platform_sdk_id = 2
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "1.108.3"
    major_login.external_storage_total = 65536
    major_login.external_storage_available = 32768
    major_login.internal_storage_total = 131072
    major_login.internal_storage_available = 65536
    major_login.game_disk_storage_available = 8192
    major_login.game_disk_storage_total = 16384
    major_login.external_sdcard_avail_storage = 4096
    major_login.external_sdcard_total_storage = 8192
    major_login.login_by = 1
    major_login.library_path = "/data/app/com.dts.freefireth/lib/arm"
    major_login.reg_avatar = 1
    major_login.library_token = "lib_token_123"
    major_login.channel_type = 1
    major_login.cpu_type = 1
    major_login.cpu_architecture = "ARMv7"
    major_login.client_version_code = "1.108.3"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"analytics_data"
    major_login.loading_time = 5000
    major_login.release_channel = "stable"
    major_login.extra_info = "additional_info"
    major_login.android_engine_init_flag = 1
    major_login.if_push = 1
    major_login.is_vpn = 0
    major_login.origin_platform_type = "android"
    major_login.primary_platform_type = "mobile"
    
    # Create game security
    game_security = major_login.memory_available
    game_security.version = 1
    game_security.hidden_value = 123456789
    
    # Create message object
    my_message = message_pb2.MyMessage()
    my_message.field1 = "test_field"
    my_message.field2 = 42
    my_message.field3 = b"message_binary"
    
    # Create my_message_pb2 object
    my_msg = my_message_pb2.MyMessage()
    my_msg.field21 = 2100
    my_msg.field22 = b"field22_binary"
    my_msg.field23 = b"field23_binary"
    
    return {
        'data': main_data,
        'hardest': hardest_obj,
        'jwt': jwt_msg,
        'login_req': login_req,
        'major_login': major_login,
        'my_message': my_message,
        'my_msg': my_msg
    }


@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({"error": "Both uid and password parameters are required"}), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again."
        }), 400

    # Create additional protobuf objects
    additional_objs = create_additional_protobufs(uid, token_data)

    game_data = my_pb2.GameData()
    game_data.timestamp = "2024-12-05 18:15:32"
    game_data.game_name = "free fire"
    game_data.game_version = 1
    game_data.version_code = "1.108.3"
    game_data.os_info = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)"
    game_data.device_type = "Handheld"
    game_data.network_provider = "Verizon Wireless"
    game_data.connection_type = "WIFI"
    game_data.screen_width = 1280
    game_data.screen_height = 960
    game_data.dpi = "240"
    game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
    game_data.total_ram = 5951
    game_data.gpu_name = "Adreno (TM) 640"
    game_data.gpu_version = "OpenGL ES 3.0"
    game_data.user_id = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610"
    game_data.ip_address = "172.190.111.97"
    game_data.language = "en"
    game_data.open_id = token_data['open_id']
    game_data.access_token = token_data['access_token']
    game_data.platform_type = 4
    game_data.device_form_factor = "Handheld"
    game_data.device_model = "Asus ASUS_I005DA"
    game_data.field_60 = 32968
    game_data.field_61 = 29815
    game_data.field_62 = 2479
    game_data.field_63 = 914
    game_data.field_64 = 31213
    game_data.field_65 = 32968
    game_data.field_66 = 31213
    game_data.field_67 = 32968
    game_data.field_70 = 4
    game_data.field_73 = 2
    game_data.library_path = "/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/lib/arm"
    game_data.field_76 = 1
    game_data.apk_info = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-QPvBnTUhYWE-7DMZSOGdmA==/base.apk"
    game_data.field_78 = 6
    game_data.field_79 = 1
    game_data.os_architecture = "32"
    game_data.build_number = "2019117877"
    game_data.field_85 = 1
    game_data.graphics_backend = "OpenGLES2"
    game_data.max_texture_units = 16383
    game_data.rendering_api = 4
    game_data.encoded_field_89 = "\u0017T\u0011\u0017\u0002\b\u000eUMQ\bEZ\u0003@ZK;Z\u0002\u000eV\ri[QVi\u0003\ro\t\u0007e"
    game_data.field_92 = 9204
    game_data.marketplace = "3rd_party"
    game_data.encryption_key = "KqsHT2B4It60T/65PGR5PXwFxQkVjGNi+IMCK3CFBCBfrNpSUA1dZnjaT3HcYchlIFFL1ZJOg0cnulKCPGD3C3h1eFQ="
    game_data.total_storage = 111107
    game_data.field_97 = 1
    game_data.field_98 = 1
    game_data.field_99 = "4"
    game_data.field_100 = "4"

    try:
        # Combine all data
        all_data = {
            'game_data': game_data.SerializeToString(),
            'additional_data': {
                'data': additional_objs['data'].SerializeToString(),
                'hardest': additional_objs['hardest'].SerializeToString(),
                'jwt': additional_objs['jwt'].SerializeToString(),
                'login_req': additional_objs['login_req'].SerializeToString(),
                'major_login': additional_objs['major_login'].SerializeToString(),
                'my_message': additional_objs['my_message'].SerializeToString(),
                'my_msg': additional_objs['my_msg'].SerializeToString()
            }
        }
        
        # Use game_data as primary for encryption
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB51"
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                
                # Also parse with MajorLoginRes_pb2
                major_login_res = MajorLoginRes_pb2.MajorLoginRes()
                try:
                    major_login_res.ParseFromString(response.content)
                    # Add additional response data
                    response_dict['account_id'] = major_login_res.account_id
                    response_dict['server_url'] = major_login_res.server_url
                    response_dict['ttl'] = major_login_res.ttl
                except:
                    pass
                
                return jsonify({
                    "uid": uid,
                    "status": response_dict.get("status", "N/A"),
                    "token": response_dict.get("token", "N/A"),
                    "accountID": response_dict.get("account_id", "N/A"),
                    "serverUrl": response_dict.get("server_url", "N/A"),
                    "ttl": response_dict.get("ttl", "N/A")
                })
            except Exception as e:
                return jsonify({
                    "uid": uid,
                    "error": f"Failed to deserialize the response: {str(e)}"
                }), 400
        else:
            return jsonify({
                "uid": uid,
                "error": f"Failed to get response: HTTP {response.status_code}, {response.reason}"
            }), 400
    except Exception as e:
        return jsonify({
            "uid": uid,
            "error": f"Internal error occurred: {str(e)}"
        }), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)