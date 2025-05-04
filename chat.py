#!/usr/bin/env python3
from flask import Flask, render_template, session, request
from flask_socketio import SocketIO
import requests
import json
import os
import logging
import sys
import time
import ssl
from datetime import datetime
from dotenv import load_dotenv
import urllib.request
import urllib.error
import http.client
import socket

# 加载环境变量
load_dotenv()

# 首先配置日志系统
logging.basicConfig(
    level=logging.DEBUG,  # 修改为DEBUG级别，获取更多信息
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ===== 修复SSL递归错误 =====
logger.info("应用SSL修复以避免递归错误...")

try:
    # 创建自定义SSL上下文
    ssl._create_default_https_context = ssl._create_unverified_context
    logger.debug("已设置自定义SSL上下文")
    
    # 导入和配置urllib3
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.debug("已禁用urllib3警告")
    
    # 修补requests会话，避免SSL验证
    old_merge_environment_settings = requests.Session.merge_environment_settings
    
    def patched_merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings
    
    requests.Session.merge_environment_settings = patched_merge_environment_settings
    logger.debug("已修补requests会话设置")
    
    # 设置默认不验证SSL
    requests.packages.urllib3.disable_warnings()
    
    logger.info("SSL修复应用完成")
except Exception as e:
    logger.error(f"应用SSL修复时出错: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())

# 添加详细错误追踪函数
def log_exception(e, prefix="错误"):
    """详细记录异常信息，包括堆栈跟踪"""
    import traceback
    error_trace = traceback.format_exc()
    logger.error(f"{prefix}: {str(e)}")
    logger.error(f"错误类型: {type(e).__name__}")
    logger.error(f"错误堆栈:\n{error_trace}")
    return error_trace

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

# 配置SocketIO，添加云端适配选项
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # 允许跨域请求
    ping_timeout=120,         # 进一步增加超时时间，避免长时间请求断开
    ping_interval=15,         # 减少ping间隔，提高连接稳定性
    async_mode='eventlet',    # 使用eventlet作为异步模式
    logger=True,              # 启用SocketIO日志
    engineio_logger=True      # 启用Engine.IO日志
)

API_URL = os.getenv('API_URL', 'https://api.x.ai/v1/chat/completions')

# Store chat history, user API keys and Tavily settings
# 使用类来管理会话，提高内存效率
class SessionManager:
    def __init__(self, max_conversations=50, max_messages_per_conversation=30):
        self.conversation_history = {}
        self.user_api_keys = {}
        self.user_tavily_settings = {}
        self.user_tavily_api_keys = {}
        self.max_conversations = max_conversations
        self.max_messages_per_conversation = max_messages_per_conversation
    
    def sanitize_message(self, message):
        """清理消息数据，确保格式正确且不包含无效数据"""
        try:
            if not isinstance(message, dict):
                logger.warning(f"消息格式不正确: {type(message)}")
                return None
            
            # 确保基本字段存在
            if 'role' not in message or 'content' not in message:
                logger.warning("消息缺少必要字段")
                return None
            
            # 清理并验证角色字段
            role = str(message.get('role', '')).strip().lower()
            if role not in ['system', 'user', 'assistant']:
                logger.warning(f"消息角色无效: {role}")
                role = 'user'  # 默认为用户消息
            
            # 清理内容字段
            content = str(message.get('content', '')).strip()
            if not content:
                logger.warning("消息内容为空")
                return None
            
            # 限制内容长度
            if len(content) > 10000:
                logger.warning(f"消息内容过长 ({len(content)}字符)，已截断")
                content = content[:10000] + "..."
            
            # 创建干净的消息对象
            clean_message = {
                'role': role,
                'content': content,
                'timestamp': message.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            }
            
            return clean_message
        except Exception as e:
            logger.error(f"清理消息时出错: {str(e)}")
            return None
    
    def cleanup_old_conversations(self):
        """清理旧会话以节省内存"""
        try:
            if len(self.conversation_history) > self.max_conversations:
                # 按时间戳排序并保留最新的会话
                sorted_convs = sorted(
                    self.conversation_history.items(),
                    key=lambda x: x[1].get('timestamp', ''),
                    reverse=True
                )[:self.max_conversations]
                # 直接创建新字典而不是修改现有字典
                self.conversation_history = {cid: conv for cid, conv in sorted_convs}
                logger.info(f"已清理旧会话，当前会话数: {len(self.conversation_history)}")
        except Exception as e:
            logger.error(f"清理旧会话时发生错误: {str(e)}")
    
    def add_message_to_conversation(self, conversation_id, message):
        """添加消息到会话，并在必要时清理旧消息"""
        try:
            # 清理消息数据
            clean_message = self.sanitize_message(message)
            if not clean_message:
                logger.warning(f"跳过添加无效消息到会话: {conversation_id}")
                return
            
            # 如果会话不存在，创建新会话
            if conversation_id not in self.conversation_history:
                self.conversation_history[conversation_id] = {
                    'messages': [],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'title': clean_message.get('content', '')[:30] + '...' if len(clean_message.get('content', '')) > 30 else clean_message.get('content', '')
                }
            
            conv = self.conversation_history[conversation_id]
            messages = conv['messages']
            
            # 如果消息数量超过限制，直接移除旧消息
            if len(messages) >= self.max_messages_per_conversation:
                # 保留系统消息和最新的消息
                system_messages = [msg for msg in messages if msg.get('role') == 'system']
                other_messages = [msg for msg in messages if msg.get('role') != 'system']
                
                # 计算要保留的非系统消息数量
                keep_count = max(1, self.max_messages_per_conversation - len(system_messages))
                # 只保留最新的消息
                kept_messages = system_messages + other_messages[-keep_count:]
                
                # 直接替换消息列表
                conv['messages'] = kept_messages
                logger.debug(f"会话 {conversation_id} 清理后的消息数: {len(kept_messages)}")
            
            # 添加新消息
            conv['messages'].append(clean_message)
            # 更新时间戳
            conv['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.debug(f"消息已添加到会话 {conversation_id}, 当前消息数: {len(conv['messages'])}")
            
            # 定期清理旧会话
            if len(self.conversation_history) > self.max_conversations:
                self.cleanup_old_conversations()
                
        except Exception as e:
            error_trace = log_exception(e, f"添加消息到会话 {conversation_id} 时发生错误")
            raise RuntimeError(f"添加消息到会话失败: {str(e)}")
    
    def get_conversation_messages(self, conversation_id):
        """获取会话消息"""
        try:
            messages = self.conversation_history.get(conversation_id, {}).get('messages', [])
            # 复制消息列表，避免引用问题
            return list(messages)
        except Exception as e:
            logger.error(f"获取会话消息时发生错误: {str(e)}")
            return []
            
    def get_conversation_count(self):
        """获取当前会话数量"""
        return len(self.conversation_history)
        
    def clear_old_data(self):
        """定期清理过期数据"""
        try:
            # 清理24小时前的会话
            current_time = datetime.now()
            old_conversations = []
            
            for cid, conv in self.conversation_history.items():
                try:
                    conv_time = datetime.strptime(conv['timestamp'], '%Y-%m-%d %H:%M:%S')
                    if (current_time - conv_time).days >= 1:
                        old_conversations.append(cid)
                except (ValueError, KeyError):
                    continue
            
            for cid in old_conversations:
                del self.conversation_history[cid]
                
            if old_conversations:
                logger.info(f"已清理 {len(old_conversations)} 个过期会话")
        except Exception as e:
            logger.error(f"清理过期数据时发生错误: {str(e)}")

# 初始化会话管理器，减小默认值以适应云环境
session_manager = SessionManager(max_conversations=50, max_messages_per_conversation=30)
conversation_history = session_manager.conversation_history
user_api_keys = session_manager.user_api_keys
user_tavily_settings = session_manager.user_tavily_settings
user_tavily_api_keys = session_manager.user_tavily_api_keys

# 添加定期清理任务
def cleanup_task():
    while True:
        try:
            session_manager.clear_old_data()
            time.sleep(3600)  # 每小时清理一次
        except Exception as e:
            logger.error(f"清理任务执行出错: {str(e)}")
            time.sleep(60)  # 出错后等待1分钟再试

def get_tavily_search_results(query, api_key):
    """使用Tavily API进行搜索，使用urllib库而非requests"""
    if not api_key:
        logger.warning("未设置Tavily API密钥")
        return None
    
    request_id = datetime.now().strftime('%Y%m%d%H%M%S')
    logger.debug(f"Tavily请求[{request_id}]开始: 查询={query[:30]}...")
    
    try:
        # 构建请求URL和数据
        url = 'https://api.tavily.com/search'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-Web-Client/1.0'
        }
        data = {
            'query': query,
            'search_depth': 'advanced',
            'include_answer': True
        }
        
        # 转换数据为JSON
        data_json = json.dumps(data)
        
        # 创建SSL上下文
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # 解析URL
        host = 'api.tavily.com'
        path = '/search'
        
        # 发送请求
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=10)
        logger.debug(f"Tavily请求[{request_id}]连接到: {host}")
        
        try:
            start_time = datetime.now()
            conn.request("POST", path, data_json, headers)
            
            # 获取响应
            response = conn.getresponse()
            status = response.status
            elapsed_time = (datetime.now() - start_time).total_seconds()
            logger.debug(f"Tavily请求[{request_id}]收到响应: 状态码={status}, 耗时={elapsed_time:.2f}秒")
            
            # 检查响应状态
            if status != 200:
                response_body = response.read().decode('utf-8')
                logger.error(f"Tavily请求[{request_id}]失败: 状态码={status}")
                logger.debug(f"Tavily请求[{request_id}]错误详情: {response_body[:200]}")
                return None
            
            # 读取并解析响应
            response_data = response.read().decode('utf-8')
            result = json.loads(response_data)
            
            # 验证响应格式
            if not isinstance(result, dict):
                logger.error(f"Tavily请求[{request_id}]响应格式错误: 不是字典类型")
                return None
            
            # 检查结果中是否包含answer字段
            if 'answer' in result:
                answer_length = len(result['answer'])
                logger.info(f"Tavily请求[{request_id}]成功: 回答长度={answer_length}字符")
                return result
            else:
                logger.warning(f"Tavily请求[{request_id}]缺少answer字段")
                return None
                
        finally:
            # 确保连接关闭
            conn.close()
            
    except json.JSONDecodeError as e:
        logger.error(f"Tavily请求[{request_id}]解析JSON失败: {str(e)}")
        return None
    except ssl.SSLError as e:
        logger.error(f"Tavily请求[{request_id}]SSL错误: {str(e)}")
        return None
    except http.client.HTTPException as e:
        logger.error(f"Tavily请求[{request_id}]HTTP错误: {str(e)}")
        return None
    except socket.timeout:
        logger.error(f"Tavily请求[{request_id}]连接超时")
        return None
    except Exception as e:
        error_trace = log_exception(e, f"Tavily请求[{request_id}]异常")
        return None

def get_conversation_id():
    if 'conversation_id' not in session:
        session['conversation_id'] = datetime.now().strftime('%Y%m%d%H%M%S')
    return session['conversation_id']

def calculate_tokens(messages):
    # Simple token calculation method, each character counts as 1 token
    total_tokens = sum(len(msg['content']) for msg in messages)
    return total_tokens

def send_message(messages, api_key=None):
    """向API发送消息并获取响应，使用urllib不依赖requests库"""
    if not api_key:
        logger.error("未设置API密钥")
        return {'error': '请先在设置中配置有效的API密钥'}
    
    try:
        # 验证消息格式
        if not isinstance(messages, list):
            logger.error("消息格式错误：不是列表类型")
            return {'error': '消息格式错误'}
        
        for msg in messages:
            if not isinstance(msg, dict) or 'role' not in msg or 'content' not in msg:
                logger.error("消息格式错误：缺少必要字段")
                return {'error': '消息格式错误'}
        
        # 记录请求详情
        request_id = datetime.now().strftime('%Y%m%d%H%M%S')
        logger.debug(f"API请求[{request_id}]初始化: 消息数={len(messages)}")
        logger.debug(f"API请求[{request_id}]URL: {API_URL}")
        
        # 从环境变量获取模型信息
        model = os.getenv('MODEL_NAME', 'grok-3-beta')
        temperature = float(os.getenv('TEMPERATURE', '0'))
        logger.debug(f"API请求[{request_id}]模型: {model}, 温度: {temperature}")
        
        # 构建请求数据
        data = {
            'messages': messages,
            'model': model,
            'stream': False,
            'temperature': temperature
        }
        
        # 记录请求数据大小
        data_json = json.dumps(data)
        request_size = len(data_json)
        logger.debug(f"API请求[{request_id}]数据大小: {request_size}字节")
        
        start_time = datetime.now()
        
        # 构建请求头
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-API-Client/1.0'
        }
        
        # 使用底层urllib库而不是requests
        import urllib.request
        import urllib.error
        import http.client
        
        # 重试配置
        max_retries = 3
        base_delay = 2
        
        # 执行请求
        for attempt in range(max_retries):
            try:
                current_delay = base_delay * (2 ** attempt)
                logger.debug(f"API请求[{request_id}]尝试: {attempt + 1}/{max_retries}")
                
                # 创建请求上下文
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                # 解析URL
                if API_URL.startswith('https://'):
                    logger.debug(f"API请求[{request_id}]使用HTTPS连接")
                    host = API_URL.replace('https://', '').split('/')[0]
                    path = '/' + '/'.join(API_URL.replace('https://', '').split('/')[1:])
                    conn = http.client.HTTPSConnection(host, context=ctx, timeout=60)
                else:
                    logger.debug(f"API请求[{request_id}]使用HTTP连接")
                    host = API_URL.replace('http://', '').split('/')[0]
                    path = '/' + '/'.join(API_URL.replace('http://', '').split('/')[1:])
                    conn = http.client.HTTPConnection(host, timeout=60)
                
                # 发送请求
                conn.request("POST", path, data_json, headers)
                
                # 获取响应
                start_response_time = datetime.now()
                response = conn.getresponse()
                response_status = response.status
                elapsed_time = (datetime.now() - start_response_time).total_seconds()
                
                logger.debug(f"API请求[{request_id}]响应状态码: {response_status}, 用时: {elapsed_time}秒")
                
                # 处理错误状态码
                if response_status != 200:
                    response_body = response.read().decode('utf-8')
                    logger.warning(f"API请求[{request_id}]返回非200状态码: {response_status}")
                    logger.debug(f"API请求[{request_id}]响应头: {dict(response.getheaders())}")
                    logger.debug(f"API请求[{request_id}]响应内容: {response_body[:200]}")
                    
                    if response_status == 401:
                        return {'error': 'API密钥无效或已过期，请更新您的API密钥'}
                    elif response_status == 429:
                        if attempt < max_retries - 1:
                            retry_after = int(dict(response.getheaders()).get('Retry-After', current_delay))
                            logger.warning(f"API请求[{request_id}]超限，等待 {retry_after} 秒后重试")
                            time.sleep(retry_after)
                            continue
                        return {'error': 'API请求频率超限，请稍后再试'}
                    elif response_status == 500:
                        if attempt < max_retries - 1:
                            logger.warning(f"API请求[{request_id}]服务器错误，等待 {current_delay} 秒后重试")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API服务器出现错误，请稍后再试'}
                    elif response_status == 503:
                        if attempt < max_retries - 1:
                            logger.warning(f"API请求[{request_id}]服务暂时不可用，等待 {current_delay} 秒后重试")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API服务暂时不可用，请稍后再试'}
                    else:
                        return {'error': f'API响应错误: {response_status}'}
                
                # 读取响应内容
                response_data = response.read().decode('utf-8')
                
                # 尝试获取并记录响应内容预览
                response_preview = response_data[:200] + '...' if len(response_data) > 200 else response_data
                logger.debug(f"API请求[{request_id}]响应预览: {response_preview}")
                
                # 解析响应JSON
                try:
                    response_json = json.loads(response_data)
                except json.JSONDecodeError as e:
                    logger.error(f"API请求[{request_id}]解析JSON失败: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
                    return {'error': 'API响应格式错误，请稍后再试'}
                
                # 验证响应结构
                if not isinstance(response_json, dict):
                    logger.error(f"API请求[{request_id}]响应不是字典类型")
                    return {'error': 'API响应格式错误'}
                
                # 检查是否包含必要字段
                if 'choices' not in response_json:
                    logger.error(f"API请求[{request_id}]响应缺少choices字段")
                    logger.debug(f"API请求[{request_id}]响应结构: {list(response_json.keys())}")
                    return {'error': 'API响应数据不完整'}
                
                if not isinstance(response_json['choices'], list):
                    logger.error(f"API请求[{request_id}]响应choices不是列表类型")
                    return {'error': 'API响应数据格式错误'}
                
                # 计算总处理时间
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                token_count = calculate_tokens(messages)
                
                logger.info(f"API请求[{request_id}]成功，总耗时: {response_time}秒")
                
                # 关闭连接
                conn.close()
                
                # 返回成功响应
                return {
                    'response': response_json,
                    'response_time': response_time,
                    'token_count': token_count
                }
                
            except urllib.error.URLError as e:
                logger.error(f"API请求[{request_id}]URL错误: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API连接错误: {str(e)}'}
                
            except http.client.HTTPException as e:
                logger.error(f"API请求[{request_id}]HTTP错误: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API请求错误: {str(e)}'}
                
            except socket.timeout:
                logger.error(f"API请求[{request_id}]连接超时")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': 'API请求超时，请检查网络连接后再试'}
                
            except Exception as e:
                error_trace = log_exception(e, f"API请求[{request_id}]异常")
                return {'error': f'API请求出现错误: {str(e)}'}
                
            finally:
                # 确保连接被关闭
                if 'conn' in locals():
                    try:
                        conn.close()
                    except:
                        pass
                
    except RecursionError as e:
        # 特别处理递归错误
        logger.critical(f"发送消息时遇到递归错误: {str(e)}")
        return {'error': 'API请求处理错误，请联系管理员检查服务器配置'}
    except Exception as e:
        error_trace = log_exception(e, "发送消息时发生未知错误")
        return {'error': '发生未知错误，请稍后再试'}

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('get_history')
def get_history():
    socketio.emit('update_history', {
        'conversations': [
            {
                'id': cid,
                'title': conv['title'],
                'timestamp': conv['timestamp']
            } for cid, conv in conversation_history.items()
        ]
    })

@socketio.on('get_conversation')
def get_conversation(data):
    conversation_id = data['conversation_id']
    if conversation_id in conversation_history:
        socketio.emit('load_conversation', {
            'messages': conversation_history[conversation_id]['messages']
        })

@socketio.on('new_conversation')
def handle_new_conversation():
    # Reset session ID
    session['conversation_id'] = datetime.now().strftime('%Y%m%d%H%M%S')
    # Clear current session history
    conversation_id = session.get('conversation_id')
    if conversation_id in conversation_history:
        del conversation_history[conversation_id]
    # Notify client that reset is complete
    socketio.emit('conversation_reset')

@socketio.on('delete_conversation')
def handle_delete_conversation(data):
    conversation_id = data['conversation_id']
    if conversation_id in conversation_history:
        del conversation_history[conversation_id]
        # Send updated history
        socketio.emit('update_history', {
            'conversations': [
                {
                    'id': cid,
                    'title': conv['title'],
                    'timestamp': conv['timestamp']
                } for cid, conv in conversation_history.items()
            ]
        })

@socketio.on('send_message')
def handle_message(data):
    # 添加请求ID用于跟踪
    request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(data))}"
    logger.info(f'开始处理消息请求 [ID:{request_id}]')
    
    try:
        # 基本验证
        if not data.get('message'):
            logger.error(f'[ID:{request_id}] 消息内容为空')
            socketio.emit('error', {'message': '消息内容不能为空'}, room=request.sid)
            return

        # 检查会话ID
        conversation_id = get_conversation_id()
        logger.debug(f'[ID:{request_id}] 会话ID: {conversation_id}')
        
        # 检查API密钥
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        if not api_key:
            logger.error(f'[ID:{request_id}] API密钥未设置')
            socketio.emit('error', {'message': '请先设置您的API密钥'}, room=request.sid)
            return

        # 记录关键请求信息
        logger.debug(f'[ID:{request_id}] API URL: {API_URL}')
        logger.debug(f'[ID:{request_id}] 消息长度: {len(data.get("message", ""))}字符')
        
        # 更新API密钥
        user_api_keys[request.sid] = api_key
        
        # 处理Tavily设置
        if 'tavily_enabled' in data:
            user_tavily_settings[request.sid] = data.get('tavily_enabled')
        if 'tavily_api_key' in data and data.get('tavily_api_key'):
            user_tavily_api_keys[request.sid] = data.get('tavily_api_key')

        # 消息长度检查
        if len(data.get('message', '')) > 4000:
            logger.warning(f'[ID:{request_id}] 消息过长: {len(data.get("message", ""))}字符')
            socketio.emit('error', {'message': '消息过长，请缩短您的消息'}, room=request.sid)
            return

        # 构建用户消息
        user_message = {
            'role': 'user',
            'content': data['message'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # 获取当前会话消息
        current_messages = []
        try:
            logger.debug(f'[ID:{request_id}] 尝试获取会话消息')
            current_messages = list(session_manager.get_conversation_messages(conversation_id))
            logger.debug(f'[ID:{request_id}] 当前会话消息数: {len(current_messages)}')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] 获取会话消息失败')
            # 继续处理，使用空列表
            current_messages = []

        # 添加用户消息
        try:
            logger.debug(f'[ID:{request_id}] 尝试添加用户消息到会话')
            session_manager.add_message_to_conversation(conversation_id, user_message)
            logger.debug(f'[ID:{request_id}] 用户消息已添加到会话')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] 添加用户消息失败')
            socketio.emit('error', {
                'message': '处理消息时发生错误，请重试', 
                'request_id': request_id
            }, room=request.sid)
            return

        # 发送处理确认
        socketio.emit('message_received', {
            'status': 'processing',
            'request_id': request_id
        }, room=request.sid)

        # 处理Tavily搜索
        search_results = None
        if user_tavily_settings.get(request.sid, False):
            tavily_api_key = user_tavily_api_keys.get(request.sid)
            if tavily_api_key:
                try:
                    logger.debug(f'[ID:{request_id}] 尝试执行Tavily搜索')
                    search_results = get_tavily_search_results(data['message'], tavily_api_key)
                    if search_results and 'answer' in search_results:
                        logger.debug(f'[ID:{request_id}] 搜索结果获取成功，长度: {len(search_results["answer"])}字符')
                        # 发送搜索成功通知给客户端
                        socketio.emit('search_status', {
                            'status': 'success',
                            'message': '已获取网络搜索结果',
                            'request_id': request_id
                        }, room=request.sid)
                    else:
                        logger.warning(f'[ID:{request_id}] 搜索结果为空或缺少answer字段')
                        # 发送搜索警告通知给客户端
                        socketio.emit('search_status', {
                            'status': 'warning',
                            'message': '网络搜索未返回结果，将使用模型直接回答',
                            'request_id': request_id
                        }, room=request.sid)
                except Exception as e:
                    error_trace = log_exception(e, f'[ID:{request_id}] Tavily搜索失败')
                    # 发送搜索错误通知给客户端
                    socketio.emit('search_status', {
                        'status': 'error',
                        'message': '网络搜索失败，将使用模型直接回答',
                        'request_id': request_id
                    }, room=request.sid)
            else:
                logger.warning(f'[ID:{request_id}] Tavily搜索已启用但未设置API密钥')
                # 发送搜索配置错误通知
                socketio.emit('search_status', {
                    'status': 'error',
                    'message': '请先设置您的Tavily API密钥',
                    'request_id': request_id
                }, room=request.sid)

        # 构建系统消息
        system_message = 'You are a helpful assistant.'
        if search_results and 'answer' in search_results:
            logger.debug(f'[ID:{request_id}] 使用搜索结果构建系统消息')
            search_answer = search_results['answer']
            
            # 如果有搜索上下文，也包含进去
            search_context = ""
            if 'context' in search_results and search_results['context']:
                # 检查context是否为列表
                if isinstance(search_results['context'], list):
                    # 合并前5个上下文项（如果有）
                    context_items = search_results['context'][:5]
                    for i, item in enumerate(context_items):
                        if isinstance(item, dict) and 'content' in item:
                            search_context += f"\n\n源 {i+1}:\n{item['content']}"
            
            # 构建增强的系统提示
            system_message = f"""You are a helpful assistant with internet search capability. I will provide you with some search results as background information.

Search Results:
{search_answer}
{search_context}

Please answer the user's question based on the search results above. If the search results are relevant, prioritize using information from them. If the search results are not relevant, you can ignore them and answer directly based on your knowledge. Always ensure your response is accurate, relevant, and helpful. Be very brief, unless the user request is complex and substantive. Give preference to recent information from search results over your training data."""

            logger.debug(f'[ID:{request_id}] 系统消息已包含搜索结果，长度: {len(system_message)}字符')
        else:
            logger.debug(f'[ID:{request_id}] 使用默认系统消息')

        # 构建API请求消息列表 - 修正这里的逻辑，确保消息按正确顺序添加
        messages = [{'role': 'system', 'content': system_message}]
        
        # 如果有现有会话消息，添加到系统消息之后
        if current_messages:
            messages.extend(current_messages)
        
        # 已经添加到会话历史中的用户消息不需要再添加
        # 检查最后一个消息是否已经是当前用户消息
        if not messages or messages[-1]['role'] != 'user' or messages[-1]['content'] != user_message['content']:
            messages.append(user_message)
            
        logger.debug(f'[ID:{request_id}] 准备发送API请求，总消息数: {len(messages)}，包含系统消息: {system_message[:50]}...')

        # 调用API
        try:
            logger.debug(f'[ID:{request_id}] 开始调用API')
            response_data = send_message(messages, api_key)
            logger.debug(f'[ID:{request_id}] API调用完成，检查响应')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] API调用失败')
            socketio.emit('error', {
                'message': 'API调用失败，请稍后重试',
                'request_id': request_id
            }, room=request.sid)
            return

        # 检查错误响应
        if 'error' in response_data:
            logger.error(f'[ID:{request_id}] API返回错误: {response_data["error"]}')
            socketio.emit('error', {
                'message': response_data['error'],
                'request_id': request_id
            }, room=request.sid)
            return

        # 验证响应格式
        if not (response_data and 'response' in response_data and 'choices' in response_data['response']):
            logger.error(f'[ID:{request_id}] API响应格式不符合预期: {json.dumps(response_data)}')
            socketio.emit('error', {
                'message': 'API响应格式错误',
                'request_id': request_id
            }, room=request.sid)
            return

        # 处理API响应
        try:
            # 提取助手回复
            choices = response_data['response']['choices']
            if not choices or not isinstance(choices, list) or len(choices) == 0:
                logger.error(f'[ID:{request_id}] API响应choices为空或格式错误')
                socketio.emit('error', {
                    'message': 'API响应数据不完整',
                    'request_id': request_id
                }, room=request.sid)
                return

            # 检查消息格式
            first_choice = choices[0]
            if not isinstance(first_choice, dict) or 'message' not in first_choice:
                logger.error(f'[ID:{request_id}] API响应choice格式错误: {json.dumps(first_choice)}')
                socketio.emit('error', {
                    'message': 'API响应数据格式错误',
                    'request_id': request_id
                }, room=request.sid)
                return

            # 提取消息内容
            message_obj = first_choice['message']
            if not isinstance(message_obj, dict) or 'content' not in message_obj:
                logger.error(f'[ID:{request_id}] API响应message格式错误: {json.dumps(message_obj)}')
                socketio.emit('error', {
                    'message': 'API响应消息格式错误',
                    'request_id': request_id
                }, room=request.sid)
                return

            # 获取内容
            assistant_message = message_obj['content']
            logger.debug(f'[ID:{request_id}] 成功提取助手回复，长度: {len(assistant_message)}字符')
            
            # 构建助手消息对象
            assistant_message_obj = {
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # 添加助手消息到会话
            try:
                logger.debug(f'[ID:{request_id}] 尝试添加助手回复到会话')
                session_manager.add_message_to_conversation(conversation_id, assistant_message_obj)
                logger.debug(f'[ID:{request_id}] 助手回复已添加到会话')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] 添加助手回复到会话失败')
                # 即使添加失败，也尝试返回响应给用户

            # 发送响应给客户端
            logger.debug(f'[ID:{request_id}] 发送响应给客户端')
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data.get('response_time', 0), 2),
                'token_count': response_data.get('token_count', 0),
                'request_id': request_id
            }, room=request.sid)

            # 更新会话列表
            try:
                logger.debug(f'[ID:{request_id}] 更新会话列表')
                conversations = [
                    {
                        'id': cid,
                        'title': conv['title'],
                        'timestamp': conv['timestamp']
                    } for cid, conv in session_manager.conversation_history.items()
                ]
                socketio.emit('update_history', {'conversations': conversations}, room=request.sid)
                logger.info(f'[ID:{request_id}] 消息处理完成')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] 更新会话列表失败')
                # 不阻止主要功能

        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] 处理API响应失败')
            socketio.emit('error', {
                'message': '处理响应时发生错误，请重试',
                'request_id': request_id
            }, room=request.sid)
            return

    except Exception as e:
        error_trace = log_exception(e, f'[ID:{request_id}] 消息处理主流程出错')
        socketio.emit('error', {
            'message': f'发生未知错误，请稍后再试',
            'request_id': request_id
        }, room=request.sid)

if __name__ == '__main__':
    from gevent import monkey
    monkey.patch_all()
    
    # 启动清理任务
    from threading import Thread
    cleanup_thread = Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    
    # 从环境变量获取端口，适应云平台要求
    port = int(os.getenv('PORT', 10000))
    
    # 记录启动信息
    logger.info(f"应用启动于端口: {port}")
    logger.info(f"API URL: {API_URL}")
    logger.info(f"最大会话数: {session_manager.max_conversations}")
    logger.info(f"每个会话最大消息数: {session_manager.max_messages_per_conversation}")
    
    # 在云环境中，通常会自动分配主机和端口
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port,
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )