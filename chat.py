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
    """Use Tavily API for web search using urllib library instead of requests
    
    This function performs a web search using the Tavily API:
    1. Validates the API key
    2. Prepares the search request
    3. Sends the request using a custom SSL context
    4. Processes and validates the response
    
    Args:
        query (str): The search query to send to Tavily
        api_key (str): Tavily API key for authentication
        
    Returns:
        dict or None: Search results with answer and context, or None on failure
    """
    if not api_key:
        logger.warning("Tavily API key not set")
        return None
    
    request_id = datetime.now().strftime('%Y%m%d%H%M%S')
    logger.debug(f"Tavily request[{request_id}] started: query={query[:30]}...")
    
    try:
        # Step 1: Prepare request URL and headers
        url = 'https://api.tavily.com/search'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-Web-Client/1.0'
        }
        
        # Step 2: Prepare request data
        data = {
            'query': query,
            'search_depth': 'advanced',
            'include_answer': True
        }
        
        # Step 3: Convert data to JSON
        data_json = json.dumps(data)
        
        # Step 4: Create SSL context to avoid recursion issues
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Step 5: Set host and path for the request
        host = 'api.tavily.com'
        path = '/search'
        
        # Step 6: Create HTTPS connection
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=10)
        logger.debug(f"Tavily request[{request_id}] connecting to: {host}")
        
        try:
            # Step 7: Send the request and record timing
            start_time = datetime.now()
            conn.request("POST", path, data_json, headers)
            
            # Step 8: Get the response
            response = conn.getresponse()
            status = response.status
            elapsed_time = (datetime.now() - start_time).total_seconds()
            logger.debug(f"Tavily request[{request_id}] response received: status={status}, time={elapsed_time:.2f}s")
            
            # Step 9: Check response status
            if status != 200:
                response_body = response.read().decode('utf-8')
                logger.error(f"Tavily request[{request_id}] failed: status={status}")
                logger.debug(f"Tavily request[{request_id}] error details: {response_body[:200]}")
                return None
            
            # Step 10: Read and parse the response
            response_data = response.read().decode('utf-8')
            result = json.loads(response_data)
            
            # Step 11: Validate response format
            if not isinstance(result, dict):
                logger.error(f"Tavily request[{request_id}] invalid response format: not a dictionary")
                return None
            
            # Step 12: Check if response contains answer field
            if 'answer' in result:
                answer_length = len(result['answer'])
                logger.info(f"Tavily request[{request_id}] successful: answer_length={answer_length} characters")
                return result
            else:
                logger.warning(f"Tavily request[{request_id}] missing answer field")
                return None
                
        finally:
            # Step 13: Ensure connection is closed
            conn.close()
            
    except json.JSONDecodeError as e:
        logger.error(f"Tavily request[{request_id}] JSON parse error: {str(e)}")
        return None
    except ssl.SSLError as e:
        logger.error(f"Tavily request[{request_id}] SSL error: {str(e)}")
        return None
    except http.client.HTTPException as e:
        logger.error(f"Tavily request[{request_id}] HTTP error: {str(e)}")
        return None
    except socket.timeout:
        logger.error(f"Tavily request[{request_id}] connection timeout")
        return None
    except Exception as e:
        error_trace = log_exception(e, f"Tavily request[{request_id}] exception")
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
    """Send message to API using urllib instead of requests library
    
    This function handles the entire API communication process:
    1. Validates the input messages
    2. Prepares the request with proper headers
    3. Sends the request using low-level HTTP client
    4. Handles various error scenarios
    5. Processes and validates the response
    
    Args:
        messages (list): List of message objects with role and content
        api_key (str, optional): API key for authentication
        
    Returns:
        dict: Response data or error information
    """
    if not api_key:
        logger.error("API key not set")
        return {'error': 'Please configure a valid API key in settings'}
    
    try:
        # Step 1: Validate message format
        if not isinstance(messages, list):
            logger.error("Invalid message format: not a list type")
            return {'error': 'Invalid message format'}
        
        for msg in messages:
            if not isinstance(msg, dict) or 'role' not in msg or 'content' not in msg:
                logger.error("Invalid message format: missing required fields")
                return {'error': 'Invalid message format'}
        
        # Step 2: Log request details with unique ID for tracking
        request_id = datetime.now().strftime('%Y%m%d%H%M%S')
        logger.debug(f"API request[{request_id}] initialized: message_count={len(messages)}")
        logger.debug(f"API request[{request_id}] URL: {API_URL}")
        
        # Step 3: Get model settings from environment variables
        model = os.getenv('MODEL_NAME', 'grok-3-beta')
        temperature = float(os.getenv('TEMPERATURE', '0'))
        logger.debug(f"API request[{request_id}] model: {model}, temperature: {temperature}")
        
        # Step 4: Build request data
        data = {
            'messages': messages,
            'model': model,
            'stream': False,
            'temperature': temperature
        }
        
        # Step 5: Convert data to JSON and calculate request size
        data_json = json.dumps(data)
        request_size = len(data_json)
        logger.debug(f"API request[{request_id}] data size: {request_size} bytes")
        
        # Step 6: Record start time for performance tracking
        start_time = datetime.now()
        
        # Step 7: Prepare request headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-API-Client/1.0'
        }
        
        # Step 8: Configure retry settings
        max_retries = 3
        base_delay = 2
        
        # Step 9: Execute request with retry logic
        for attempt in range(max_retries):
            try:
                # Calculate exponential backoff delay for retries
                current_delay = base_delay * (2 ** attempt)
                logger.debug(f"API request[{request_id}] attempt: {attempt + 1}/{max_retries}")
                
                # Step 10: Create custom SSL context to avoid recursion issues
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                # Step 11: Parse URL and create appropriate connection
                if API_URL.startswith('https://'):
                    logger.debug(f"API request[{request_id}] using HTTPS connection")
                    host = API_URL.replace('https://', '').split('/')[0]
                    path = '/' + '/'.join(API_URL.replace('https://', '').split('/')[1:])
                    conn = http.client.HTTPSConnection(host, context=ctx, timeout=60)
                else:
                    logger.debug(f"API request[{request_id}] using HTTP connection")
                    host = API_URL.replace('http://', '').split('/')[0]
                    path = '/' + '/'.join(API_URL.replace('http://', '').split('/')[1:])
                    conn = http.client.HTTPConnection(host, timeout=60)
                
                # Step 12: Send the request
                conn.request("POST", path, data_json, headers)
                
                # Step 13: Get and process the response
                start_response_time = datetime.now()
                response = conn.getresponse()
                response_status = response.status
                elapsed_time = (datetime.now() - start_response_time).total_seconds()
                
                logger.debug(f"API request[{request_id}] response status: {response_status}, time: {elapsed_time}s")
                
                # Step 14: Handle error status codes
                if response_status != 200:
                    response_body = response.read().decode('utf-8')
                    logger.warning(f"API request[{request_id}] non-200 status: {response_status}")
                    logger.debug(f"API request[{request_id}] response headers: {dict(response.getheaders())}")
                    logger.debug(f"API request[{request_id}] response content: {response_body[:200]}")
                    
                    # Handle different error status codes
                    if response_status == 401:
                        return {'error': 'Invalid or expired API key, please update your API key'}
                    elif response_status == 429:
                        if attempt < max_retries - 1:
                            retry_after = int(dict(response.getheaders()).get('Retry-After', current_delay))
                            logger.warning(f"API request[{request_id}] rate limited, waiting {retry_after}s before retry")
                            time.sleep(retry_after)
                            continue
                        return {'error': 'API request rate limit exceeded, please try again later'}
                    elif response_status == 500:
                        if attempt < max_retries - 1:
                            logger.warning(f"API request[{request_id}] server error, waiting {current_delay}s before retry")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API server error, please try again later'}
                    elif response_status == 503:
                        if attempt < max_retries - 1:
                            logger.warning(f"API request[{request_id}] service unavailable, waiting {current_delay}s before retry")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API service temporarily unavailable, please try again later'}
                    else:
                        return {'error': f'API response error: {response_status}'}
                
                # Step 15: Read and decode response content
                response_data = response.read().decode('utf-8')
                
                # Step 16: Log response preview
                response_preview = response_data[:200] + '...' if len(response_data) > 200 else response_data
                logger.debug(f"API request[{request_id}] response preview: {response_preview}")
                
                # Step 17: Parse response JSON
                try:
                    response_json = json.loads(response_data)
                except json.JSONDecodeError as e:
                    logger.error(f"API request[{request_id}] JSON parse error: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
                    return {'error': 'API response format error, please try again later'}
                
                # Step 18: Validate response structure
                if not isinstance(response_json, dict):
                    logger.error(f"API request[{request_id}] response not a dictionary")
                    return {'error': 'API response format error'}
                
                # Step 19: Verify required fields exist
                if 'choices' not in response_json:
                    logger.error(f"API request[{request_id}] response missing 'choices' field")
                    logger.debug(f"API request[{request_id}] response structure: {list(response_json.keys())}")
                    return {'error': 'API response data incomplete'}
                
                if not isinstance(response_json['choices'], list):
                    logger.error(f"API request[{request_id}] 'choices' field not a list")
                    return {'error': 'API response data format error'}
                
                # Step 20: Calculate total processing time
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                token_count = calculate_tokens(messages)
                
                logger.info(f"API request[{request_id}] successful, total time: {response_time}s")
                
                # Step 21: Close connection
                conn.close()
                
                # Step 22: Return successful response
                return {
                    'response': response_json,
                    'response_time': response_time,
                    'token_count': token_count
                }
                
            except urllib.error.URLError as e:
                # Handle URL errors (DNS issues, connectivity problems)
                logger.error(f"API request[{request_id}] URL error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API connection error: {str(e)}'}
                
            except http.client.HTTPException as e:
                # Handle HTTP protocol errors
                logger.error(f"API request[{request_id}] HTTP error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API request error: {str(e)}'}
                
            except socket.timeout:
                # Handle timeout errors
                logger.error(f"API request[{request_id}] connection timeout")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': 'API request timeout, please check your network connection'}
                
            except Exception as e:
                # Handle all other exceptions
                error_trace = log_exception(e, f"API request[{request_id}] exception")
                return {'error': f'API request error: {str(e)}'}
                
            finally:
                # Ensure connection is always closed to prevent resource leaks
                if 'conn' in locals():
                    try:
                        conn.close()
                    except:
                        pass
                
    except RecursionError as e:
        # Special handling for recursion errors that might occur in SSL module
        logger.critical(f"Recursion error while sending message: {str(e)}")
        return {'error': 'API request processing error, please contact administrator'}
    except Exception as e:
        # Catch-all for any other exceptions
        error_trace = log_exception(e, "Unknown error while sending message")
        return {'error': 'Unknown error occurred, please try again later'}

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
    """Handle incoming messages from the client
    
    This function processes messages sent by the client:
    1. Validates the message and API keys
    2. Adds user message to conversation history
    3. Performs web search if enabled
    4. Constructs prompt with search results
    5. Calls AI API to generate a response
    6. Processes and returns the response to the client
    
    Args:
        data (dict): Message data from the client containing the message text and settings
    """
    # Generate unique request ID for tracking
    request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(data))}"
    logger.info(f'Processing message request [ID:{request_id}]')
    
    try:
        # Step 1: Basic validation
        if not data.get('message'):
            logger.error(f'[ID:{request_id}] Empty message content')
            socketio.emit('error', {'message': 'Message content cannot be empty'}, room=request.sid)
            return

        # Step 2: Get conversation ID from session
        conversation_id = get_conversation_id()
        logger.debug(f'[ID:{request_id}] Conversation ID: {conversation_id}')
        
        # Step 3: Check API key
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        if not api_key:
            logger.error(f'[ID:{request_id}] API key not set')
            socketio.emit('error', {'message': 'Please set your API key first'}, room=request.sid)
            return

        # Step 4: Log key request information
        logger.debug(f'[ID:{request_id}] API URL: {API_URL}')
        logger.debug(f'[ID:{request_id}] Message length: {len(data.get("message", ""))} characters')
        
        # Step 5: Update API key in session
        user_api_keys[request.sid] = api_key
        
        # Step 6: Process Tavily settings
        if 'tavily_enabled' in data:
            user_tavily_settings[request.sid] = data.get('tavily_enabled')
        if 'tavily_api_key' in data and data.get('tavily_api_key'):
            user_tavily_api_keys[request.sid] = data.get('tavily_api_key')

        # Step 7: Check message length
        if len(data.get('message', '')) > 4000:
            logger.warning(f'[ID:{request_id}] Message too long: {len(data.get("message", ""))} characters')
            socketio.emit('error', {'message': 'Message too long, please shorten it'}, room=request.sid)
            return

        # Step 8: Build user message object
        user_message = {
            'role': 'user',
            'content': data['message'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Step 9: Get current conversation messages
        current_messages = []
        try:
            logger.debug(f'[ID:{request_id}] Retrieving conversation messages')
            current_messages = list(session_manager.get_conversation_messages(conversation_id))
            logger.debug(f'[ID:{request_id}] Current message count: {len(current_messages)}')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to retrieve conversation messages')
            # Continue with empty list
            current_messages = []

        # Step 10: Add user message to conversation
        try:
            logger.debug(f'[ID:{request_id}] Adding user message to conversation')
            session_manager.add_message_to_conversation(conversation_id, user_message)
            logger.debug(f'[ID:{request_id}] User message added to conversation')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to add user message')
            socketio.emit('error', {
                'message': 'Error processing message, please try again', 
                'request_id': request_id
            }, room=request.sid)
            return

        # Step 11: Send processing confirmation
        socketio.emit('message_received', {
            'status': 'processing',
            'request_id': request_id
        }, room=request.sid)

        # Step 12: Perform web search if enabled
        search_results = None
        if user_tavily_settings.get(request.sid, False):
            tavily_api_key = user_tavily_api_keys.get(request.sid)
            if tavily_api_key:
                try:
                    logger.debug(f'[ID:{request_id}] Attempting Tavily search')
                    search_results = get_tavily_search_results(data['message'], tavily_api_key)
                    if search_results and 'answer' in search_results:
                        logger.debug(f'[ID:{request_id}] Search results retrieved, length: {len(search_results["answer"])} characters')
                        # Send search success notification to client
                        socketio.emit('search_status', {
                            'status': 'success',
                            'message': 'Web search results retrieved',
                            'request_id': request_id
                        }, room=request.sid)
                    else:
                        logger.warning(f'[ID:{request_id}] Search results empty or missing answer field')
                        # Send search warning notification to client
                        socketio.emit('search_status', {
                            'status': 'warning',
                            'message': 'No web search results found, model will answer directly',
                            'request_id': request_id
                        }, room=request.sid)
                except Exception as e:
                    error_trace = log_exception(e, f'[ID:{request_id}] Tavily search failed')
                    # Send search error notification to client
                    socketio.emit('search_status', {
                        'status': 'error',
                        'message': 'Web search failed, model will answer directly',
                        'request_id': request_id
                    }, room=request.sid)
            else:
                logger.warning(f'[ID:{request_id}] Tavily search enabled but API key not set')
                # Send search configuration error notification
                socketio.emit('search_status', {
                    'status': 'error',
                    'message': 'Please set your Tavily API key first',
                    'request_id': request_id
                }, room=request.sid)

        # Step 13: Build system message
        system_message = 'You are a helpful assistant.'
        if search_results and 'answer' in search_results:
            logger.debug(f'[ID:{request_id}] Building system message with search results')
            search_answer = search_results['answer']
            
            # Include search context if available
            search_context = ""
            if 'context' in search_results and search_results['context']:
                # Check if context is a list
                if isinstance(search_results['context'], list):
                    # Merge up to 5 context items (if available)
                    context_items = search_results['context'][:5]
                    for i, item in enumerate(context_items):
                        if isinstance(item, dict) and 'content' in item:
                            search_context += f"\n\nSource {i+1}:\n{item['content']}"
            
            # Build enhanced system prompt
            system_message = f"""You are a helpful assistant with internet search capability. I will provide you with some search results as background information.

Search Results:
{search_answer}
{search_context}

Please answer the user's question based on the search results above. If the search results are relevant, prioritize using information from them. If the search results are not relevant, you can ignore them and answer directly based on your knowledge. Always ensure your response is accurate, relevant, and helpful. Be very brief, unless the user request is complex and substantive. Give preference to recent information from search results over your training data."""

            logger.debug(f'[ID:{request_id}] System message includes search results, length: {len(system_message)} characters')
        else:
            logger.debug(f'[ID:{request_id}] Using default system message')

        # Step 14: Build API request message list - fix logic to ensure messages are added in correct order
        messages = [{'role': 'system', 'content': system_message}]
        
        # Add existing conversation messages after system message
        if current_messages:
            messages.extend(current_messages)
        
        # Check if the last message is already the current user message
        if not messages or messages[-1]['role'] != 'user' or messages[-1]['content'] != user_message['content']:
            messages.append(user_message)
            
        logger.debug(f'[ID:{request_id}] Preparing to send API request, total messages: {len(messages)}, system message: {system_message[:50]}...')

        # Step 15: Call API
        try:
            logger.debug(f'[ID:{request_id}] Starting API call')
            response_data = send_message(messages, api_key)
            logger.debug(f'[ID:{request_id}] API call completed, checking response')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] API call failed')
            socketio.emit('error', {
                'message': 'API call failed, please try again later',
                'request_id': request_id
            }, room=request.sid)
            return

        # Step 16: Check for errors in response
        if 'error' in response_data:
            logger.error(f'[ID:{request_id}] API returned error: {response_data["error"]}')
            socketio.emit('error', {
                'message': response_data['error'],
                'request_id': request_id
            }, room=request.sid)
            return

        # Step 17: Validate response format
        if not (response_data and 'response' in response_data and 'choices' in response_data['response']):
            logger.error(f'[ID:{request_id}] API response format unexpected: {json.dumps(response_data)}')
            socketio.emit('error', {
                'message': 'API response format error',
                'request_id': request_id
            }, room=request.sid)
            return

        # Step 18: Process API response
        try:
            # Extract assistant reply
            choices = response_data['response']['choices']
            if not choices or not isinstance(choices, list) or len(choices) == 0:
                logger.error(f'[ID:{request_id}] API response choices empty or format error')
                socketio.emit('error', {
                    'message': 'API response data incomplete',
                    'request_id': request_id
                }, room=request.sid)
                return

            # Check message format
            first_choice = choices[0]
            if not isinstance(first_choice, dict) or 'message' not in first_choice:
                logger.error(f'[ID:{request_id}] API response choice format error: {json.dumps(first_choice)}')
                socketio.emit('error', {
                    'message': 'API response data format error',
                    'request_id': request_id
                }, room=request.sid)
                return

            # Extract message content
            message_obj = first_choice['message']
            if not isinstance(message_obj, dict) or 'content' not in message_obj:
                logger.error(f'[ID:{request_id}] API response message format error: {json.dumps(message_obj)}')
                socketio.emit('error', {
                    'message': 'API response message format error',
                    'request_id': request_id
                }, room=request.sid)
                return

            # Get content
            assistant_message = message_obj['content']
            logger.debug(f'[ID:{request_id}] Successfully extracted assistant reply, length: {len(assistant_message)} characters')
            
            # Step 19: Build assistant message object
            assistant_message_obj = {
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Step 20: Add assistant message to conversation
            try:
                logger.debug(f'[ID:{request_id}] Adding assistant reply to conversation')
                session_manager.add_message_to_conversation(conversation_id, assistant_message_obj)
                logger.debug(f'[ID:{request_id}] Assistant reply added to conversation')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] Failed to add assistant reply to conversation')
                # Continue to return response to user even if saving fails

            # Step 21: Send response to client
            logger.debug(f'[ID:{request_id}] Sending response to client')
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data.get('response_time', 0), 2),
                'token_count': response_data.get('token_count', 0),
                'request_id': request_id
            }, room=request.sid)

            # Step 22: Update conversation list
            try:
                logger.debug(f'[ID:{request_id}] Updating conversation list')
                conversations = [
                    {
                        'id': cid,
                        'title': conv['title'],
                        'timestamp': conv['timestamp']
                    } for cid, conv in session_manager.conversation_history.items()
                ]
                socketio.emit('update_history', {'conversations': conversations}, room=request.sid)
                logger.info(f'[ID:{request_id}] Message processing completed')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] Failed to update conversation list')
                # Don't block main functionality

        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to process API response')
            socketio.emit('error', {
                'message': 'Error processing response, please try again',
                'request_id': request_id
            }, room=request.sid)
            return

    except Exception as e:
        error_trace = log_exception(e, f'[ID:{request_id}] Error in main message processing flow')
        socketio.emit('error', {
            'message': 'Unknown error occurred, please try again later',
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