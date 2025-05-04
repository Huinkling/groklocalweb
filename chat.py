#!/usr/bin/env python3
from flask import Flask, render_template, session, request
from flask_socketio import SocketIO
import requests
import json
import os
import logging
import sys
import time
from datetime import datetime
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

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
        self.max_conversations = max_conversations
        self.max_messages_per_conversation = max_messages_per_conversation
    
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
            # 如果会话不存在，创建新会话
            if conversation_id not in self.conversation_history:
                self.conversation_history[conversation_id] = {
                    'messages': [],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'title': message.get('content', '')[:30] + '...' if len(message.get('content', '')) > 30 else message.get('content', '')
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
            
            # 添加新消息
            conv['messages'].append(message)
            # 更新时间戳
            conv['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # 定期清理旧会话
            if len(self.conversation_history) > self.max_conversations:
                self.cleanup_old_conversations()
                
        except Exception as e:
            logger.error(f"添加消息到会话时发生错误: {str(e)}")
            raise
    
    def get_conversation_messages(self, conversation_id):
        """获取会话消息"""
        try:
            return self.conversation_history.get(conversation_id, {}).get('messages', [])
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

# 初始化会话管理器
session_manager = SessionManager(max_conversations=50, max_messages_per_conversation=30)
conversation_history = session_manager.conversation_history
user_api_keys = session_manager.user_api_keys

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
    if not api_key:
        return None
    url = 'https://api.tavily.com/search'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    data = {
        'query': query,
        'search_depth': 'advanced',
        'include_answer': True
    }
    try:
        # 添加超时设置，避免长时间等待
        response = requests.post(url, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.Timeout:
        logger.error("Tavily API 请求超时")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f'Tavily API 错误: {str(e)}')
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
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
        
        # 从环境变量获取模型名称和温度设置
        model = os.getenv('MODEL_NAME', 'grok-3-beta')
        temperature = float(os.getenv('TEMPERATURE', '0'))
        
        # 构建请求数据
        data = {
            'messages': messages,
            'model': model,
            'stream': False,
            'temperature': temperature
        }
        
        start_time = datetime.now()
        
        # 添加超时设置和重试机制
        max_retries = 3
        base_delay = 2  # 基础延迟时间（秒）
        
        for attempt in range(max_retries):
            try:
                current_delay = base_delay * (2 ** attempt)  # 指数退避
                
                # 发送请求
                response = requests.post(
                    API_URL,
                    headers=headers,
                    json=data,
                    timeout=60  # 60秒超时
                )
                
                # 记录响应状态
                logger.info(f"API响应状态码: {response.status_code}")
                
                # 处理常见错误状态码
                if response.status_code == 401:
                    return {'error': 'API密钥无效或已过期，请更新您的API密钥'}
                elif response.status_code == 429:
                    if attempt < max_retries - 1:
                        retry_after = int(response.headers.get('Retry-After', current_delay))
                        logger.warning(f"API请求超限，等待 {retry_after} 秒后重试")
                        time.sleep(retry_after)
                        continue
                    return {'error': 'API请求频率超限，请稍后再试'}
                elif response.status_code == 500:
                    if attempt < max_retries - 1:
                        logger.warning(f"API服务器错误，等待 {current_delay} 秒后重试")
                        time.sleep(current_delay)
                        continue
                    return {'error': 'API服务器出现错误，请稍后再试'}
                elif response.status_code == 503:
                    if attempt < max_retries - 1:
                        logger.warning(f"API服务暂时不可用，等待 {current_delay} 秒后重试")
                        time.sleep(current_delay)
                        continue
                    return {'error': 'API服务暂时不可用，请稍后再试'}
                
                # 确保响应状态码正常
                response.raise_for_status()
                
                # 解析响应数据
                try:
                    response_data = response.json()
                except json.JSONDecodeError as e:
                    logger.error(f"解析API响应JSON时出错: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
                    return {'error': 'API响应格式错误，请稍后再试'}
                
                # 验证响应数据结构
                if not isinstance(response_data, dict):
                    logger.error("API响应格式错误：不是字典类型")
                    return {'error': 'API响应格式错误'}
                
                if 'choices' not in response_data or not response_data['choices']:
                    logger.error("API响应缺少choices字段")
                    return {'error': 'API响应数据不完整'}
                
                if not isinstance(response_data['choices'], list):
                    logger.error("API响应choices字段格式错误")
                    return {'error': 'API响应数据格式错误'}
                
                # 计算响应时间和token数量
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                token_count = calculate_tokens(messages)
                
                # 构建成功响应
                return {
                    'response': response_data,
                    'response_time': response_time,
                    'token_count': token_count
                }
                
            except requests.exceptions.Timeout:
                logger.error(f"API请求超时 (尝试 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    continue
                return {'error': 'API请求超时，请检查网络连接后再试'}
                
            except requests.exceptions.ConnectionError:
                logger.error(f"API连接错误 (尝试 {attempt + 1}/{max_retries})")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': 'API连接失败，请检查网络连接或API地址是否正确'}
                
            except requests.exceptions.RequestException as e:
                logger.error(f"API请求异常: {str(e)}")
                return {'error': f'API请求出现错误: {str(e)}'}
                
    except Exception as e:
        logger.error(f"发送消息时发生未知错误: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
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

        conversation_id = get_conversation_id()
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        
        if not api_key:
            logger.error(f'[ID:{request_id}] API密钥未设置')
            socketio.emit('error', {'message': '请先设置您的API密钥'}, room=request.sid)
            return

        # 更新API密钥
        user_api_keys[request.sid] = api_key

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
            current_messages = list(session_manager.get_conversation_messages(conversation_id))
        except Exception as e:
            logger.error(f'[ID:{request_id}] 获取会话消息失败: {str(e)}')
            # 继续处理，使用空列表

        # 添加用户消息
        try:
            session_manager.add_message_to_conversation(conversation_id, user_message)
        except Exception as e:
            logger.error(f'[ID:{request_id}] 添加用户消息失败: {str(e)}')
            socketio.emit('error', {'message': '处理消息时发生错误，请重试'}, room=request.sid)
            return

        # 发送处理确认
        socketio.emit('message_received', {
            'status': 'processing',
            'request_id': request_id
        }, room=request.sid)

        # 构建API请求消息列表
        messages = [{'role': 'system', 'content': 'You are a helpful assistant.'}]
        messages.extend(current_messages)
        messages.append(user_message)

        # 调用API
        try:
            response_data = send_message(messages, api_key)
        except Exception as e:
            logger.error(f'[ID:{request_id}] API调用失败: {str(e)}')
            socketio.emit('error', {'message': 'API调用失败，请稍后重试'}, room=request.sid)
            return

        if 'error' in response_data:
            socketio.emit('error', {
                'message': response_data['error'],
                'request_id': request_id
            }, room=request.sid)
            return

        # 处理API响应
        if not (response_data and 'response' in response_data and 'choices' in response_data['response']):
            socketio.emit('error', {
                'message': 'API响应格式错误',
                'request_id': request_id
            }, room=request.sid)
            return

        try:
            # 提取助手回复
            assistant_message = response_data['response']['choices'][0]['message']['content']
            
            # 构建助手消息对象
            assistant_message_obj = {
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # 添加助手消息到会话
            session_manager.add_message_to_conversation(conversation_id, assistant_message_obj)

            # 发送响应给客户端
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data.get('response_time', 0), 2),
                'token_count': response_data.get('token_count', 0),
                'request_id': request_id
            }, room=request.sid)

            # 更新会话列表
            conversations = [
                {
                    'id': cid,
                    'title': conv['title'],
                    'timestamp': conv['timestamp']
                } for cid, conv in session_manager.conversation_history.items()
            ]
            socketio.emit('update_history', {'conversations': conversations}, room=request.sid)

        except Exception as e:
            logger.error(f'[ID:{request_id}] 处理API响应失败: {str(e)}')
            socketio.emit('error', {
                'message': '处理响应时发生错误，请重试',
                'request_id': request_id
            }, room=request.sid)
            return

    except Exception as e:
        logger.error(f'[ID:{request_id}] 处理消息时发生错误: {str(e)}')
        import traceback
        logger.error(traceback.format_exc())
        socketio.emit('error', {
            'message': f'处理消息时发生错误: {str(e)}',
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