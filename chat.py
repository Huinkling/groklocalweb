#!/usr/bin/env python3
from flask import Flask, render_template, session, request
from flask_socketio import SocketIO
import requests
import json
import os
import logging
import sys
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
    ping_timeout=60,          # 增加超时时间
    ping_interval=25,         # 调整ping间隔
    async_mode='eventlet'     # 明确指定异步模式
)

API_URL = os.getenv('API_URL', 'https://api.x.ai/v1/chat/completions')

# Store chat history, user API keys and Tavily settings
# 使用类来管理会话，提高内存效率
class SessionManager:
    def __init__(self, max_conversations=100):
        self.conversation_history = {}
        self.user_api_keys = {}
        self.user_tavily_settings = {}
        self.user_tavily_api_keys = {}
        self.max_conversations = max_conversations
    
    def cleanup_old_conversations(self):
        """清理旧会话以节省内存"""
        if len(self.conversation_history) > self.max_conversations:
            # 按时间戳排序并保留最新的会话
            sorted_convs = sorted(
                self.conversation_history.items(),
                key=lambda x: x[1].get('timestamp', ''),
                reverse=True
            )
            # 保留最新的max_conversations个会话
            self.conversation_history = dict(sorted_convs[:self.max_conversations])
            logger.info(f"清理了 {len(sorted_convs) - self.max_conversations} 个旧会话")

# 初始化会话管理器
session_manager = SessionManager()
conversation_history = session_manager.conversation_history
user_api_keys = session_manager.user_api_keys
user_tavily_settings = session_manager.user_tavily_settings
user_tavily_api_keys = session_manager.user_tavily_api_keys

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
        return {'error': '未设置API密钥'}
        
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    
    # 从环境变量获取模型名称和温度设置
    model = os.getenv('MODEL_NAME', 'grok-3-beta')
    temperature = float(os.getenv('TEMPERATURE', '0'))
    
    data = {
        'messages': messages,
        'model': model,
        'stream': False,
        'temperature': temperature
    }
    
    start_time = datetime.now()
    try:
        # 添加超时设置和重试机制
        for attempt in range(3):
            try:
                response = requests.post(API_URL, headers=headers, json=data, timeout=30)
                # 检查API密钥是否有效
                if response.status_code == 401:
                    logger.error("API密钥无效或已过期")
                    return {'error': 'API密钥无效或已过期，请更新您的API密钥'}
                response.raise_for_status()
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < 2:  # 最多重试2次
                    logger.warning(f"API请求失败，正在重试 ({attempt+1}/3): {str(e)}")
                    continue
                raise
                
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        response_data = response.json()
        token_count = calculate_tokens(messages)
        
        return {
            'response': response_data,
            'response_time': response_time,
            'token_count': token_count
        }
    except requests.exceptions.Timeout:
        logger.error("API请求超时")
        return {'error': 'API请求超时，请稍后再试'}
    except requests.exceptions.RequestException as e:
        logger.error(f'API请求错误: {str(e)}')
        return {'error': f'API请求错误: {str(e)}'}
    except Exception as e:
        logger.error(f'未知错误: {str(e)}')
        return {'error': '发生未知错误，请检查API密钥或稍后再试'}

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

@socketio.on('update_settings')
def handle_settings_update(data):
    if 'api_key' in data:
        api_key = data['api_key']
        user_api_keys[request.sid] = api_key
        # 验证API密钥是否有效
        if api_key:
            # 发送确认消息给客户端
            socketio.emit('api_key_updated', {'status': 'success', 'message': 'API密钥已更新，可以开始对话'})
        else:
            socketio.emit('api_key_updated', {'status': 'error', 'message': 'API密钥不能为空'})
    if 'tavily_api_key' in data:
        user_tavily_api_keys[request.sid] = data['tavily_api_key']
    if 'tavily_enabled' in data:
        user_tavily_settings[request.sid] = data['tavily_enabled']

@socketio.on('send_message')
def handle_message(data):
    try:
        conversation_id = get_conversation_id()
        
        # Check if API key is set
        api_key = user_api_keys.get(request.sid)
        if not api_key:
            socketio.emit('error', {'message': '请先设置您的API密钥'})
            return
        
        # 限制消息长度，防止过大的请求
        if len(data.get('message', '')) > 4000:
            socketio.emit('error', {'message': '消息过长，请缩短您的消息'})
            return
        
        if conversation_id not in conversation_history:
            conversation_history[conversation_id] = {
                'messages': [],
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'title': data['message'][:30] + '...' if len(data['message']) > 30 else data['message']
            }
        
        # 清理旧会话，优化内存使用
        session_manager.cleanup_old_conversations()
        
        # Add user message to history
        conversation_history[conversation_id]['messages'].append({
            'role': 'user',
            'content': data['message']
        })
        
        # If Tavily search is enabled, get search results first
        search_results = None
        if user_tavily_settings.get(request.sid, False):
            tavily_api_key = user_tavily_api_keys.get(request.sid)
            if tavily_api_key:
                search_results = get_tavily_search_results(data['message'], tavily_api_key)
            else:
                socketio.emit('error', {'message': 'Please set your Tavily API key first'})
    except Exception as e:
        logger.error(f'处理消息时发生错误: {str(e)}')
        socketio.emit('error', {'message': '处理消息时发生错误'})
        return
    
    try:
        # Build system prompt, using search results as main content
        system_message = ''
        if search_results and 'answer' in search_results:
            search_answer = search_results['answer']
            system_message = f"""You are a helpful assistant. I will provide you with some search results as background information.

Search Results:
{search_answer}

Please answer the user's question based on the search results above. If the search results are relevant, prioritize using information from them. If the search results are not relevant, you can ignore them and answer directly. Please ensure your response is accurate, relevant, and helpful."""
        else:
            system_message = 'You are a helpful assistant.'
        
        messages = [
            {
                'role': 'system',
                'content': system_message
            }
        ] + conversation_history[conversation_id]['messages']
        
        response_data = send_message(messages, api_key)
        
        if response_data and 'response' in response_data and 'choices' in response_data['response']:
            assistant_message = response_data['response']['choices'][0]['message']['content']
            # Add assistant response to history
            conversation_history[conversation_id]['messages'].append({
                'role': 'assistant',
                'content': assistant_message
            })
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data['response_time'], 2),
                'token_count': response_data['token_count']
            })
        else:
            socketio.emit('error', {'message': 'API request failed, please check if your API key is correct'})
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
    except Exception as e:
        logger.error(f'处理响应时发生错误: {str(e)}')
        socketio.emit('error', {'message': '处理响应时发生错误'})
        return

if __name__ == '__main__':
    from eventlet import monkey_patch
    monkey_patch()
    
    # 从环境变量获取端口，适应云平台要求
    port = int(os.getenv('PORT', 10000))
    
    # 记录启动信息
    logger.info(f"应用启动于端口: {port}")
    logger.info(f"API URL: {API_URL}")
    
    # 在云环境中，通常会自动分配主机和端口
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port,
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )