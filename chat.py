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
        logger.error("未设置API密钥")
        return {'error': '请先在设置中配置有效的API密钥'}
        
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
                
                # 检查各种状态码
                if response.status_code == 401:
                    logger.error("API密钥无效或已过期")
                    return {'error': 'API密钥无效或已过期，请更新您的API密钥'}
                elif response.status_code == 429:
                    logger.error("API请求超过限制")
                    return {'error': 'API请求频率超过限制，请稍后再试'}
                elif response.status_code == 500:
                    logger.error("API服务器错误")
                    return {'error': 'API服务器出现错误，请稍后再试'}
                elif response.status_code == 503:
                    logger.error("API服务暂时不可用")
                    return {'error': 'API服务暂时不可用，请稍后再试'}
                
                response.raise_for_status()
                
                # 尝试解析响应数据
                try:
                    response_data = response.json()
                except json.JSONDecodeError as e:
                    logger.error(f"API响应格式错误: {str(e)}")
                    return {'error': 'API响应格式错误，请稍后再试'}
                
                # 检查响应数据结构
                if 'choices' not in response_data or not response_data['choices']:
                    logger.error("API响应数据结构异常")
                    return {'error': 'API响应数据异常，请稍后再试'}
                    
                break
                
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < 2:  # 最多重试2次
                    logger.warning(f"API请求失败，正在重试 ({attempt+1}/3): {str(e)}")
                    continue
                logger.error(f"API请求重试{attempt+1}次后仍然失败: {str(e)}")
                raise
                
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        token_count = calculate_tokens(messages)
        
        return {
            'response': response_data,
            'response_time': response_time,
            'token_count': token_count
        }
        
    except requests.exceptions.Timeout:
        logger.error("API请求超时")
        return {'error': 'API请求超时，请检查网络连接后再试'}
    except requests.exceptions.ConnectionError:
        logger.error("API连接错误")
        return {'error': 'API连接失败，请检查网络连接或API地址是否正确'}
    except requests.exceptions.RequestException as e:
        logger.error(f'API请求错误: {str(e)}')
        return {'error': f'API请求出现错误: {str(e)}'}
    except Exception as e:
        logger.error(f'未知错误: {str(e)}')
        return {'error': '发生未知错误，请检查API配置或稍后再试'}

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

# 删除重复的函数定义

@socketio.on('send_message')
def handle_message(data):
    try:
        conversation_id = get_conversation_id()
        
        # 从请求数据中获取API密钥，如果前端每次请求都发送API密钥，优先使用
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        if not api_key:
            logger.error('API密钥未设置')
            socketio.emit('error', {'message': '请先设置您的API密钥'}, room=request.sid)
            return
        
        # 更新会话中的API密钥
        user_api_keys[request.sid] = api_key
        
        # 从请求数据中获取Tavily设置
        if 'tavily_enabled' in data:
            user_tavily_settings[request.sid] = data.get('tavily_enabled')
        if 'tavily_api_key' in data and data.get('tavily_api_key'):
            user_tavily_api_keys[request.sid] = data.get('tavily_api_key')
        
        # 限制消息长度，防止过大的请求
        if len(data.get('message', '')) > 4000:
            logger.warning(f'消息过长: {len(data.get("message", ""))}字符')
            socketio.emit('error', {'message': '消息过长，请缩短您的消息'}, room=request.sid)
            return
        
        # 记录请求信息
        logger.info(f'收到消息请求: sid={request.sid}, conversation_id={conversation_id}')
        
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
                logger.info('使用Tavily搜索获取结果')
                search_results = get_tavily_search_results(data['message'], tavily_api_key)
            else:
                logger.warning('Tavily搜索已启用但未设置API密钥')
                socketio.emit('error', {'message': '请先设置您的Tavily API密钥'}, room=request.sid)
    except Exception as e:
        logger.error(f'处理消息时发生错误: {str(e)}')
        socketio.emit('error', {'message': f'处理消息时发生错误: {str(e)}'}, room=request.sid)
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
        
        # 记录系统提示信息长度
        logger.info(f'系统提示信息长度: {len(system_message)}字符')
        
        messages = [
            {
                'role': 'system',
                'content': system_message
            }
        ] + conversation_history[conversation_id]['messages']
        
        # 记录发送请求信息
        logger.info(f'发送API请求: conversation_id={conversation_id}, 消息数量={len(messages)}')
        
        # 发送确认消息给客户端
        socketio.emit('message_received', {'status': 'processing'}, room=request.sid)
        
        # 调用API获取响应
        response_data = send_message(messages, api_key)
        
        # 检查响应中是否包含错误
        if 'error' in response_data:
            error_message = response_data['error']
            logger.error(f'API响应错误: {error_message}')
            socketio.emit('error', {'message': error_message}, room=request.sid)
            return
        
        # 处理成功的响应
        if response_data and 'response' in response_data and 'choices' in response_data['response']:
            # 提取助手回复内容
            try:
                assistant_message = response_data['response']['choices'][0]['message']['content']
                logger.info(f'收到API响应: 长度={len(assistant_message)}字符')
                
                # 添加助手回复到会话历史
                conversation_history[conversation_id]['messages'].append({
                    'role': 'assistant',
                    'content': assistant_message
                })
                
                # 发送响应给客户端
                socketio.emit('response', {
                    'message': assistant_message,
                    'conversation_id': conversation_id,
                    'response_time': round(response_data['response_time'], 2),
                    'token_count': response_data['token_count']
                }, room=request.sid)
                
                # 更新会话历史列表
                socketio.emit('update_history', {
                    'conversations': [
                        {
                            'id': cid,
                            'title': conv['title'],
                            'timestamp': conv['timestamp']
                        } for cid, conv in conversation_history.items()
                    ]
                }, room=request.sid)
            except (KeyError, IndexError) as e:
                logger.error(f'解析API响应时出错: {str(e)}')
                logger.error(f'响应数据结构: {response_data}')
                socketio.emit('error', {'message': '解析API响应时出错，请稍后再试'}, room=request.sid)
        else:
            logger.error(f'API响应格式异常: {response_data}')
            socketio.emit('error', {'message': 'API请求失败，请检查您的API密钥是否正确'}, room=request.sid)
    except Exception as e:
        logger.error(f'处理响应时发生错误: {str(e)}')
        import traceback
        logger.error(traceback.format_exc())
        socketio.emit('error', {'message': f'处理响应时发生错误: {str(e)}'}, room=request.sid)
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