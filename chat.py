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

# Load environment variables from .env file
load_dotenv()

# Configure detailed logging system first
logging.basicConfig(
    level=logging.DEBUG,  # Set DEBUG level to get more detailed information
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ===== Fix SSL Recursion Error =====
logger.info("Applying SSL fix to avoid recursion errors...")

try:
    # Create custom SSL context that doesn't verify certificates
    # This helps avoid SSL recursion errors in Python's SSL module
    ssl._create_default_https_context = ssl._create_unverified_context
    logger.debug("Custom SSL context set")
    
    # Import and configure urllib3 to ignore SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.debug("urllib3 warnings disabled")
    
    # Patch requests session to bypass SSL verification
    # This prevents recursion errors in the requests library's SSL handling
    old_merge_environment_settings = requests.Session.merge_environment_settings
    
    def patched_merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings
    
    requests.Session.merge_environment_settings = patched_merge_environment_settings
    logger.debug("Requests session settings patched")
    
    # Disable SSL warnings at package level
    requests.packages.urllib3.disable_warnings()
    
    logger.info("SSL fix successfully applied")
except Exception as e:
    logger.error(f"Error applying SSL fix: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())

# Function to log detailed exception information
def log_exception(e, prefix="Error"):
    """Log detailed exception information, including stack trace"""
    import traceback
    error_trace = traceback.format_exc()
    logger.error(f"{prefix}: {str(e)}")
    logger.error(f"Error type: {type(e).__name__}")
    logger.error(f"Stack trace:\n{error_trace}")
    return error_trace

# Initialize Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

# Configure SocketIO with cloud-friendly options
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Allow cross-origin requests
    ping_timeout=120,         # Increase timeout to prevent disconnections
    ping_interval=15,         # Decrease ping interval for better connection stability
    async_mode='eventlet',    # Use eventlet as async mode for better performance
    logger=True,              # Enable SocketIO logging
    engineio_logger=True      # Enable Engine.IO logging
)

# API endpoint for Grok API
API_URL = os.getenv('API_URL', 'https://api.x.ai/v1/chat/completions')

# Session management for chats, API keys and settings
# Efficient memory management using class-based approach
class SessionManager:
    def __init__(self, max_conversations=50, max_messages_per_conversation=30):
        """Initialize the session manager with memory limits
        
        Args:
            max_conversations: Maximum number of conversations to keep in memory
            max_messages_per_conversation: Maximum messages per conversation
        """
        self.conversation_history = {}  # Stores all conversation data
        self.user_api_keys = {}         # Maps session IDs to API keys
        self.user_tavily_settings = {}  # Maps session IDs to Tavily search settings
        self.user_tavily_api_keys = {}  # Maps session IDs to Tavily API keys
        self.max_conversations = max_conversations
        self.max_messages_per_conversation = max_messages_per_conversation
    
    def sanitize_message(self, message):
        """Clean and validate message data to ensure proper format and remove invalid data
        
        Args:
            message: The message object to sanitize
            
        Returns:
            A cleaned message object or None if invalid
        """
        try:
            if not isinstance(message, dict):
                logger.warning(f"Invalid message format: {type(message)}")
                return None
            
            # Ensure required fields exist
            if 'role' not in message or 'content' not in message:
                logger.warning("Message missing required fields")
                return None
            
            # Clean and validate role field
            role = str(message.get('role', '')).strip().lower()
            if role not in ['system', 'user', 'assistant']:
                logger.warning(f"Invalid message role: {role}")
                role = 'user'  # Default to user message
            
            # Clean content field
            content = str(message.get('content', '')).strip()
            if not content:
                logger.warning("Empty message content")
                return None
            
            # Limit content length
            if len(content) > 10000:
                logger.warning(f"Message content too long ({len(content)} chars), truncating")
                content = content[:10000] + "..."
            
            # Create clean message object
            clean_message = {
                'role': role,
                'content': content,
                'timestamp': message.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            }
            
            return clean_message
        except Exception as e:
            logger.error(f"Error cleaning message: {str(e)}")
            return None
    
    def cleanup_old_conversations(self):
        """Remove oldest conversations when limit is reached to save memory"""
        try:
            if len(self.conversation_history) > self.max_conversations:
                # Sort by timestamp and keep only the newest conversations
                sorted_convs = sorted(
                    self.conversation_history.items(),
                    key=lambda x: x[1].get('timestamp', ''),
                    reverse=True
                )[:self.max_conversations]
                # Create new dictionary directly instead of modifying existing one
                self.conversation_history = {cid: conv for cid, conv in sorted_convs}
                logger.info(f"Cleaned up old conversations, current count: {len(self.conversation_history)}")
        except Exception as e:
            logger.error(f"Error cleaning up old conversations: {str(e)}")
    
    def add_message_to_conversation(self, conversation_id, message):
        """Add a message to conversation, cleaning up old messages if needed
        
        Args:
            conversation_id: ID of the conversation
            message: Message object to add
            
        Raises:
            RuntimeError: If message can't be added
        """
        try:
            # Clean the message data
            clean_message = self.sanitize_message(message)
            if not clean_message:
                logger.warning(f"Skipping invalid message for conversation: {conversation_id}")
                return
            
            # Create new conversation if it doesn't exist
            if conversation_id not in self.conversation_history:
                self.conversation_history[conversation_id] = {
                    'messages': [],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'title': clean_message.get('content', '')[:30] + '...' if len(clean_message.get('content', '')) > 30 else clean_message.get('content', '')
                }
            
            conv = self.conversation_history[conversation_id]
            messages = conv['messages']
            
            # If message count exceeds limit, remove older messages
            if len(messages) >= self.max_messages_per_conversation:
                # Keep system messages and most recent user/assistant messages
                system_messages = [msg for msg in messages if msg.get('role') == 'system']
                other_messages = [msg for msg in messages if msg.get('role') != 'system']
                
                # Calculate how many non-system messages to keep
                keep_count = max(1, self.max_messages_per_conversation - len(system_messages))
                # Keep only the newest messages
                kept_messages = system_messages + other_messages[-keep_count:]
                
                # Replace message list
                conv['messages'] = kept_messages
                logger.debug(f"Conversation {conversation_id} messages after cleanup: {len(kept_messages)}")
            
            # Add new message
            conv['messages'].append(clean_message)
            # Update timestamp
            conv['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.debug(f"Message added to conversation {conversation_id}, current count: {len(conv['messages'])}")
            
            # Periodically clean up old conversations
            if len(self.conversation_history) > self.max_conversations:
                self.cleanup_old_conversations()
                
        except Exception as e:
            error_trace = log_exception(e, f"Error adding message to conversation {conversation_id}")
            raise RuntimeError(f"Failed to add message to conversation: {str(e)}")
    
    def get_conversation_messages(self, conversation_id):
        """Get messages for a specific conversation
        
        Args:
            conversation_id: ID of the conversation
            
        Returns:
            List of messages or empty list if conversation doesn't exist
        """
        try:
            messages = self.conversation_history.get(conversation_id, {}).get('messages', [])
            # Return a copy of messages list to avoid reference issues
            return list(messages)
        except Exception as e:
            logger.error(f"Error getting conversation messages: {str(e)}")
            return []
            
    def get_conversation_count(self):
        """Get the current number of conversations"""
        return len(self.conversation_history)
        
    def clear_old_data(self):
        """Periodically clean up expired data (conversations older than 24 hours)"""
        try:
            # Clean up conversations older than 24 hours
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
                logger.info(f"Cleared {len(old_conversations)} expired conversations")
        except Exception as e:
            logger.error(f"Error clearing expired data: {str(e)}")

# Initialize session manager with smaller defaults for cloud environment
session_manager = SessionManager(max_conversations=50, max_messages_per_conversation=30)
conversation_history = session_manager.conversation_history
user_api_keys = session_manager.user_api_keys
user_tavily_settings = session_manager.user_tavily_settings
user_tavily_api_keys = session_manager.user_tavily_api_keys

# Background task to clean up old data
def cleanup_task():
    """Background task that runs periodically to clean up old data"""
    while True:
        try:
            session_manager.clear_old_data()
            time.sleep(3600)  # Run every hour
        except Exception as e:
            logger.error(f"Error in cleanup task: {str(e)}")
            time.sleep(60)  # Wait 1 minute before retrying if error occurs

def get_tavily_search_results(query, api_key):
    """Perform web search using Tavily API with urllib instead of requests
    
    Args:
        query: The search query text
        api_key: Tavily API key
        
    Returns:
        Search results dictionary or None if search failed
    """
    if not api_key:
        logger.warning("Tavily API key not set")
        return None
    
    request_id = datetime.now().strftime('%Y%m%d%H%M%S')
    logger.debug(f"Tavily request[{request_id}] started: query={query[:30]}...")
    
    try:
        # Build request URL and data
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
        
        # Convert data to JSON
        data_json = json.dumps(data)
        
        # Create SSL context
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Parse URL
        host = 'api.tavily.com'
        path = '/search'
        
        # Send request
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=10)
        logger.debug(f"Tavily request[{request_id}] connecting to: {host}")
        
        try:
            start_time = datetime.now()
            conn.request("POST", path, data_json, headers)
            
            # Get response
            response = conn.getresponse()
            status = response.status
            elapsed_time = (datetime.now() - start_time).total_seconds()
            logger.debug(f"Tavily request[{request_id}] received response: status={status}, time={elapsed_time:.2f}s")
            
            # Check response status
            if status != 200:
                response_body = response.read().decode('utf-8')
                logger.error(f"Tavily request[{request_id}] failed: status={status}")
                logger.debug(f"Tavily request[{request_id}] error details: {response_body[:200]}")
                return None
            
            # Read and parse response
            response_data = response.read().decode('utf-8')
            result = json.loads(response_data)
            
            # Validate response format
            if not isinstance(result, dict):
                logger.error(f"Tavily request[{request_id}] invalid response format: not a dictionary")
                return None
            
            # Check if result contains answer field
            if 'answer' in result:
                answer_length = len(result['answer'])
                logger.info(f"Tavily request[{request_id}] successful: answer length={answer_length} chars")
                return result
            else:
                logger.warning(f"Tavily request[{request_id}] missing answer field")
                return None
                
        finally:
            # Ensure connection is closed
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
    """Get current conversation ID from session or create a new one"""
    if 'conversation_id' not in session:
        session['conversation_id'] = datetime.now().strftime('%Y%m%d%H%M%S')
    return session['conversation_id']

def calculate_tokens(messages):
    """Simple token calculation method, each character counts as 1 token"""
    total_tokens = sum(len(msg['content']) for msg in messages)
    return total_tokens

def send_message(messages, api_key=None):
    """Send messages to the API and get response, using urllib instead of requests
    
    Args:
        messages: List of message objects to send
        api_key: API key for authentication
        
    Returns:
        Dictionary containing response or error information
    """
    if not api_key:
        logger.error("API key not set")
        return {'error': 'Please configure a valid API key in settings'}
    
    try:
        # Validate message format
        if not isinstance(messages, list):
            logger.error("Invalid message format: not a list")
            return {'error': 'Invalid message format'}
        
        for msg in messages:
            if not isinstance(msg, dict) or 'role' not in msg or 'content' not in msg:
                logger.error("Invalid message format: missing required fields")
                return {'error': 'Invalid message format'}
        
        # Log request details
        request_id = datetime.now().strftime('%Y%m%d%H%M%S')
        logger.debug(f"API request[{request_id}] initializing: message count={len(messages)}")
        logger.debug(f"API request[{request_id}] URL: {API_URL}")
        
        # Get model info from environment variables
        model = os.getenv('MODEL_NAME', 'grok-3-beta')
        temperature = float(os.getenv('TEMPERATURE', '0'))
        logger.debug(f"API request[{request_id}] model: {model}, temperature: {temperature}")
        
        # Build request data
        data = {
            'messages': messages,
            'model': model,
            'stream': False,
            'temperature': temperature
        }
        
        # Log request data size
        data_json = json.dumps(data)
        request_size = len(data_json)
        logger.debug(f"API request[{request_id}] data size: {request_size} bytes")
        
        start_time = datetime.now()
        
        # Build request headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-API-Client/1.0'
        }
        
        # Use urllib library instead of requests
        import urllib.request
        import urllib.error
        import http.client
        
        # Retry configuration
        max_retries = 3
        base_delay = 2
        
        # Execute request
        for attempt in range(max_retries):
            try:
                current_delay = base_delay * (2 ** attempt)
                logger.debug(f"API request[{request_id}] attempt: {attempt + 1}/{max_retries}")
                
                # Create request context
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                # Parse URL
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
                
                # Send request
                conn.request("POST", path, data_json, headers)
                
                # Get response
                start_response_time = datetime.now()
                response = conn.getresponse()
                response_status = response.status
                elapsed_time = (datetime.now() - start_response_time).total_seconds()
                
                logger.debug(f"API request[{request_id}] response status: {response_status}, time: {elapsed_time}s")
                
                # Handle error status codes
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
                
                # Read response content
                response_data = response.read().decode('utf-8')
                
                # Get and log response preview
                response_preview = response_data[:200] + '...' if len(response_data) > 200 else response_data
                logger.debug(f"API request[{request_id}] response preview: {response_preview}")
                
                # Parse response JSON
                try:
                    response_json = json.loads(response_data)
                except json.JSONDecodeError as e:
                    logger.error(f"API request[{request_id}] JSON parse failed: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
                    return {'error': 'Invalid API response format, please try again later'}
                
                # Validate response structure
                if not isinstance(response_json, dict):
                    logger.error(f"API request[{request_id}] response not a dictionary")
                    return {'error': 'Invalid API response format'}
                
                # Check for required fields
                if 'choices' not in response_json:
                    logger.error(f"API request[{request_id}] response missing choices field")
                    logger.debug(f"API request[{request_id}] response structure: {list(response_json.keys())}")
                    return {'error': 'Incomplete API response data'}
                
                if not isinstance(response_json['choices'], list):
                    logger.error(f"API request[{request_id}] response choices not a list")
                    return {'error': 'Invalid API response data format'}
                
                # Calculate total processing time
                end_time = datetime.now()
                response_time = (end_time - start_time).total_seconds()
                token_count = calculate_tokens(messages)
                
                logger.info(f"API request[{request_id}] successful, total time: {response_time}s")
                
                # Close connection
                conn.close()
                
                # Return successful response
                return {
                    'response': response_json,
                    'response_time': response_time,
                    'token_count': token_count
                }
                
            except urllib.error.URLError as e:
                logger.error(f"API request[{request_id}] URL error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API connection error: {str(e)}'}
                
            except http.client.HTTPException as e:
                logger.error(f"API request[{request_id}] HTTP error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API request error: {str(e)}'}
                
            except socket.timeout:
                logger.error(f"API request[{request_id}] connection timeout")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': 'API request timeout, please check your network connection'}
                
            except Exception as e:
                error_trace = log_exception(e, f"API request[{request_id}] exception")
                return {'error': f'API request error: {str(e)}'}
                
            finally:
                # Ensure connection is closed
                if 'conn' in locals():
                    try:
                        conn.close()
                    except:
                        pass
                
    except RecursionError as e:
        # Special handling for recursion errors
        logger.critical(f"Recursion error during message send: {str(e)}")
        return {'error': 'API request processing error, please contact administrator to check server configuration'}
    except Exception as e:
        error_trace = log_exception(e, "Unknown error during message send")
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
    # 添加请求ID用于跟踪
    request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(data))}"
    logger.info(f'Processing message request [ID:{request_id}]')
    
    try:
        # Basic validation
        if not data.get('message'):
            logger.error(f'[ID:{request_id}] Message content is empty')
            socketio.emit('error', {'message': 'Message content cannot be empty'}, room=request.sid)
            return

        # Check conversation ID
        conversation_id = get_conversation_id()
        logger.debug(f'[ID:{request_id}] Conversation ID: {conversation_id}')
        
        # Check API key
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        if not api_key:
            logger.error(f'[ID:{request_id}] API key not set')
            socketio.emit('error', {'message': 'Please set your API key first'}, room=request.sid)
            return

        # Log key request info
        logger.debug(f'[ID:{request_id}] API URL: {API_URL}')
        logger.debug(f'[ID:{request_id}] Message length: {len(data.get("message", ""))} characters')
        
        # Update API key
        user_api_keys[request.sid] = api_key
        
        # Handle Tavily settings
        if 'tavily_enabled' in data:
            user_tavily_settings[request.sid] = data.get('tavily_enabled')
        if 'tavily_api_key' in data and data.get('tavily_api_key'):
            user_tavily_api_keys[request.sid] = data.get('tavily_api_key')

        # Message length check
        if len(data.get('message', '')) > 4000:
            logger.warning(f'[ID:{request_id}] Message too long: {len(data.get("message", ""))} characters')
            socketio.emit('error', {'message': 'Message is too long, please shorten your message'}, room=request.sid)
            return

        # Build user message
        user_message = {
            'role': 'user',
            'content': data['message'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Get current conversation messages
        current_messages = []
        try:
            logger.debug(f'[ID:{request_id}] Attempting to get conversation messages')
            current_messages = list(session_manager.get_conversation_messages(conversation_id))
            logger.debug(f'[ID:{request_id}] Current conversation message count: {len(current_messages)}')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to get conversation messages')
            # Continue processing, use empty list
            current_messages = []

        # Add user message
        try:
            logger.debug(f'[ID:{request_id}] Attempting to add user message to conversation')
            session_manager.add_message_to_conversation(conversation_id, user_message)
            logger.debug(f'[ID:{request_id}] User message added to conversation')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to add user message')
            socketio.emit('error', {
                'message': 'Error processing message, please try again', 
                'request_id': request_id
            }, room=request.sid)
            return

        # Send processing confirmation
        socketio.emit('message_received', {
            'status': 'processing',
            'request_id': request_id
        }, room=request.sid)

        # Handle Tavily search
        search_results = None
        if user_tavily_settings.get(request.sid, False):
            tavily_api_key = user_tavily_api_keys.get(request.sid)
            if tavily_api_key:
                try:
                    logger.debug(f'[ID:{request_id}] Attempting to perform Tavily search')
                    search_results = get_tavily_search_results(data['message'], tavily_api_key)
                    if search_results and 'answer' in search_results:
                        logger.debug(f'[ID:{request_id}] Search results successfully retrieved, length: {len(search_results["answer"])} characters')
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
                            'message': 'Web search returned no results, using model to answer directly',
                            'request_id': request_id
                        }, room=request.sid)
                except Exception as e:
                    error_trace = log_exception(e, f'[ID:{request_id}] Tavily search failed')
                    # Send search error notification to client
                    socketio.emit('search_status', {
                        'status': 'error',
                        'message': 'Web search failed, using model to answer directly',
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

        # Build system message
        system_message = 'You are a helpful assistant.'
        if search_results and 'answer' in search_results:
            logger.debug(f'[ID:{request_id}] Building system message with search results')
            search_answer = search_results['answer']
            
            # Include search context if available
            search_context = ""
            if 'context' in search_results and search_results['context']:
                # Check if context is a list
                if isinstance(search_results['context'], list):
                    # Merge first 5 context items (if available)
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

        # Build API request message list - Fix the logic here to ensure messages are added in the correct order
        messages = [{'role': 'system', 'content': system_message}]
        
        # If there are existing conversation messages, add them after the system message
        if current_messages:
            messages.extend(current_messages)
        
        # Don't need to add the user message that's already been added to the conversation history
        # Check if the last message is already the current user message
        if not messages or messages[-1]['role'] != 'user' or messages[-1]['content'] != user_message['content']:
            messages.append(user_message)
            
        logger.debug(f'[ID:{request_id}] Ready to send API request, total messages: {len(messages)}, including system message: {system_message[:50]}...')

        # Call API
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

        # Check for error response
        if 'error' in response_data:
            logger.error(f'[ID:{request_id}] API returned error: {response_data["error"]}')
            socketio.emit('error', {
                'message': response_data['error'],
                'request_id': request_id
            }, room=request.sid)
            return

        # Validate response format
        if not (response_data and 'response' in response_data and 'choices' in response_data['response']):
            logger.error(f'[ID:{request_id}] API response format does not match expected: {json.dumps(response_data)}')
            socketio.emit('error', {
                'message': 'API response format error',
                'request_id': request_id
            }, room=request.sid)
            return

        # Process API response
        try:
            # Extract assistant reply
            choices = response_data['response']['choices']
            if not choices or not isinstance(choices, list) or len(choices) == 0:
                logger.error(f'[ID:{request_id}] API response choices empty or format error')
                socketio.emit('error', {
                    'message': 'Incomplete API response data',
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
            
            # Build assistant message object
            assistant_message_obj = {
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Add assistant message to conversation
            try:
                logger.debug(f'[ID:{request_id}] Attempting to add assistant reply to conversation')
                session_manager.add_message_to_conversation(conversation_id, assistant_message_obj)
                logger.debug(f'[ID:{request_id}] Assistant reply added to conversation')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] Failed to add assistant reply to conversation')
                # Try to return response to user even if adding to conversation fails

            # Send response to client
            logger.debug(f'[ID:{request_id}] Sending response to client')
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data.get('response_time', 0), 2),
                'token_count': response_data.get('token_count', 0),
                'request_id': request_id
            }, room=request.sid)

            # Update conversation list
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
            'message': f'An unknown error occurred, please try again later',
            'request_id': request_id
        }, room=request.sid)

if __name__ == '__main__':
    from gevent import monkey
    monkey.patch_all()
    
    # Start cleanup task
    from threading import Thread
    cleanup_thread = Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    
    # Get port from environment variables, adapt to cloud platform requirements
    port = int(os.getenv('PORT', 10000))
    
    # Log startup information
    logger.info(f"Application started on port: {port}")
    logger.info(f"API URL: {API_URL}")
    logger.info(f"Maximum conversations: {session_manager.max_conversations}")
    logger.info(f"Maximum messages per conversation: {session_manager.max_messages_per_conversation}")
    
    # In cloud environments, host and port are usually automatically assigned
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port,
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )