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

# Load environment variables
load_dotenv()

# Configure logging system
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG level for more information
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ===== Fix SSL recursion errors =====
logger.info("Applying SSL fix to avoid recursion errors...")

try:
    # Create custom SSL context
    ssl._create_default_https_context = ssl._create_unverified_context
    logger.debug("Custom SSL context set")
    
    # Import and configure urllib3
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    logger.debug("urllib3 warnings disabled")
    
    # Patch requests session to avoid SSL verification
    old_merge_environment_settings = requests.Session.merge_environment_settings
    
    def patched_merge_environment_settings(self, url, proxies, stream, verify, cert):
        settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
        settings['verify'] = False
        return settings
    
    requests.Session.merge_environment_settings = patched_merge_environment_settings
    logger.debug("Requests session settings patched")
    
    # Set default to not verify SSL
    requests.packages.urllib3.disable_warnings()
    
    logger.info("SSL fix applied successfully")
except Exception as e:
    logger.error(f"Error applying SSL fix: {str(e)}")
    import traceback
    logger.error(traceback.format_exc())

# Add detailed error tracking function
def log_exception(e, prefix="Error"):
    """Log detailed exception information including stack trace"""
    import traceback
    error_trace = traceback.format_exc()
    logger.error(f"{prefix}: {str(e)}")
    logger.error(f"Error type: {type(e).__name__}")
    logger.error(f"Stack trace:\n{error_trace}")
    return error_trace

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')

# Configure SocketIO with cloud-ready options
socketio = SocketIO(
    app,
    cors_allowed_origins="*",  # Allow cross-origin requests
    ping_timeout=120,         # Increase timeout to prevent disconnection on long requests
    ping_interval=15,         # Reduce ping interval for more stable connection
    async_mode='eventlet',    # Use eventlet as async mode
    logger=True,              # Enable SocketIO logging
    engineio_logger=True      # Enable Engine.IO logging
)

API_URL = os.getenv('API_URL', 'https://api.x.ai/v1/chat/completions')

# Use class to manage sessions efficiently
class SessionManager:
    def __init__(self, max_conversations=50, max_messages_per_conversation=30):
        self.conversation_history = {}
        self.user_api_keys = {}
        self.user_tavily_settings = {}
        self.user_tavily_api_keys = {}
        self.max_conversations = max_conversations
        self.max_messages_per_conversation = max_messages_per_conversation
    
    def sanitize_message(self, message):
        """Clean message data to ensure correct format and no invalid data"""
        try:
            if not isinstance(message, dict):
                logger.warning(f"Invalid message format: {type(message)}")
                return None
            
            # Ensure basic fields exist
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
                logger.warning("Message content is empty")
                return None
            
            # Limit content length
            if len(content) > 10000:
                logger.warning(f"Message content too long ({len(content)} chars), truncated")
                content = content[:10000] + "..."
            
            # Create clean message object
            clean_message = {
                'role': role,
                'content': content,
                'timestamp': message.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            }
            
            return clean_message
        except Exception as e:
            logger.error(f"Error sanitizing message: {str(e)}")
            return None
    
    def cleanup_old_conversations(self):
        """Clean old conversations to save memory"""
        try:
            if len(self.conversation_history) > self.max_conversations:
                # Sort by timestamp and keep the latest conversations
                sorted_convs = sorted(
                    self.conversation_history.items(),
                    key=lambda x: x[1].get('timestamp', ''),
                    reverse=True
                )[:self.max_conversations]
                # Directly create new dictionary instead of modifying existing dictionary
                self.conversation_history = {cid: conv for cid, conv in sorted_convs}
                logger.info(f"Cleaned up old conversations, current count: {len(self.conversation_history)}")
        except Exception as e:
            logger.error(f"Error cleaning up old conversations: {str(e)}")
    
    def add_message_to_conversation(self, conversation_id, message):
        """Add message to conversation and clean old messages if necessary"""
        try:
            # Clean message data
            clean_message = self.sanitize_message(message)
            if not clean_message:
                logger.warning(f"Skipping invalid message for conversation: {conversation_id}")
                return
            
            # If conversation doesn't exist, create new conversation
            if conversation_id not in self.conversation_history:
                self.conversation_history[conversation_id] = {
                    'messages': [],
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'title': clean_message.get('content', '')[:30] + '...' if len(clean_message.get('content', '')) > 30 else clean_message.get('content', '')
                }
            
            conv = self.conversation_history[conversation_id]
            messages = conv['messages']
            
            # If message count exceeds limit, directly remove old messages
            if len(messages) >= self.max_messages_per_conversation:
                # Keep system messages and latest messages
                system_messages = [msg for msg in messages if msg.get('role') == 'system']
                other_messages = [msg for msg in messages if msg.get('role') != 'system']
                
                # Calculate non-system messages to keep
                keep_count = max(1, self.max_messages_per_conversation - len(system_messages))
                # Only keep latest messages
                kept_messages = system_messages + other_messages[-keep_count:]
                
                # Directly replace message list
                conv['messages'] = kept_messages
                logger.debug(f"Conversation {conversation_id} cleaned, message count: {len(kept_messages)}")
            
            # Add new message
            conv['messages'].append(clean_message)
            # Update timestamp
            conv['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            logger.debug(f"Message added to conversation {conversation_id}, current count: {len(conv['messages'])}")
            
            # Periodically clean old conversations
            if len(self.conversation_history) > self.max_conversations:
                self.cleanup_old_conversations()
                
        except Exception as e:
            error_trace = log_exception(e, f"Error adding message to conversation {conversation_id}")
            raise RuntimeError(f"Failed to add message to conversation: {str(e)}")
    
    def get_conversation_messages(self, conversation_id):
        """Get conversation messages"""
        try:
            messages = self.conversation_history.get(conversation_id, {}).get('messages', [])
            # Copy message list to avoid reference issues
            return list(messages)
        except Exception as e:
            logger.error(f"Error retrieving conversation messages: {str(e)}")
            return []
            
    def get_conversation_count(self):
        """Get current conversation count"""
        return len(self.conversation_history)
        
    def clear_old_data(self):
        """Periodically clean expired data"""
        try:
            # Clean conversations older than 24 hours
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

# Add periodic cleanup task
def cleanup_task():
    while True:
        try:
            session_manager.clear_old_data()
            time.sleep(3600)  # Clean up once per hour
        except Exception as e:
            logger.error(f"Error in cleanup task: {str(e)}")
            time.sleep(60)  # Wait 1 minute before trying again after an error

def get_tavily_search_results(query, api_key):
    """Use Tavily API for search, using urllib library instead of requests"""
    # Check if API key exists
    if not api_key:
        logger.warning("No Tavily API key provided")
        return None
    
    # Generate request ID and record query information
    request_id = datetime.now().strftime('%Y%m%d%H%M%S')
    logger.debug(f"Tavily request[{request_id}] start: query={query[:30]}...")
    
    try:
        # Build Tavily API request URL and headers
        url = 'https://api.tavily.com/search'
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-Web-Client/1.0'
        }
        
        # Build search request data, set advanced search depth and include answer
        data = {
            'query': query,
            'search_depth': 'advanced',
            'include_answer': True,
            'include_domains': [],
            'exclude_domains': [],
            'max_results': 5  # Limit result count for optimization
        }
        
        # Convert data to JSON string
        data_json = json.dumps(data)
        
        # Create SSL context, disable certificate verification to avoid SSL recursion
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        # Set host and path
        host = 'api.tavily.com'
        path = '/search'
        
        # Create HTTPS connection, set 10 seconds timeout
        conn = http.client.HTTPSConnection(host, context=ctx, timeout=10)
        logger.debug(f"Tavily request[{request_id}] connecting to: {host}")
        
        try:
            # Record start time and send request
            start_time = datetime.now()
            conn.request("POST", path, data_json, headers)
            
            # Get response and calculate time
            response = conn.getresponse()
            status = response.status
            elapsed_time = (datetime.now() - start_time).total_seconds()
            logger.debug(f"Tavily request[{request_id}] response received: status={status}, time={elapsed_time:.2f}s")
            
            # Check response status code, non-200 indicates error
            if status != 200:
                response_body = response.read().decode('utf-8')
                logger.error(f"Tavily request[{request_id}] failed: status={status}")
                logger.debug(f"Tavily request[{request_id}] error details: {response_body[:200]}")
                return None
            
            # Read and parse response data
            response_data = response.read().decode('utf-8')
            result = json.loads(response_data)
            
            # Verify response is dictionary type
            if not isinstance(result, dict):
                logger.error(f"Tavily request[{request_id}] response format error: not a dictionary")
                return None
            
            # Check if response contains answer and context fields
            if 'answer' in result:
                answer_length = len(result['answer'])
                logger.info(f"Tavily request[{request_id}] success: answer length={answer_length} characters")
                
                # Ensure context field exists and is correct format
                if 'context' in result and isinstance(result['context'], list):
                    context_count = len(result['context'])
                    logger.debug(f"Tavily request[{request_id}] context items: {context_count}")
                else:
                    logger.warning(f"Tavily request[{request_id}] missing or invalid context field")
                    # If no context, add an empty list
                    result['context'] = []
                    
                return result
            else:
                # Missing answer field, possibly API did not return search results
                logger.warning(f"Tavily request[{request_id}] missing answer field")
                return None
                
        finally:
            # Ensure connection closed to avoid resource leak
            conn.close()
            
    except json.JSONDecodeError as e:
        # Handle JSON parsing error
        logger.error(f"Tavily request[{request_id}] JSON parsing failed: {str(e)}")
        return None
    except ssl.SSLError as e:
        # Handle SSL certificate error
        logger.error(f"Tavily request[{request_id}] SSL error: {str(e)}")
        return None
    except http.client.HTTPException as e:
        # Handle HTTP protocol error
        logger.error(f"Tavily request[{request_id}] HTTP error: {str(e)}")
        return None
    except socket.timeout:
        # Handle connection timeout
        logger.error(f"Tavily request[{request_id}] connection timeout")
        return None
    except Exception as e:
        # Handle all other exceptions
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
    """Send message to API and get response, using http.client without depending on requests library"""
    # Check if API key exists
    if not api_key:
        logger.error("API key not provided")
        return {'error': 'Please set your API key first'}
    
    try:
        # Verify message format - Ensure it's list type
        if not isinstance(messages, list):
            logger.error("Message format error: not a list")
            return {'error': 'Message format error'}
        
        # Verify each message contains necessary fields (role and content)
        for msg in messages:
            if not isinstance(msg, dict) or 'role' not in msg or 'content' not in msg:
                logger.error("Message format error: missing required fields")
                return {'error': 'Message format error'}
        
        # Generate request ID and record request details
        request_id = datetime.now().strftime('%Y%m%d%H%M%S')
        logger.debug(f"API request[{request_id}] initialized: messages={len(messages)}")
        logger.debug(f"API request[{request_id}] URL: {API_URL}")
        
        # Get model information from environment variable
        model = os.getenv('MODEL_NAME', 'grok-3-beta')
        temperature = float(os.getenv('TEMPERATURE', '0'))
        logger.debug(f"API request[{request_id}] model: {model}, temperature: {temperature}")
        
        # Build request data - Including messages, model, and temperature settings
        data = {
            'messages': messages,
            'model': model,
            'stream': False,
            'temperature': temperature,
            'max_tokens': 4096  # Add max token limit to improve reliability
        }
        
        # Convert data to JSON and record size
        data_json = json.dumps(data)
        request_size = len(data_json)
        logger.debug(f"API request[{request_id}] data size: {request_size} bytes")
        
        # Record start time for calculating request duration
        start_time = datetime.now()
        
        # Build HTTP request headers
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}',
            'User-Agent': 'Grok-API-Client/1.0'
        }
        
        # Retry configuration - max 3 attempts with exponential backoff
        max_retries = 3
        base_delay = 2
        
        # Start request loop
        for attempt in range(max_retries):
            try:
                # Calculate current retry delay (exponential growth)
                current_delay = base_delay * (2 ** attempt)
                logger.debug(f"API request[{request_id}] attempt: {attempt + 1}/{max_retries}")
                
                # Create SSL context, disable certificate verification to avoid SSL recursion
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                
                # Parse URL and establish HTTP connection
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
                
                # Send HTTP POST request
                conn.request("POST", path, data_json, headers)
                
                # Get response and calculate response time
                start_response_time = datetime.now()
                response = conn.getresponse()
                response_status = response.status
                elapsed_time = (datetime.now() - start_response_time).total_seconds()
                
                logger.debug(f"API request[{request_id}] response status: {response_status}, time: {elapsed_time}s")
                
                # Handle non-200 status code errors
                if response_status != 200:
                    response_body = response.read().decode('utf-8')
                    logger.warning(f"API request[{request_id}] returned non-200 status: {response_status}")
                    logger.debug(f"API request[{request_id}] response headers: {dict(response.getheaders())}")
                    logger.debug(f"API request[{request_id}] response content: {response_body[:200]}")
                    
                    # Return appropriate error message based on status code
                    if response_status == 401:
                        return {'error': 'API key invalid or expired, please update your API key'}
                    elif response_status == 429:
                        if attempt < max_retries - 1:
                            # Get retry wait time and wait
                            retry_after = int(dict(response.getheaders()).get('Retry-After', current_delay))
                            logger.warning(f"API request[{request_id}] rate limited, waiting {retry_after}s")
                            time.sleep(retry_after)
                            continue
                        return {'error': 'API request rate limit exceeded, please try again later'}
                    elif response_status == 500:
                        if attempt < max_retries - 1:
                            # Server error, retry after delay
                            logger.warning(f"API request[{request_id}] server error, retrying in {current_delay}s")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API server error, please try again later'}
                    elif response_status == 503:
                        if attempt < max_retries - 1:
                            # Service unavailable, retry after delay
                            logger.warning(f"API request[{request_id}] service unavailable, retrying in {current_delay}s")
                            time.sleep(current_delay)
                            continue
                        return {'error': 'API service temporarily unavailable, please try again later'}
                    else:
                        return {'error': f'API response error: {response_status}'}
                
                # Read and parse response data
                response_data = response.read().decode('utf-8')
                
                # Record response content preview
                response_preview = response_data[:200] + '...' if len(response_data) > 200 else response_data
                logger.debug(f"API request[{request_id}] response preview: {response_preview}")
                
                # Parse JSON response
                try:
                    response_json = json.loads(response_data)
                except json.JSONDecodeError as e:
                    logger.error(f"API request[{request_id}] JSON parse error: {str(e)}")
                    if attempt < max_retries - 1:
                        continue
                    return {'error': 'API response format error, please try again later'}
                
                # Verify response is dictionary type
                if not isinstance(response_json, dict):
                    logger.error(f"API request[{request_id}] response not a dictionary")
                    return {'error': 'API response format error'}
                
                # Check if response contains necessary 'choices' field
                if 'choices' not in response_json:
                    logger.error(f"API request[{request_id}] response missing 'choices' field")
                    logger.debug(f"API request[{request_id}] response structure: {list(response_json.keys())}")
                    return {'error': 'API response data incomplete'}
                
                # Check if choices are list type
                if not isinstance(response_json['choices'], list) or not response_json['choices']:
                    logger.error(f"API request[{request_id}] 'choices' not a list or empty")
                    return {'error': 'API response data format error'}
                
                # Calculate total processing time and token count
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
                # Handle URL error (e.g., DNS resolution failure)
                logger.error(f"API request[{request_id}] URL error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API connection error: {str(e)}'}
                
            except http.client.HTTPException as e:
                # Handle HTTP exception
                logger.error(f"API request[{request_id}] HTTP error: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API request error: {str(e)}'}
                
            except socket.timeout:
                # Handle connection timeout
                logger.error(f"API request[{request_id}] connection timeout")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': 'API request timeout, please check your network connection and try again'}
                
            except Exception as e:
                # Handle other exceptions
                error_trace = log_exception(e, f"API request[{request_id}] exception")
                if attempt < max_retries - 1:
                    time.sleep(current_delay)
                    continue
                return {'error': f'API request error: {str(e)}'}
                
            finally:
                # Ensure connection closed to avoid resource leak
                if 'conn' in locals():
                    try:
                        conn.close()
                    except:
                        pass
                
    except RecursionError as e:
        # Special handling for recursion error
        logger.critical(f"Recursion error in send_message: {str(e)}")
        logger.critical("This is likely due to SSL verification issues")
        return {'error': 'API request processing error, please contact administrator to check server configuration'}
    except Exception as e:
        # Catch all other exceptions
        error_trace = log_exception(e, "Unknown error in send_message")
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
    """Process client sent message, call API and return response
    
    This is the core function of the application, responsible for:
    1. Receiving user message
    2. Executing network search (if enabled)
    3. Calling Grok API to get reply
    4. Sending response back to client
    
    Parameters:
        data (dict): Dictionary containing user message and configuration
            - message: User message content
            - api_key: (Optional)API key
            - tavily_enabled: (Optional)Whether to enable network search
            - tavily_api_key: (Optional)Tavily API key
    """
    # Generate request ID for tracking and logging
    request_id = f"{datetime.now().strftime('%Y%m%d%H%M%S')}-{hash(str(data))}"
    logger.info(f'Processing message request [ID:{request_id}]')
    
    try:
        # Check conversation ID, get or create a unique identifier
        conversation_id = get_conversation_id()
        logger.debug(f'[ID:{request_id}] Conversation ID: {conversation_id}')
        
        # Check API key - Prioritize key from request, then session stored key
        api_key = data.get('api_key') or user_api_keys.get(request.sid)
        if not api_key:
            logger.error(f'[ID:{request_id}] API key not set')
            socketio.emit('error', {'message': 'Please set your API key first'}, room=request.sid)
            return

        # Record key request information for debugging
        logger.debug(f'[ID:{request_id}] API URL: {API_URL}')
        logger.debug(f'[ID:{request_id}] Message length: {len(data.get("message", ""))} chars')
        
        # Update user API key to session storage
        user_api_keys[request.sid] = api_key
        
        # Process Tavily search settings - Update user preferences
        if 'tavily_enabled' in data:
            user_tavily_settings[request.sid] = data.get('tavily_enabled')
        if 'tavily_api_key' in data and data.get('tavily_api_key'):
            user_tavily_api_keys[request.sid] = data.get('tavily_api_key')

        # Message length check - Limit long messages to prevent large requests
        if len(data.get('message', '')) > 4000:
            logger.warning(f'[ID:{request_id}] Message too long: {len(data.get("message", ""))} chars')
            socketio.emit('error', {'message': 'Message too long, please shorten your message'}, room=request.sid)
            return

        # Build user message object
        user_message = {
            'role': 'user',
            'content': data['message'],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        # Get current conversation message history
        current_messages = []
        try:
            logger.debug(f'[ID:{request_id}] Retrieving conversation messages')
            current_messages = list(session_manager.get_conversation_messages(conversation_id))
            logger.debug(f'[ID:{request_id}] Current conversation message count: {len(current_messages)}')
        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to retrieve conversation messages')
            # Continue processing, use empty list as message history

        # Add user message to conversation history
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

        # Send message received confirmation to client
        socketio.emit('message_received', {
            'status': 'processing',
            'request_id': request_id
        }, room=request.sid)

        # Process Tavily search - If search feature is enabled
        search_results = None
        if user_tavily_settings.get(request.sid, False):
            tavily_api_key = user_tavily_api_keys.get(request.sid)
            if tavily_api_key:
                try:
                    logger.debug(f'[ID:{request_id}] Executing Tavily search')
                    search_results = get_tavily_search_results(data['message'], tavily_api_key)
                    if search_results and 'answer' in search_results:
                        logger.debug(f'[ID:{request_id}] Search results retrieved, length: {len(search_results["answer"])} chars')
                        # Send search success notification to client
                        socketio.emit('search_status', {
                            'status': 'success',
                            'message': 'Search results successfully retrieved',
                            'request_id': request_id
                        }, room=request.sid)
                    else:
                        logger.warning(f'[ID:{request_id}] Search results empty or missing answer field')
                        # Send search warning notification to client
                        socketio.emit('search_status', {
                            'status': 'warning',
                            'message': 'No search results found, will use model to answer directly',
                            'request_id': request_id
                        }, room=request.sid)
                except Exception as e:
                    error_trace = log_exception(e, f'[ID:{request_id}] Tavily search failed')
                    # Send search error notification to client
                    socketio.emit('search_status', {
                        'status': 'error',
                        'message': 'Search failed, will use model to answer directly',
                        'request_id': request_id
                    }, room=request.sid)
            else:
                logger.warning(f'[ID:{request_id}] Tavily search enabled but no API key set')
                # Send search configuration error notification
                socketio.emit('search_status', {
                    'status': 'error',
                    'message': 'Please set your Tavily API key first',
                    'request_id': request_id
                }, room=request.sid)

        # Build system message - Based on whether there are search results
        system_message = 'You are a helpful assistant.'
        if search_results and 'answer' in search_results:
            logger.debug(f'[ID:{request_id}] Building system message with search results')
            
            # Extract search results and context
            search_answer = search_results.get('answer', '')
            
            # Build search context content
            search_context = ""
            if 'context' in search_results and isinstance(search_results['context'], list):
                # Limit processed context items to avoid exceeding token limit
                context_items = search_results['context'][:5]
                logger.debug(f'[ID:{request_id}] Processing {len(context_items)} search context items')
                
                for i, item in enumerate(context_items):
                    if isinstance(item, dict):
                        # Organize context information, including content, URL, and title
                        content = item.get('content', '')
                        url = item.get('url', 'No URL')
                        title = item.get('title', 'No Title')
                        
                        if content:
                            search_context += f"\n\nSource {i+1}: {title}\nURL: {url}\n"
                            # Limit each context item length
                            if len(content) > 1000:
                                content = content[:1000] + "..."
                            search_context += f"{content}"
            
            # Build enhanced system prompt - Ensure format clear, search results highlighted
            system_message = f"""You are a helpful assistant with internet search capability. Below are search results for the user's query:

SEARCH RESULTS:
{search_answer}

ADDITIONAL CONTEXT:
{search_context}

INSTRUCTIONS:
1. Use the search results above to answer the user's question.
2. If the search results are relevant and up-to-date, prioritize this information over your training data.
3. If the search results are not relevant or incomplete, you can supplement with your knowledge.
4. Always cite sources when you use information from the search results.
5. Be concise and direct in your response.
6. If you don't know the answer, don't make up information."""

            logger.debug(f'[ID:{request_id}] System message built, contains search results and context, total length: {len(system_message)} chars')
        else:
            logger.debug(f'[ID:{request_id}] Using base system message, no search results')
            # Enhance base system message for clearer guidance
            system_message = """You are a helpful assistant. Please provide accurate, relevant, and helpful information in response to user queries. Be concise and direct in your answers. If you don't know something, admit it rather than making up information."""

        # Build API request message list - Optimize message order and deduplicate
        messages = [{'role': 'system', 'content': system_message}]
        
        # If there is conversation message history, add to system message
        if current_messages:
            messages.extend(current_messages)
        
        # Avoid adding duplicate user messages (if history already has current message)
        if not messages or messages[-1]['role'] != 'user' or messages[-1]['content'] != user_message['content']:
            messages.append(user_message)
            
        logger.debug(f'[ID:{request_id}] Preparing to send API request, total message count: {len(messages)}, includes system message: {system_message[:50]}...')

        # Call API to get reply
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

        # Check API response for errors
        if 'error' in response_data:
            logger.error(f'[ID:{request_id}] API returned error: {response_data["error"]}')
            socketio.emit('error', {
                'message': response_data['error'],
                'request_id': request_id
            }, room=request.sid)
            return

        # Verify API response format is as expected
        if not (response_data and 'response' in response_data and 'choices' in response_data['response']):
            logger.error(f'[ID:{request_id}] API response format not as expected: {json.dumps(response_data)}')
            socketio.emit('error', {
                'message': 'API response format error',
                'request_id': request_id
            }, room=request.sid)
            return

        # Process API successful response
        try:
            # Extract assistant reply, perform multi-layer verification
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

            # Get reply content
            assistant_message = message_obj['content']
            logger.debug(f'[ID:{request_id}] Successfully extracted assistant reply, length: {len(assistant_message)} chars')
            
            # Build assistant message object, prepare to add to conversation history
            assistant_message_obj = {
                'role': 'assistant',
                'content': assistant_message,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            # Add assistant reply to conversation history
            try:
                logger.debug(f'[ID:{request_id}] Attempting to add assistant reply to conversation')
                session_manager.add_message_to_conversation(conversation_id, assistant_message_obj)
                logger.debug(f'[ID:{request_id}] Assistant reply added to conversation')
            except Exception as e:
                error_trace = log_exception(e, f'[ID:{request_id}] Failed to add assistant reply')
                # Even if adding fails, try to return response to user

            # Send response to client
            logger.debug(f'[ID:{request_id}] Sending response to client')
            socketio.emit('response', {
                'message': assistant_message,
                'conversation_id': conversation_id,
                'response_time': round(response_data.get('response_time', 0), 2),
                'token_count': response_data.get('token_count', 0),
                'request_id': request_id
            }, room=request.sid)

            # Update conversation history list
            try:
                logger.debug(f'[ID:{request_id}] Updating conversation history')
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
                error_trace = log_exception(e, f'[ID:{request_id}] Failed to update conversation history')
                # Do not block main functionality

        except Exception as e:
            error_trace = log_exception(e, f'[ID:{request_id}] Failed to process API response')
            socketio.emit('error', {
                'message': 'Error processing response, please try again',
                'request_id': request_id
            }, room=request.sid)
            return

    except Exception as e:
        error_trace = log_exception(e, f'[ID:{request_id}] Main message processing flow error')
        socketio.emit('error', {
            'message': 'Unknown error occurred, please try again later',
            'request_id': request_id
        }, room=request.sid)

if __name__ == '__main__':
    from gevent import monkey
    monkey.patch_all()
    
    # Start cleanup task
    from threading import Thread
    cleanup_thread = Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()
    
    # Get port from environment variable, adapt to cloud platform requirements
    port = int(os.getenv('PORT', 10000))
    
    # Record startup information
    logger.info(f"Application starting on port: {port}")
    logger.info(f"API URL: {API_URL}")
    logger.info(f"Max conversations: {session_manager.max_conversations}")
    logger.info(f"Max messages per conversation: {session_manager.max_messages_per_conversation}")
    
    # In cloud environment, usually automatically assigned host and port
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port,
        debug=os.getenv('DEBUG', 'False').lower() == 'true'
    )