#!/usr/bin/env python3
from flask import Flask, render_template, session, request
from flask_socketio import SocketIO
import requests
import json
import os
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app)

API_URL = 'https://api.x.ai/v1/chat/completions'

# Store chat history, user API keys and Tavily settings
conversation_history = {}
user_api_keys = {}
user_tavily_settings = {}
user_tavily_api_keys = {}

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
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f'Tavily API Error: {str(e)}')
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
        return None
        
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }
    
    data = {
        'messages': messages,
        'model': 'grok-3-latest',
        'stream': False,
        'temperature': 0
    }
    
    start_time = datetime.now()
    try:
        response = requests.post(API_URL, headers=headers, json=data)
        response.raise_for_status()
        end_time = datetime.now()
        response_time = (end_time - start_time).total_seconds()
        response_data = response.json()
        token_count = calculate_tokens(messages)
        
        return {
            'response': response_data,
            'response_time': response_time,
            'token_count': token_count
        }
    except requests.exceptions.RequestException as e:
        print(f'Error: {str(e)}')
        return None

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
        user_api_keys[request.sid] = data['api_key']
    if 'tavily_api_key' in data:
        user_tavily_api_keys[request.sid] = data['tavily_api_key']
    if 'tavily_enabled' in data:
        user_tavily_settings[request.sid] = data['tavily_enabled']

@socketio.on('send_message')
def handle_message(data):
    conversation_id = get_conversation_id()
    
    # Check if API key is set
    api_key = user_api_keys.get(request.sid)
    if not api_key:
        socketio.emit('error', {'message': 'Please set your API key first'})
        return
    
    if conversation_id not in conversation_history:
        conversation_history[conversation_id] = {
            'messages': [],
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'title': data['message'][:30] + '...' if len(data['message']) > 30 else data['message']
        }
    
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

if __name__ == '__main__':
    socketio.run(app, port=5001, debug=True)