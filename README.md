# Grok 3.0 API Chat Application

This is a Flask and SocketIO-based chat application for the Grok 3.0 API, optimized for cloud deployment (such as Render).

## Features

- Chat conversations using the Grok 3.0 API
- Tavily search integration for more accurate answers
- Conversation history management
- WebSocket configuration optimized for cloud environments
- Environment variable support for enhanced security and flexibility

## Cloud Deployment Guide

### Render Deployment Steps

1. Create a new Web Service on Render
2. Connect to your GitHub repository
3. Configure the following settings:
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn --worker-class eventlet -w 1 chat:app`

### Environment Variable Configuration

Add the following variables in the Render environment settings:

```
API_URL=https://api.x.ai/v1/chat/completions
MODEL_NAME=grok-3-beta
TEMPERATURE=0
SECRET_KEY=<generate a secure random key>
DEBUG=False
```

If you need to use the Tavily search feature, also add:
```
TAVILY_API_KEY=<your Tavily API key>
```

## Local Development

1. Clone the repository
2. Copy `.env.example` to `.env` and fill in the appropriate configuration
3. Install dependencies: `pip install -r requirements.txt`
4. Start the application: `python chat.py`

## Performance Optimization Notes

This application has been optimized for cloud environments with the following improvements:

1. **WebSocket Configuration Optimization**: Adjusted ping intervals and timeout settings for improved connection stability
2. **Memory Management**: Implemented automatic session cleanup to prevent memory leaks
3. **Enhanced Error Handling**: Added detailed logging and exception handling
4. **Environment Variable Support**: All key configurations can be set through environment variables
5. **Request Timeout and Retry**: Added timeout limits and retry mechanisms for API requests
6. **Port Adaptation**: Automatically adapts to the port assigned by the cloud platform

## Important Notes

- In production environments, ensure you set a secure `SECRET_KEY`
- The application uses in-memory storage for session data; for persistent storage, database integration is recommended
- Message length and conversation count are limited by default and can be adjusted as needed