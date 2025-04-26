# Grok 3.0 API 聊天应用

这是一个基于Flask和SocketIO的Grok 3.0 API聊天应用，已优化用于云端部署（如Render）。

## 功能特点

- 使用Grok 3.0 API进行聊天对话
- 支持Tavily搜索集成，提供更准确的回答
- 会话历史管理
- 针对云端环境优化的WebSocket配置
- 环境变量支持，增强安全性和灵活性

## 云端部署指南

### Render部署步骤

1. 在Render上创建一个新的Web Service
2. 连接到您的GitHub仓库
3. 设置以下配置：
   - **环境**: Python 3
   - **构建命令**: `pip install -r requirements.txt`
   - **启动命令**: `gunicorn --worker-class eventlet -w 1 chat:app`

### 环境变量配置

在Render的环境变量设置中添加以下变量：

```
API_URL=https://api.x.ai/v1/chat/completions
MODEL_NAME=grok-3-latest
TEMPERATURE=0
SECRET_KEY=<生成一个安全的随机密钥>
DEBUG=False
```

如果需要使用Tavily搜索功能，还需添加：
```
TAVILY_API_KEY=<您的Tavily API密钥>
```

## 本地开发

1. 克隆仓库
2. 复制`.env.example`为`.env`并填写相应配置
3. 安装依赖：`pip install -r requirements.txt`
4. 启动应用：`python chat.py`

## 性能优化说明

本应用已进行以下优化，以适应云端环境：

1. **WebSocket配置优化**：调整了ping间隔和超时设置，提高了连接稳定性
2. **内存管理**：实现了会话自动清理机制，防止内存泄漏
3. **错误处理增强**：添加了详细的日志记录和异常处理
4. **环境变量支持**：所有关键配置都可通过环境变量设置
5. **请求超时和重试**：为API请求添加了超时限制和重试机制
6. **端口适配**：自动适应云平台分配的端口

## 注意事项

- 在生产环境中，请确保设置一个安全的`SECRET_KEY`
- 应用使用内存存储会话数据，如需持久化存储，建议集成数据库
- 默认限制了消息长度和会话数量，可根据需要调整