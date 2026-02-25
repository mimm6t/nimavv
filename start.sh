#!/bin/bash

echo "🚀 gvbyh-rust 快速启动"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 检查二进制文件
if [ ! -f "target/release/gvbyh-server" ] || [ ! -f "target/release/gvbyh-client" ]; then
    echo "⚠️  未找到编译后的二进制文件"
    echo "正在编译..."
    cargo build --release --bin gvbyh-server --bin gvbyh-client
    echo ""
fi

echo "请选择运行模式:"
echo "1) 启动服务端"
echo "2) 启动客户端"
echo "3) 同时启动（测试模式）"
echo ""
read -p "请输入选项 [1-3]: " choice

case $choice in
    1)
        echo ""
        echo "🖥️  启动服务端..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "端口选择策略："
        echo "  1. 优先使用邮件端口: 25, 587, 465, 143, 993, 110, 995"
        echo "  2. 如果被占用，随机使用 10111-55535"
        echo ""
        ./target/release/gvbyh-server \
            --worker-url http://mirrors.ustc.ip-ddns.com \
            --log-level info
        ;;
    2)
        echo ""
        echo "💻 启动客户端..."
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ./target/release/gvbyh-client \
            --worker-url http://mirrors.ustc.ip-ddns.com \
            --socks5 127.0.0.1:1080 \
            --log-level info
        ;;
    3)
        echo ""
        echo "🔄 测试模式：同时启动服务端和客户端"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "启动服务端（后台）..."
        ./target/release/gvbyh-server \
            --worker-url http://mirrors.ustc.ip-ddns.com \
            --log-level info &
        SERVER_PID=$!
        
        sleep 3
        
        echo "启动客户端..."
        ./target/release/gvbyh-client \
            --worker-url http://mirrors.ustc.ip-ddns.com \
            --socks5 127.0.0.1:1080 \
            --log-level info &
        CLIENT_PID=$!
        
        echo ""
        echo "✅ 服务已启动"
        echo "   服务端 PID: $SERVER_PID"
        echo "   客户端 PID: $CLIENT_PID"
        echo "   SOCKS5: 127.0.0.1:1080"
        echo ""
        echo "测试命令:"
        echo "  curl -x socks5h://127.0.0.1:1080 https://www.google.com"
        echo ""
        echo "按 Ctrl+C 停止所有服务"
        
        trap "kill $SERVER_PID $CLIENT_PID 2>/dev/null; echo ''; echo '✓ 已停止所有服务'; exit" INT TERM
        wait
        ;;
    *)
        echo "无效选项"
        exit 1
        ;;
esac
