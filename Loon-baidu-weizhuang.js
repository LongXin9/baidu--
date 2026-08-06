/**
 * ==============================================================================
 * 脚本名称：百度免流 Custom 协议动态报头重写脚本 (日志集成与 Loon 语法修复版)
 * 适用平台：Loon (Custom 协议类型脚本)
 * 核心功能：当检测到访问目标为红果短剧或字节系域名时，自动向代理网关注入百度专属特征头
 * ==============================================================================
 */

// ==============================================================================
// 一、 全局状态常量定义 (Session State Constants)
// 作用：用于标记 TCP 连接在 HTTP CONNECT 握手过程中的各个阶段状态
// ==============================================================================

// 状态 -1：无效状态。表示连接未就绪、建立失败或已被断开重置
const HTTP_STATUS_INVALID = -1;

// 状态 0：TCP 连接已建立。此时已连上代理服务器，正在准备或已发送 HTTP CONNECT 伪装请求头
const HTTP_STATUS_CONNECTED = 0;

// 状态 1：等待响应。伪装请求头已成功发送给代理服务器，等待其返回 "HTTP/1.1 200 OK"
const HTTP_STATUS_WAITRESPONSE = 1;

// 状态 2：透传转发。代理握手完全成功，后续客户端与目标服务器的所有数据直接双向透传
const HTTP_STATUS_FORWARDING = 2;

// 日志统一前缀，方便在 Loon 日志过滤框中迅速定位
const LOG_PREFIX = "[BaiduProxy]";


// ==============================================================================
// 二、 目标域名匹配规则 (Domain Matcher)
// 作用：定义需要特殊注入百度特征头的域名关键字列表
// ==============================================================================

// 定义一个字符串数组，包含所有需要命中特殊伪装规则的域名关键字（字节系及红果短剧）
const HK_DOMAINS = [
    "zijie",    // 匹配字节跳动通用域名（如 *.zijieapi.com）
    "hongguo",  // 匹配红果短剧主域名
    "novel",    // 匹配番茄小说/短剧服务
    "pangolin", // 匹配穿山甲广告 SDK 域名
    "sigmob",   // 匹配移动广告联盟域名
    "amemv",    // 匹配抖音短视频 CDN 域名
    "douyin",   // 匹配抖音主域名及子域名
    "iesdouyin",// 匹配抖音 API 及后台服务域名
    "byteimg",  // 匹配字节系静态图片与资源 CDN 域名
    "toutiao",  // 匹配今日头条域名
    "ixigua",   // 匹配西瓜视频域名
    "snssdk",   // 匹配字节系通用 SDK 接口域名
    "bdurl"     // 匹配字节短网址服务域名
];

/**
 * 辅助函数：判断当前请求的目标 host 是否命中上面的关键字列表
 * @param {string} host - 从 Loon 环境获取的目标主机名（如 "v1-dy.byteimg.com"）
 * @return {boolean} - 如果命中包含关键字则返回 true，否则返回 false
 */
function isHongguoTarget(host) {
    // 安全保护：如果传入的 host 为 null、undefined 或空字符串，直接返回 false
    if (!host) return false;
    
    // 将传入的域名统一转为小写字母，防止因为大小写差异（如 "DouYin.com"）导致匹配失败
    const lowerHost = host.toLowerCase();
    
    // 使用数组的 .some() 方法遍历列表：只要有一个关键字被 lowerHost 包含（includes），即返回 true
    return HK_DOMAINS.some(domain => lowerHost.includes(domain));
}


// ==============================================================================
// 三、 Loon Session 生命周期回调函数 (Loon Lifecycle Callbacks)
// 作用：Loon 会在 TCP/TLS 连接建立的不同节点自动触发以下函数
// ==============================================================================

/**
 * 回调 1：TCP 底层连接成功触发
 * 当 Loon 与你设置的代理服务器成功建立 TCP 三次握手后，由 Loon 自动调用
 */
function tunnelDidConnected() {
    const target = `${$session.conHost}:${$session.conPort}`;
    console.log(`${LOG_PREFIX} ➔ [TCP Connected] Session connected to proxy, target: ${target}`);
    
    // 检查当前配置的代理服务器是否启用了 TLS 加密 (如 HTTPS 代理或 WSS 代理)
    if (!$session.proxy.isTLS) {
        console.log(`${LOG_PREFIX} [HTTP Mode] Plain TCP proxy detected, building fake header...`);
        // 如果是纯 HTTP 代理（没有 TLS），TCP 连上后立即调用函数写入 HTTP 伪装报头
        _writeHttpHeader();
        
        // 在当前会话上下文 ($session) 上记录当前状态为“已连接/已发头”
        $session.httpStatus = HTTP_STATUS_CONNECTED;
    } else {
        console.log(`${LOG_PREFIX} [TLS Mode] Underlayer TCP ready, waiting for TLS handshake...`);
    }
    
    // 返回 true 告诉 Loon 该步骤正常，继续往下执行
    return true;
}

/**
 * 回调 2：TLS 加密握手成功触发
 * 仅在 $session.proxy.isTLS 为 true 且与代理服务器完成 TLS 握手后由 Loon 调用
 */
function tunnelTLSFinished() {
    const target = `${$session.conHost}:${$session.conPort}`;
    console.log(`${LOG_PREFIX} ➔ [TLS Handshake Finished] Secure channel ready, target: ${target}`);
    
    // TLS 安全通道建立完毕，向代理服务器写入加密后的 HTTP 伪装报头
    _writeHttpHeader();
    
    // 在当前会话上标记状态为“已连接/已发头”
    $session.httpStatus = HTTP_STATUS_CONNECTED;
    
    // 返回 true 允许 Loon 继续后续流程
    return true;
}

/**
 * 回调 3：收到代理服务器发回的数据时触发
 * @param {ArrayBuffer|string} data - 代理服务器下发的数据块
 * @return {ArrayBuffer|string|null} - 处理后返回给客户端 App 的数据（返回 null 表示吞掉/拦截数据）
 */
function tunnelDidRead(data) {
    const target = `${$session.conHost}:${$session.conPort}`;
    
    // 读取当前会话的状态，判断是否正在“等待代理服务器回应 200 OK”
    if ($session.httpStatus === HTTP_STATUS_WAITRESPONSE) {
        // 走到这里说明 Loon 成功读取到了我们之前设定的结束符 "\r\n\r\n"（说明代理服务器接受了握手）
        console.log(`${LOG_PREFIX} ✔ [Handshake Success] HTTP CONNECT Handshake Success for ${target}`);
        console.log(`${LOG_PREFIX} [Tunnel Established] Intercepting 200 OK response header from client...`);
        
        // 将当前会话状态更新为“透传转发中”
        $session.httpStatus = HTTP_STATUS_FORWARDING;
        
        // 核心 API：通知 Loon 代理握手正式完毕，建立起客户端与目标服务器之间的逻辑通道
        $tunnel.established($session);
        
        // 关键点：返回 null 表示把代理服务器发回的 "HTTP/1.1 200 Connection Established" 响应头拦截掉
        // 不让它传给手机客户端 App，避免 App 被非标准的 HTTP 响应打断连接
        return null;
    } 
    
    // 正常数据传输阶段（或未命中 WAITRESPONSE 状态时）：将数据原样返回，让 Loon 传递给 App
    if ($session.httpStatus === HTTP_STATUS_FORWARDING) {
        return data;
    }
    
    // 关键修正：确保兜底返回原样数据，防止隐式返回 undefined 导致丢包
    return data;
}

/**
 * 回调 4：向代理服务器写入数据成功后触发
 * @return {boolean} - 返回 true 继续写回调，返回 false 则暂停后续写回调
 */
function tunnelDidWrite() {
    const target = `${$session.conHost}:${$session.conPort}`;
    
    // 判断当前是否处于“刚发完伪装请求头”的状态
    if ($session.httpStatus === HTTP_STATUS_CONNECTED) {
        console.log(`${LOG_PREFIX} ⬆ [Header Sent] Sent HTTP CONNECT Header Successfully to ${target}`);
        
        // 将状态标记切换为“正在等待代理服务器回复响应”
        $session.httpStatus = HTTP_STATUS_WAITRESPONSE;
        
        // 核心 API：指示 Loon 开始读取代理服务器发回的数据，直到遇到了 HTTP 头的标准结束符 "\r\n\r\n" 为止
        $tunnel.readTo($session, "\r\n\r\n");
        
        // 返回 false：暂时挂起写入回调，防止在握手没完成前触发后续数据写事件
        return false;
    }
    
    // 在透传阶段（HTTP_STATUS_FORWARDING）：正常返回 true，允许后续数据写入
    return true;
}

/**
 * 回调 5：会话关闭时触发
 * 当 TCP 连接断开、超时或用户主动中断连接时由 Loon 调用
 */
function tunnelDidClose() {
    const target = `${$session.conHost}:${$session.conPort}`;
    console.log(`${LOG_PREFIX} ✖ [Session Closed] Session disconnected or terminated, target: ${target}`);
    
    // 重置当前 session 的状态为 INVALID（无效）
    $session.httpStatus = HTTP_STATUS_INVALID;
    
    // 返回 true 允许 Loon 清理底层占用的 socket 资源
    return true;
}


// ==============================================================================
// 四、 核心报头构造与发送逻辑 (Header Builder)
// 作用：动态拼接伪装报头并写入 TCP 连接
// ==============================================================================

/**
 * 辅助函数：构造伪装 HTTP CONNECT 报头并发送给代理服务器
 */
function _writeHttpHeader() {
    // 从 Loon 当前会话中获取客户端实际想访问的目标主机名（如 "v1-dy.byteimg.com"）
    const conHost = $session.conHost;
    
    // 从 Loon 当前会话中获取客户端实际想访问的目标端口（HTTPS 默认为 443）
    const conPort = $session.conPort;
    
    // 调用前面的匹配函数，检测目标域名是否符合字节系/红果短剧特征
    const isHg = isHongguoTarget(conHost);

    // 声明一个变量 header 用于存储最终拼接完成的 HTTP 请求头文本
    let header = "";
    let modeName = "Standard Baidu Header";

    // 分支 1：如果是红果/字节系流量，注入全套百度高级特征头
    if (isHg) {
        modeName = "ByteDance / HongGuo Enhanced Header";
        // 按照标准 HTTP 格式逐行拼接字符串，\r\n 表示回车换行
        // 【关键修复】： Host 头部必须使用与 CONNECT 一致的真实域名和端口，不能硬编码 IP
        header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\n` +          // HTTP 代理握手请求行
                 `Host: ${conHost}:${conPort}\r\n` +                      // Host 字段，与实际目标相对应
                 `Proxy-Connection: Keep-Alive\r\n` +                    // 告知代理服务器保持代理长连接
                 `Connection: keep-alive\r\n` +                          // 告知目标服务器保持长连接
                 `X-T5-Auth: 683556433\r\n` +                            // 百度免流网关鉴权认证 Token
                 `User-Agent: baiduboxapp\r\n` +                          // 伪装 User-Agent 为百度 App
                 `X-Bd-Traceid: 0000000000000000000000000000000000000000\r\n` + // 注入百度内部链路追踪 ID 特征
                 `X-Bd-Product: BDUSS\r\n` +                             // 注入百度账号 Token 特征标记
                 `X-Bd-Uid: 0\r\n` +                                     // 注入百度用户 UID 特征
                 `Accept: */*\r\n` +                                     // 接受所有数据格式
                 `\r\n`;                                                 // 【关键】必须以连续两个 \r\n 结尾，表示 HTTP 头部结束
    } 
    // 分支 2：如果是普通目标域名，使用基础百度 App 伪装头
    else {
        // 【关键修复】： Host 头部保持与 CONNECT 目标严格一致
        header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\n` +          // 标准请求行
                 `Host: ${conHost}:${conPort}\r\n` +                      // 标准 Host
                 `Proxy-Connection: Keep-Alive\r\n` +                    // 保持代理长连接
                 `Connection: keep-alive\r\n` +                          // 保持长连接
                 `X-T5-Auth: 683556433\r\n` +                            // 基础鉴权 Token
                 `User-Agent: baiduboxapp\r\n` +                          // 基础 User-Agent 伪装
                 `\r\n`;                                                 // 头部结束符
    }

    // 打印当前生成的报文模式与内容预览日志
    console.log(`${LOG_PREFIX} ⚙ [Mode Selected: ${modeName}] -> Target: ${conHost}:${conPort} | isHg: ${isHg}`);
    console.log(`${LOG_PREFIX} 📝 [Header Preview]:\n${header.replace(/\r\n/g, " \\r\\n ")}`);

    // 核心 API：调用 Loon 底层的 $tunnel.write 方法，把拼接好的字符串报头通过网络发给代理服务器
    $tunnel.write($session, header);
}
