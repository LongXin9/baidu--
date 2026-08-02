/**
 * 转换自 lua/backend-baidu.lua 的 Loon Custom 协议脚本
 * 功能：专门针对红果短剧及字节系域名动态构造百度特征头的 HTTP CONNECT 代理
 * 
 * [配置使用参考]
 * [Proxy]
 * BaiduHongguo = custom, 你的代理服务器IP, 端口, script-path=https://raw.githubusercontent.com/.../this_script.js
 */

// ==================== 全局状态常量定义 ====================
// 定义 TCP 会话在 HTTP 代理握手过程中的各种状态标志
let HTTP_STATUS_INVALID = -1     // 状态：无效/连接未就绪或已关闭
let HTTP_STATUS_CONNECTED = 0   // 状态：TCP 已经建立连接，准备或正在发送代理请求头
let HTTP_STATUS_WAITRESPONSE = 1 // 状态：代理请求头已成功发出，正在等待代理服务器返回 200 OK 响应
let HTTP_STATUS_FORWARDING = 2   // 状态：握手成功，进入正常的数据透传阶段

// 记录当前 Session 的 HTTP 状态，初始化为无效状态
var httpStatus = HTTP_STATUS_INVALID

// ==================== 目标域名匹配规则 ====================
// 红果短剧及字节跳动系视频/广告/CDN 域名的特征关键字列表
const HK_DOMAINS = [
    "zijie",     // 字节跳动相关域名
    "hongguo",   // 红果短剧
    "novel",     // 番茄小说/短剧相关域名
    "pangolin",  // 穿山甲广告 SDK
    "sigmob",    // 移动广告联盟平台
    "amemv",     // 抖音短视频相关 CDN
    "douyin",    // 抖音主域名
    "iesdouyin", // 抖音 API/服务域名
    "byteimg",   // 字节系图片/静态资源 CDN
    "toutiao",   // 今日头条
    "ixigua",    // 西瓜视频
    "snssdk",    // 字节系通用 SDK 接口
    "bdurl"      // 字节短网址服务
];

/**
 * 函数：判断当前访问的目标域名是否匹配红果/字节系特征
 * @param {string} host - 从 $session 中获取的目标主机名/域名
 * @return {boolean} - 若命中返回 true，否则返回 false
 */
function isHongguoTarget(host) {
    // 判空保护：如果域名不存在，直接返回 false
    if (!host) return false;
    
    // 将传入的域名统一转换为小写，防止因大小写混淆导致无法匹配
    const lowerHost = host.toLowerCase();
    
    // 遍历 HK_DOMAINS 数组，只要数组中有任意一个关键词被当前域名包含，即返回 true
    return HK_DOMAINS.some(domain => lowerHost.includes(domain));
}

// ==================== Loon Session 生命周期回调函数 ====================

/**
 * 生命周期回调 1：TCP 连接成功
 * 当 Loon 与代理服务器的底层 TCP 通道连接建立成功后，由 Loon 自动触发此函数
 */
function tunnelDidConnected() {
    // 在 Loon 控制台打印调试日志，输出当前访问的目标地址与端口
    console.log(`[BaiduProxy] Session connected to ${$session.conHost}:${$session.conPort}`);
    
    // 判断该代理配置是否启用了底层 TLS 加密
    if ($session.proxy.isTLS) {
        // 如果启用 TLS，此时 TCP 刚连上，还需等待 TLS 握手完成（交由 tunnelTLSFinished 处理）
    } else {
        // 如果是纯 HTTP 代理，直接调用自定义函数发送伪装请求头
        _writeHttpHeader();
        
        // 更新会话状态为“已连接/已发送请求头”
        httpStatus = HTTP_STATUS_CONNECTED;
    }
    
    // 返回 true 表示该阶段处理成功，通知 Loon 继续后续流程
    return true;
}

/**
 * 生命周期回调 2：TLS 握手完成
 * 仅在 $session.proxy.isTLS 为 true 且与代理服务器的加密握手成功后触发
 */
function tunnelTLSFinished() {
    // TLS 握手完毕，开始向代理服务器发送 HTTP CONNECT 握手包
    _writeHttpHeader();
    
    // 更新会话状态为“已连接/已发送请求头”
    httpStatus = HTTP_STATUS_CONNECTED;
    
    // 返回 true 允许继续
    return true;
}

/**
 * 生命周期回调 3：从代理服务器读取到数据
 * @param {ArrayBuffer|string} data - 代理服务器下发的数据块
 * @return {ArrayBuffer|string|null} - 返回给客户端的数据（返回 null 则丢弃/不传给客户端）
 */
function tunnelDidRead(data) {
    // 如果当前处于“等待代理服务器回应 CONNECT”的状态
    if (httpStatus === HTTP_STATUS_WAITRESPONSE) {
        // 走到这里说明已经读取到了我们在 tunnelDidWrite 中指定的结束符 (\r\n\r\n)
        console.log("[BaiduProxy] HTTP CONNECT Handshake Success");
        
        // 将状态切换为“透传转发中”
        httpStatus = HTTP_STATUS_FORWARDING;
        
        // 核心步骤：调用 $tunnel.established() 告知 Loon 代理协议建立完毕，开启数据双向直通
        $tunnel.established($session);
        
        // 返回 null 表示将代理服务器返回的 HTTP/1.1 200 Connection Established 响应头“拦截/吞掉”，不转发给 App
        return null;
    } 
    // 如果当前已经是正常的数据透传阶段
    else if (httpStatus === HTTP_STATUS_FORWARDING) {
        // 保持数据原样返回，让 Loon 将其正常传递给发出请求的 App
        return data;
    }
}

/**
 * 生命周期回调 4：向代理服务器写入数据成功
 * 当发送数据给代理服务器的操作完成时由 Loon 调用
 * @return {boolean} - 返回 true 继续写回调，返回 false 中断写回调
 */
function tunnelDidWrite() {
    // 如果是在“已连接”状态下完成的第一次写入（即刚才发出了 HTTP CONNECT 伪装头）
    if (httpStatus === HTTP_STATUS_CONNECTED) {
        console.log("[BaiduProxy] Sent HTTP CONNECT Header Successfully");
        
        // 将状态标记为“等待代理服务器返回响应”
        httpStatus = HTTP_STATUS_WAITRESPONSE;
        
        // 核心步骤：指示 $tunnel 开始读取代理服务器的数据，直到遇到 HTTP 头的结束标记 "\r\n\r\n"
        $tunnel.readTo($session, "\r\n\r\n");
        
        // 返回 false 用于暂时中断写回调，在握手响应没收到前不触发后续写事件
        return false;
    }
    
    // 其他阶段（透传阶段）正常返回 true，允许后续写入
    return true;
}

/**
 * 生命周期回调 5：会话关闭
 * 当 TCP 连接断开或被用户强制终止时调用
 */
function tunnelDidClose() {
    // 将状态重置为无效，释放相关标记
    httpStatus = HTTP_STATUS_INVALID;
    
    // 返回 true 允许清理资源
    return true;
}

// ==================== 核心辅助工具函数 ====================

/**
 * 工具函数：构造并发送针对百度免流网关的 HTTP CONNECT 伪装请求头
 */
function _writeHttpHeader() {
    // 获取当前客户端真正要访问的目标域名（例如：v1-dy.byteimg.com）
    const conHost = $session.conHost;
    
    // 获取当前客户端真正要访问的目标端口（通常 HTTPS 为 443）
    const conPort = $session.conPort;
    
    // 调用先前定义的匹配逻辑，检测目标域名是否属于“红果短剧/字节系”
    const isHg = isHongguoTarget(conHost);

    // 用于保存最终生成的请求头字符串
    let header = "";

    // 针对红果短剧及字节系流量进行特殊伪装分支
    if (isHg) {
        // 拼接包含完整百度内部服务特征（BDUSS, Bd-Traceid, Bd-Uid 等）的 CONNECT 请求头
        header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\n` +
                 `Host: 153.3.236.22:443\r\n` +
                 `Proxy-Connection: Keep-Alive\r\n` +
                 `Connection: keep-alive\r\n` +
                 `X-T5-Auth: 683556433\r\n` +
                 `User-Agent: baiduboxapp\r\n` +
                 `X-Bd-Traceid: 0000000000000000000000000000000000000000\r\n` +
                 `X-Bd-Product: BDUSS\r\n` +
                 `X-Bd-Uid: 0\r\n` +
                 `Accept: */*\r\n` +
                 `\r\n`; // HTTP 报头必须以连续的两个换行符 \r\n\r\n 结尾
    } 
    // 普通目标域名的标准百度 App 伪装分支
    else {
        // 拼接基础的百度 App (baiduboxapp) 免流请求头
        header = `CONNECT ${conHost}:${conPort} HTTP/1.1\r\n` +
                 `Host: 153.3.236.22:443\r\n` +
                 `Proxy-Connection: Keep-Alive\r\n` +
                 `Connection: keep-alive\r\n` +
                 `X-T5-Auth: 683556433\r\n` +
                 `User-Agent: baiduboxapp\r\n` +
                 `\r\n`; // HTTP 报头必须以连续的两个换行符 \r\n\r\n 结尾
    }

    // 调用 Loon 底层的 $tunnel.write 方法，将构造好的伪装报头写入到代理服务器连接中
    $tunnel.write($session, header);
}
