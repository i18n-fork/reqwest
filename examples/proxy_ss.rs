//! This example shows how to use a Shadowsocks proxy with reqwest.
//!
//! It reads a list of `ss://` URLs from `~/.config/ss`, and then
//! concurrently tests each proxy by making a request to `https://ifconfig.me/ip`.
//!
//! The test results, including the response status and body, are printed to the console.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

// use futures::stream::{self, StreamExt}; // 不再需要并发处理
use reqwest::{Client, Proxy};
use url::Url;
use percent_encoding::percent_decode_str;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 设置日志级别
    std::env::set_var("RUST_LOG", "warn");
    env_logger::init();

    println!("Testing Shadowsocks proxies...");

    // 测试多个不同的 IP 检测服务（包括 HTTP 和 HTTPS）
    let test_urls = vec![
        ("https://ifconfig.me/ip", "HTTPS"),
        ("http://ifconfig.me/ip", "HTTP"),
    ];

    let proxy_ss_urls = find_proxy_ss_urls()?;

    if proxy_ss_urls.is_empty() {
        println!("No ss:// proxy found in ~/.config/ss");
        println!("Please add Shadowsocks proxy URLs to ~/.config/ss file");
        return Ok(())
    }


    // 获取本机真实IP（不使用代理）
    let direct_client = Client::builder()
        .no_proxy()
        .build()?;
    let mut real_ip = None;

    for (url, _protocol) in &test_urls {
        if let Ok(res) = direct_client.get(*url).send().await {
            if let Ok(body) = res.text().await {
                let ip = body.trim().to_string();
                if real_ip.is_none() && !ip.is_empty() && !ip.contains("Error") {
                    real_ip = Some(ip);
                    break;
                }
            }
        }
    }

    let real_ip = match real_ip {
        Some(ip) => {
            println!("Real IP: {}", ip);
            ip
        }
        None => {
            println!("Failed to get real IP");
            return Ok(())
        }
    };

    // 测试每个代理
    for (proxy_idx, proxy_url) in proxy_ss_urls.iter().enumerate() {
        println!("\nTesting proxy {} / {}...", proxy_idx + 1, proxy_ss_urls.len());

        // 解析代理 URL 以获取基本信息（不显示敏感信息）
        let parsed_url = match Url::parse(proxy_url) {
            Ok(url) => url,
            Err(e) => {
                println!("Failed to parse proxy URL: {}", e);
                continue;
            }
        };

        let server = parsed_url.host_str().unwrap_or("unknown");
        let port = parsed_url.port().unwrap_or(0);
        let name = parsed_url.fragment().unwrap_or("");
        // 显式进行 URL 解码
        let decoded_name = percent_decode_str(name).decode_utf8_lossy();
        println!("{}:{} {}", server, port, decoded_name);

        let proxy = match Proxy::all(proxy_url) {
            Ok(proxy) => proxy,
            Err(e) => {
                println!("Failed to create proxy: {}", e);
                continue;
            }
        };

        let client = match Client::builder()
            .proxy(proxy)
            .danger_accept_invalid_certs(true)
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                println!("Failed to create client: {}", e);
                continue;
            }
        };

        // 测试代理连接
        let mut test_result = None;

        for (test_url, protocol) in &test_urls {
            match client.get(*test_url).send().await {
                Ok(res) => {
                    let status = res.status();
                    if let Ok(body) = res.text().await {
                        let proxy_ip = body.trim();
                        test_result = Some((proxy_ip.to_string(), protocol, status));
                        break; // 成功获取结果，退出循环
                    }
                }
                Err(_) => continue, // 尝试下一个URL
            }
        }

        // 输出测试结果
        match test_result {
            Some((proxy_ip, protocol, status)) => {
                println!("Protocol: {} | Status: {} | Proxy IP: {} | Real IP: {}",
                    protocol, status, proxy_ip, real_ip);

                if proxy_ip == real_ip {
                    println!("Result: FAILED - Proxy not working (same IP)");
                } else {
                    println!("Result: SUCCESS - Proxy working (IP changed)");
                }
            }
            None => {
                println!("Result: FAILED - All requests failed");
            }
        }
    }

    Ok(())
}

fn find_proxy_ss_urls() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut path = PathBuf::from(std::env::var("HOME")?);
    path.push(".config/ss");

    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut urls = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("ss://") {
            urls.push(line);
        }
    }

    Ok(urls)
}