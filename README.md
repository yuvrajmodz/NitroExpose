## NitroExpose

**Letest Version:** 2.5  
**Developer:** @Nactire  
**Git Repo:** [NitroExpose](https://github.com/yuvrajmodz/NitroExpose)


## 🚀 Overview

**NitroExpose** is an advanced CLI tool that allows you to **instantly expose any local port to your custom domain,**  
**automatic SSL installation** Powered by Let's Encrypt.  

If You Don't Have Domain, No Problem We Also Provide Free Subdomain To Host Your Local Port Service On Subdomain With Https.

It provides a **one-command deployment system** for developers who want to run their local apps (Flask, FastAPI, Node.js, etc.) directly on a live domain without manually configuring NGINX or DNS records.


## ⚡ Key Features

• Easily Expose Your Local Port to Your Domain.  
• Automatic **NGINX** configuration  
• Automatic **SSL (Let's Encrypt)** installation  
• Required **Root (Sudo)** Environment  
• Intelligent error handling with Fast Speed.  
• Lightweight and Fast Completes setup in under 10 Sec


## 🛠️ System Requirements

- Python **3.8+**  
- **Ubuntu** or **Debian-based** System  
- **Root** or **Sudo** privileges  
- **apt** Package Manager Required


## 🌊 Module installation

```bash
pip install NitroExpose --break-system-packages
```

## 🧭 Usage Guide

Step 1 –  Point Your Vps/Server IP in Your Domain Records:  

**Type**:  A  
**Name**: *  
**IPv4**:   Your Vps Server IP  
**TTL**:   Auto  

Step 2 – **Launch NitroExpose**  
```bash
NitroExpose
```

Step 3 – **Enter Your Domain Or Subdomain**  
```bash
┌─╼ Enter Domain Or Subdomain
└────╼ ❯❯❯ myproject.example.com
```

Step 4 – **Enter Your Local Port to Expose**  
```bash
┌─╼ Enter Port To Expose
└────╼ ❯❯❯ 8000
```

✨ **Now it Will Take 8 to 9 Seconds For Verification And Then Boom! Your Local Port Successfully Exposed To Your Public Domain/Subdomain**.  


## 🎯 To Remove Domain/Subdomain

```bash
NitroExpose remove <domain/subdomain>
```

## 🎯 Domain/Subdomain Remove Example

```bash
NitroExpose remove myproject.example.com
```

## To Check Package Version

```bash
NitroExpose --v
```