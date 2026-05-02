cd "C:\Program Files\ZAP\Zed Attack Proxy"
.\zap.bat -daemon -port 9002 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true