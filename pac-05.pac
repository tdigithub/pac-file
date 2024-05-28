function FindProxyForURL (url, host) {
    var resolved_ip = dnsResolve(host);
  
  	/* Bypass non-HTTP protocols */
  	if ((url.substring(0,5) != "http:") && (url.substring(0,6) != "https:"))
        return "DIRECT";

  	/* Bypass RFC1918 and Localhost */
    if (isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
        isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||
        isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
        isInNet(resolved_ip, "127.0.0.0", "255.255.255.0") ||
        shExpMatch(host, "*.local"))
        return "DIRECT";

   if (isInNet(myIpAddress(), "192.168.50.0”, "255.255.255.0”)) {
     return "PROXY 192.168.255.2:8080";
   } else {
     return "PROXY brosedev.proxy.prismaaccess.com:8080";
}
