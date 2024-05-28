function FindProxyForURL (url, host) {
    var resolved_ip = dnsResolve(host);
  
  	/* Bypass non-HTTP protocols */
  	if ((url.substring(0,5) != "http:") && (url.substring(0,6) != "https:"))
        return "DIRECT";

  	/* Bypass Cloud Identity Engine and Authentication Cache Service*/
    if (shExpMatch(host, "cloud-auth.de.apps.paloaltonetworks.com") ||
        shExpMatch(host, "*.acs.prismaaccess.com"))
        return "DIRECT";

  	/* Bypass PAC File Distribution and Prisma Access Portal */
    if (shExpMatch(host, "https://store.lab.swg.prismaaccess.com/pac/ppfdffnard/7d9dc480-3a35-44ed-b721-53ddbc1464cb.pac") ||
        shExpMatch(host, "https://github.com/tdigithub/pac-file/") ||
        shExpMatch(host, "*.lab.gpcloudservice.com") ||
        shExpMatch(host, "*.lab.swg.prismaaccess.com"))
        return "DIRECT";

  	/* Bypass RFC1918 and Localhost */
    if (isInNet(resolved_ip, "10.0.0.0", "255.0.0.0") ||
        isInNet(resolved_ip, "172.16.0.0", "255.240.0.0") ||
        isInNet(resolved_ip, "192.168.0.0", "255.255.0.0") ||
        isInNet(resolved_ip, "127.0.0.0", "255.255.255.0") ||
        shExpMatch(host, "*.local"))
        return "DIRECT";

     return "PROXY homelan.proxy.lab.prismaaccess.com:8080";
}
