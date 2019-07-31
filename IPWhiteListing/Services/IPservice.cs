using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;

namespace IPWhiteListing.Services
{
    public class IPWhiteListMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<IPWhiteListMiddleware> _logger;
        private readonly string _adminSafeList;

        public IPWhiteListMiddleware(
            RequestDelegate next,
            ILogger<IPWhiteListMiddleware> logger,
            string adminSafeList)
        {
            _adminSafeList = adminSafeList;
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
           
                var remoteIp = context.Connection.RemoteIpAddress;
                _logger.LogDebug($"Request from Remote IP address: {remoteIp}");

                string[] ip = _adminSafeList.Split(';');

                var bytes = remoteIp.GetAddressBytes();
                var badIp = true;
                foreach (var address in ip)
                {
                    var testIp = IPAddress.Parse(address);
                    if (testIp.GetAddressBytes().SequenceEqual(bytes))
                    {
                        badIp = false;
                        break;
                    }
                }

                if (badIp)
                {
                    _logger.LogInformation(
                        $"Forbidden Request from Remote IP address: {remoteIp}");
                    context.Response.StatusCode = 400;
                    return;
                }
         

            await _next.Invoke(context);
        }
    }
}
