// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.AppService.Middleware.AspNetCoreMiddleware;
using Microsoft.Azure.WebJobs.Script.Middleware;
using Microsoft.Azure.WebJobs.Script.WebHost.Configuration;
using Microsoft.Extensions.Options;

namespace Microsoft.Azure.WebJobs.Script.WebHost.Middleware
{
    public class JobHostEasyAuthMiddleware : IJobHostHttpMiddleware
    {
        private RequestDelegate _invoke;

        public JobHostEasyAuthMiddleware(IOptions<HostEasyAuthOptions> hostEasyAuthOptions)
        {
            RequestDelegate contextNext = async context =>
            {
                if (context.Items.Remove(ScriptConstants.EasyAuthMiddlewareRequestDelegate, out object requestDelegate) && requestDelegate is RequestDelegate next)
                {
                    await next(context);
                }
            };
            //if easyauth is enabled, add those config values and add the middleware
            if (hostEasyAuthOptions.Value.IsEnabled)
            {
                var easyAuthMiddleware = new AppServiceMiddleware(contextNext);
                _invoke = easyAuthMiddleware.InvokeAsync;
            }
            // if not enabled, invoke without the middleware
            else
            {
                _invoke = contextNext;
            }
        }

        public async Task Invoke(HttpContext context, RequestDelegate next)
        {
            context.Items.Add(ScriptConstants.EasyAuthMiddlewareRequestDelegate, next);
            await _invoke(context);
        }
    }
}
