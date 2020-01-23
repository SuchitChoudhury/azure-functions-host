// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Script.WebHost.Configuration;
using Microsoft.Azure.WebJobs.Script.WebHost.Middleware;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Microsoft.Azure.WebJobs.Script.Tests.Middleware
{
    public class EasyAuthConfigurationMiddlewareTests
    {
        [Fact]
        public async Task Invoke_EasyAuthEnabled_ShouldSucceed()
        {
            var easyAuthSettings = new HostEasyAuthOptions
            {
                SiteAuthClientId = "id",
                SiteAuthEnabled = true
            };

            var easyAuthOptions = new OptionsWrapper<HostEasyAuthOptions>(easyAuthSettings);

            bool nextInvoked = false;
            RequestDelegate next = (ctxt) =>
            {
                nextInvoked = true;
                ctxt.Response.StatusCode = (int)HttpStatusCode.Accepted;
                return Task.CompletedTask;
            };

            var middleware = new JobHostEasyAuthMiddleware(easyAuthOptions);
            var httpContext = new DefaultHttpContext();
            await middleware.Invoke(httpContext, next);

            Assert.True(nextInvoked);
            // TODO - assertions for easy auth settings passed in? or that easyauth succeeded generally?
        }

        // TODO - auth failure
    }
}
