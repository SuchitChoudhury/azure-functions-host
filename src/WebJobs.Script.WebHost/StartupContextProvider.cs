// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.Azure.WebJobs.Script.WebHost.Security;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json.Linq;

namespace Microsoft.Azure.WebJobs.Script.WebHost
{
    public class StartupContextProvider
    {
        private readonly IEnvironment _environment;
        private readonly ILogger _logger;
        private bool _loaded = false;
        private JObject _context;

        public StartupContextProvider(IEnvironment environment, ILogger<StartupContextProvider> logger)
        {
            _environment = environment;
            _logger = logger;
        }

        private JObject Context
        {
            get
            {
                if (!_loaded)
                {
                    _context = GetStartupContextOrNull();
                    _loaded = true;
                }
                return _context;
            }
        }

        public virtual HostSecretsInfo GetHostSecretsOrNull()
        {
            if (Context != null)
            {
                // TODO: make this code more robust
                HostSecretsInfo secretsInfo = new HostSecretsInfo();
                var hostSecrets = _context["secrets"]["host"];
                secretsInfo.MasterKey = (string)hostSecrets["master"];
                secretsInfo.FunctionKeys = ((JObject)hostSecrets["function"]).ToObject<Dictionary<string, string>>();
                secretsInfo.SystemKeys = ((JObject)hostSecrets["system"]).ToObject<Dictionary<string, string>>();

                _logger.LogDebug("Loaded host keys from startup context");

                return secretsInfo;
            }

            return null;
        }

        public virtual Dictionary<string, Dictionary<string, string>> GetFunctionSecretsOrNull()
        {
            if (Context != null)
            {
                // TODO: make this code more robust
                var functionKeys = new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);
                HostSecretsInfo secretsInfo = new HostSecretsInfo();
                var functionSecrets = _context["secrets"]["function"];
                foreach (JObject function in functionSecrets)
                {
                    var currKeys = ((JObject)function["secrets"]).ToObject<Dictionary<string, string>>();
                    functionKeys.Add((string)function["name"], currKeys);
                }

                _logger.LogDebug($"Loaded keys for {functionKeys.Keys.Count} functions from startup context");

                return functionKeys;
            }

            return null;
        }

        public virtual JObject GetStartupContextOrNull()
        {
            var contextPath = _environment.GetEnvironmentVariable(EnvironmentSettingNames.AzureWebsiteStartupContextCache);
            string content = null;
            if (!string.IsNullOrEmpty(contextPath))
            {
                try
                {
                    _logger.LogDebug($"Loading startup context from {contextPath}");
                    content = File.ReadAllText(contextPath);
                }
                catch (IOException ex)
                {
                    // best effort
                    _logger.LogError(ex, "Failed to load startup context");
                    return null;
                }
            }
            else
            {
                return null;
            }

            string decryptedContent = SimpleWebTokenHelper.Decrypt(content);
            JObject context = JObject.Parse(decryptedContent);

            return context;
        }
    }
}
