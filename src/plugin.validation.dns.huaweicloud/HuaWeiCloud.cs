using HuaweiCloud.SDK.Core;
using HuaweiCloud.SDK.Core.Auth;
using HuaweiCloud.SDK.Dns.V2;
using PKISharp.WACS.Clients.DNS;
using PKISharp.WACS.Plugins.Base.Capabilities;
using PKISharp.WACS.Plugins.Interfaces;
using PKISharp.WACS.Services;
using System;
using System.Linq;
using System.Net.Http;
using System.Runtime.Versioning;
using System.Threading.Tasks;

//Api Key: https://console.huaweicloud.com/iam/#/mine/accessKey
//Api Doc: https://console.huaweicloud.com/apiexplorer/#/openapi/DNS/debug
//DNS Region: https://console.huaweicloud.com/apiexplorer/#/endpoint/DNS
[assembly: SupportedOSPlatform("windows")]
namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    [IPlugin.Plugin<HuaWeiCloudOptions, HuaWeiCloudOptionsFactory, DnsValidationCapability, HuaWeiCloudJson>
        ("ec5a5198-7224-447e-aac5-99c2ccda78a1", "HuaWeiCloud", "Create verification records in HuaWeiCloud DNS")]
    public class HuaWeiCloud : DnsValidation<HuaWeiCloud>, IDisposable
    {
        private HuaWeiCloudOptions _options { get; }
        private SecretServiceManager _ssm { get; }
        private HttpClient _hc { get; }
        private HuaweiCloud.SDK.Dns.V2.DnsClient _client { get; }

        public HuaWeiCloud(
            HuaWeiCloudOptions options,
            SecretServiceManager ssm,
            IProxyService proxyService,
            LookupClientProvider dnsClient,
            ILogService log,
            ISettingsService settings) : base(dnsClient, log, settings)
        {
            _options = options;
            _ssm = ssm;
            _hc = proxyService.GetHttpClient();
            //GetValue
            var dnsRegion = _ssm.EvaluateSecret(_options.DnsRegion);
            var keyID = _ssm.EvaluateSecret(_options.KeyID);
            var keySecret = _ssm.EvaluateSecret(_options.KeySecret);
            //New Client
            var auth = new BasicCredentials(_ssm.EvaluateSecret(keyID), _ssm.EvaluateSecret(keySecret));
            var config = HttpConfig.GetDefaultConfig();
            config.IgnoreSslVerification = true;
            _client = HuaweiCloud.SDK.Dns.V2.DnsClient.NewBuilder()
                    .WithCredential(auth)
                    .WithRegion(DnsRegion.ValueOf(dnsRegion))
                    .WithHttpConfig(config)
                    .Build();
        }

        public override async Task<bool> CreateRecord(DnsValidationRecord record)
        {
            try
            {
                var identifier = GetDomain(record) ?? throw new($"The domain name cannot be found: {record.Context.Identifier}");
                var domain = record.Authority.Domain;
                var value = record.Value;
                //Add Record
                return await AddRecord(identifier, domain, value);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //Out Error
                _log.Error($"Unable to add HuaWeiCloudDNS record: {ex.Message}");
            }
            return false;
        }

        public override async Task DeleteRecord(DnsValidationRecord record)
        {
            try
            {
                var identifier = GetDomain(record) ?? throw new($"The domain name cannot be found: {record.Context.Identifier}");
                var domain = record.Authority.Domain;
                //Delete Record
                await DelRecord(identifier, domain);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                //Out Error
                _log.Error($"Unable to delete HuaWeiCloudDNS record: {ex.Message}");
            }
        }

        #region PrivateLogic

        /// <summary>
        /// Add Record
        /// </summary>
        /// <param name="domain">Domain</param>
        /// <param name="subDomain">SubDomain</param>
        /// <param name="value">Value</param>
        /// <returns></returns>
        private async Task<bool> AddRecord(string domain, string subDomain, string value)
        {
            //Delete Record
            var delRecord = await DelRecord(domain, subDomain);
            //Add Record
            var resp = _client.CreateRecordSetWithLine(new()
            {
                ZoneId = delRecord.Item1,
                Body = new()
                {
                    Records = new()
                    {
                        $"\"{value}\""
                    },
                    Type = "TXT",
                    Name = subDomain,
                }
            });
            //Console.WriteLine(resp.Recordsets);
            return true;
        }

        /// <summary>
        /// Delete Record
        /// </summary>
        /// <param name="domain">Domain</param>
        /// <param name="subDomain">SubDomain</param>
        /// <returns></returns>
        private async Task<(string?, bool)> DelRecord(string domain, string subDomain)
        {
            //Get RecordID
            var recordId = GetRecordID(domain, subDomain);
            while (recordId.Item2 != default)
            {
                //Delete Record
                var resp = _client.DeleteRecordSets(new()
                {
                    ZoneId = recordId.Item1,
                    RecordsetId = recordId.Item2
                });
                //Console.WriteLine(resp.Recordsets);
                await Task.Delay(300);
                recordId = GetRecordID(domain, subDomain);
            }
            return (recordId.Item1, true);
        }

        /// <summary>
        /// Get RecordID
        /// </summary>
        /// <param name="domain">Domain</param>
        /// <param name="subDomain">SubDomain</param>
        /// <returns></returns>
        private (string?, string?) GetRecordID(string domain, string? subDomain = default)
        {
            //domain
            var resp1 = _client.ListRecordSetsWithLine(new()
            {
                Type = "NS",
                Name = domain.TrimEnd('.'),
            });
            if (!resp1.Recordsets.Any()) throw new($"Domain: {domain}, Does not exist");
            var zoneId = resp1.Recordsets.First().ZoneId;
            //subDomain
            if (subDomain != default)
            {
                var resp2 = _client.ListRecordSetsWithLine(new()
                {
                    Type = "TXT",
                    Name = subDomain,
                });
                if (resp2.Recordsets.Any())
                {
                    var recordID = resp2.Recordsets.First().Id;
                    return (zoneId, recordID);
                }
            }
            return (zoneId, default);
        }

        /// <summary>
        /// Get Domain
        /// </summary>
        /// <param name="record">DnsValidationRecord</param>
        /// <returns></returns>
        private string? GetDomain(DnsValidationRecord record)
        {
            var resp = _client.ListRecordSetsWithLine(new()
            {
                Type = "NS"
            });
            //Console.WriteLine(resp.Recordsets);
            var myDomains = resp.Recordsets.Select(t => t.Name);
            var zone = FindBestMatch(myDomains.ToDictionary(x => x), record.Authority.Domain);
            if (zone != null) return zone;
            return default;
        }

        #endregion PrivateLogic

        public void Dispose() => _hc.Dispose();
    }
}
