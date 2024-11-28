﻿using PKISharp.WACS.Configuration;
using PKISharp.WACS.Configuration.Arguments;

namespace PKISharp.WACS.Plugins.ValidationPlugins.Dns
{
    public class HuaWeiCloudArguments : BaseArguments
    {
        public override string Name => "HuaWeiCloud";

        public override string Group => "Validation";

        public override string Condition => "--validation huaweicloud";

        [CommandLine(Description = "DNS Region\r\nRefer: https://console.huaweicloud.com/apiexplorer/#/endpoint/DNS", Secret = false)]
        public string? HuaWeiCloudDnsRegion { get; set; } = "cn-south-1";

        [CommandLine(Description = "Access KeyId for HuaWeiCloud.", Secret = true)]
        public string? HuaWeiCloudKeyID { get; set; }

        [CommandLine(Description = "Access KeySecret for HuaWeiCloud.", Secret = true)]
        public string? HuaWeiCloudKeySecret { get; set; }
    }
}
