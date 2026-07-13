using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using NUnit.Framework;
using Aliyun.OTS.Handler;

namespace Aliyun.OTS.UnitTest
{
    [TestFixture]
    class StsTest
    {
        private const string TestEndPoint = "http://test.cn-hangzhou.ots.aliyun.com:80";
        private const string TestAccessKeyID = "test-access-key-id";
        private const string TestAccessKeySecret = "test-access-key-secret";
        private const string TestInstanceName = "test-instance";
        private const string TestSecurityToken = "test-security-token-sts";

        /// <summary>
        /// Mock handler that captures the Context after HandleBefore, so we can inspect headers.
        /// </summary>
        class CapturingHandler : PipelineHandler
        {
            public Context CapturedContext;

            public override void HandleBefore(Context context)
            {
                CapturedContext = context;
            }

            public override void HandleAfter(Context context) { }
        }

        private static OTSClientConfig MakeConfig(string securityToken = null)
        {
            return new OTSClientConfig(
                TestEndPoint,
                TestAccessKeyID,
                TestAccessKeySecret,
                TestInstanceName,
                securityToken
            );
        }

        private static Context MakeContext(OTSClientConfig config)
        {
            return new Context
            {
                ClientConfig = config,
                APIName = "/ListTable",
                HttpRequestBody = new byte[] { }
            };
        }

        /// <summary>
        /// Compute the same HMAC-SHA1 signature that HttpHeaderHandler uses, given a set of headers and an API name.
        /// </summary>
        private static string ComputeExpectedSignature(
            Dictionary<string, string> headers, string apiName, string accessKeySecret)
        {
            var items = new List<string>();
            foreach (var item in headers)
            {
                if (item.Key.StartsWith("x-ots-"))
                {
                    items.Add(String.Format("{0}:{1}", item.Key, item.Value));
                }
            }
            items.Sort();
            string headerString = String.Join("\n", items);
            string signatureString = apiName + "\nPOST\n\n" + headerString + '\n';
            var hmac = new HMACSHA1(System.Text.Encoding.ASCII.GetBytes(accessKeySecret));
            byte[] hashValue = hmac.ComputeHash(System.Text.Encoding.ASCII.GetBytes(signatureString));
            return Convert.ToBase64String(hashValue);
        }

        [Test]
        public void HandleBefore_WithSecurityToken_AddsStsTokenHeader()
        {
            var config = MakeConfig(TestSecurityToken);
            var context = MakeContext(config);
            var capturing = new CapturingHandler();
            var handler = new HttpHeaderHandler(capturing);

            handler.HandleBefore(context);

            Assert.IsTrue(
                context.HttpRequestHeaders.ContainsKey("x-ots-ststoken"),
                "x-ots-ststoken header should be present when SecurityToken is set");
            Assert.AreEqual(TestSecurityToken, context.HttpRequestHeaders["x-ots-ststoken"]);
        }

        [Test]
        public void HandleBefore_WithoutSecurityToken_DoesNotAddStsTokenHeader()
        {
            var config = MakeConfig(null);
            var context = MakeContext(config);
            var capturing = new CapturingHandler();
            var handler = new HttpHeaderHandler(capturing);

            handler.HandleBefore(context);

            Assert.IsFalse(
                context.HttpRequestHeaders.ContainsKey("x-ots-ststoken"),
                "x-ots-ststoken header should NOT be present when SecurityToken is null");
        }

        [Test]
        public void HandleBefore_WithEmptySecurityToken_DoesNotAddStsTokenHeader()
        {
            var config = MakeConfig("");
            var context = MakeContext(config);
            var capturing = new CapturingHandler();
            var handler = new HttpHeaderHandler(capturing);

            handler.HandleBefore(context);

            Assert.IsFalse(
                context.HttpRequestHeaders.ContainsKey("x-ots-ststoken"),
                "x-ots-ststoken header should NOT be present when SecurityToken is empty");
        }

        [Test]
        public void HandleBefore_WithSecurityToken_SignatureIncludesStsToken()
        {
            var config = MakeConfig(TestSecurityToken);
            var context = MakeContext(config);
            var capturing = new CapturingHandler();
            var handler = new HttpHeaderHandler(capturing);

            handler.HandleBefore(context);

            var headers = context.HttpRequestHeaders;
            string expectedSignature = ComputeExpectedSignature(
                headers, context.APIName, TestAccessKeySecret);

            Assert.AreEqual(expectedSignature, headers["x-ots-signature"],
                "Signature must include x-ots-ststoken in HMAC computation");
        }

        [Test]
        public void HandleBefore_WithoutSecurityToken_SignatureDiffersFromWithToken()
        {
            var configWithToken = MakeConfig(TestSecurityToken);
            var contextWithToken = MakeContext(configWithToken);
            var handler1 = new HttpHeaderHandler(new CapturingHandler());
            handler1.HandleBefore(contextWithToken);

            var configWithoutToken = MakeConfig(null);
            var contextWithoutToken = MakeContext(configWithoutToken);
            var handler2 = new HttpHeaderHandler(new CapturingHandler());
            handler2.HandleBefore(contextWithoutToken);

            Assert.AreNotEqual(
                contextWithToken.HttpRequestHeaders["x-ots-signature"],
                contextWithoutToken.HttpRequestHeaders["x-ots-signature"],
                "Signatures must differ when STS token is present vs absent");
        }

        [Test]
        public void HandleBefore_StsTokenHeaderSortOrder()
        {
            var config = MakeConfig(TestSecurityToken);
            var context = MakeContext(config);
            var handler = new HttpHeaderHandler(new CapturingHandler());
            handler.HandleBefore(context);

            var keys = new List<string>(context.HttpRequestHeaders.Keys);
            int stsIndex = keys.IndexOf("x-ots-ststoken");
            int akidIndex = keys.IndexOf("x-ots-accesskeyid");
            int instanceIndex = keys.IndexOf("x-ots-instancename");

            Assert.IsTrue(stsIndex > akidIndex,
                "x-ots-ststoken should come after x-ots-accesskeyid");
            Assert.IsTrue(stsIndex < instanceIndex,
                "x-ots-ststoken should come before x-ots-instancename");
        }

        [Test]
        public void HandleBefore_WithSecurityToken_OtherHeadersStillPresent()
        {
            var config = MakeConfig(TestSecurityToken);
            var context = MakeContext(config);
            var handler = new HttpHeaderHandler(new CapturingHandler());
            handler.HandleBefore(context);

            var headers = context.HttpRequestHeaders;
            Assert.IsTrue(headers.ContainsKey("x-ots-contentmd5"));
            Assert.IsTrue(headers.ContainsKey("x-ots-date"));
            Assert.IsTrue(headers.ContainsKey("x-ots-apiversion"));
            Assert.IsTrue(headers.ContainsKey("x-ots-accesskeyid"));
            Assert.IsTrue(headers.ContainsKey("x-ots-instancename"));
            Assert.IsTrue(headers.ContainsKey("x-ots-user-agent"));
            Assert.IsTrue(headers.ContainsKey("x-ots-signature"));
        }

        [Test]
        public void HandleBefore_TrimsSecurityTokenWhitespace()
        {
            var config = MakeConfig("  " + TestSecurityToken + "  ");
            var context = MakeContext(config);
            var handler = new HttpHeaderHandler(new CapturingHandler());
            handler.HandleBefore(context);

            Assert.AreEqual(TestSecurityToken, context.HttpRequestHeaders["x-ots-ststoken"]);
        }
    }
}
