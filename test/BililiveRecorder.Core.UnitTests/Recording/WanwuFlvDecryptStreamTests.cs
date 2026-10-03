using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BililiveRecorder.Core.Recording;
using Xunit;

namespace BililiveRecorder.Core.UnitTests.Recording
{
    public class WanwuFlvDecryptStreamTests
    {
        // NIST SP 800-38A F.2.1 的 AES-128-CBC 向量，不依赖被测代码生成密文。
        private const string Key = "2b7e151628aed2a6abf7158809cf4f3c";
        private const string Iv = "000102030405060708090a0b0c0d0e0f";
        private static readonly byte[] Plain = ReadHex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        private static readonly byte[] Encrypted = ReadHex("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7");

        [Theory]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(7)]
        [InlineData(11)]
        [InlineData(16)]
        [InlineData(8192)]
        public async Task DecryptsTagsAcrossReadBoundariesAsync(int readSize)
        {
            using var input = new ChunkedStream(BuildFlv(true), readSize);
            using var stream = new WanwuFlvDecryptStream(input, $"encMode=5,encKey={Key},encIV={Iv}");
            using var output = new MemoryStream();
            await stream.CopyToAsync(output, readSize);
            Assert.Equal(BuildFlv(false), output.ToArray());
        }

        [Theory]
        [InlineData("hex")]
        [InlineData("base64")]
        public async Task DecodesPrefixedSecretsAsync(string encoding)
        {
            var key = encoding == "hex" ? Key : Convert.ToBase64String(ReadHex(Key));
            var iv = encoding == "hex" ? Iv : Convert.ToBase64String(ReadHex(Iv));
            using var stream = new WanwuFlvDecryptStream(new MemoryStream(BuildFlv(true)), $"encIV={encoding}:{iv},encKey={encoding}:{key},encMode=5");
            using var output = new MemoryStream();
            await stream.CopyToAsync(output);
            Assert.Equal(BuildFlv(false), output.ToArray());
        }

        [Fact]
        public void SynchronousReadPreservesTheFlv()
        {
            using var stream = new WanwuFlvDecryptStream(new ChunkedStream(BuildFlv(true), 1), $"encMode=5,encKey={Key},encIV={Iv}");
            using var output = new MemoryStream();
            stream.CopyTo(output);
            Assert.Equal(BuildFlv(false), output.ToArray());
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(6)]
        public void RejectsUnsupportedModes(int mode) => Assert.Throws<NotSupportedException>(() => new WanwuFlvDecryptStream(Stream.Null, $"encMode={mode},encKey={Key},encIV={Iv}"));

        private static byte[] BuildFlv(bool encrypted)
        {
            using var output = new MemoryStream();
            var header = ReadHex("464c5601050000000b123400000000");
            output.Write(header, 0, header.Length);
            var payload = (encrypted ? Encrypted : Plain).Concat(new byte[] { 17, 18, 19, 20, 21, 22, 23, 24, 25 }).ToArray();
            WriteTag(output, 18, 0, new byte[] { 1, 2, 3 });
            WriteTag(output, 8, 0, new byte[] { 175, 0 }.Concat(payload).ToArray());
            WriteTag(output, 9, 0, new byte[] { 23, 0, 0, 0, 0 }.Concat(payload).ToArray());
            WriteTag(output, 8, 0x01020304, new byte[] { 175, 1 }.Concat(payload).ToArray());
            var sei = new byte[] { 6 }.Concat(Plain).ToArray();
            var nalus = MakeNalu(new byte[] { 101 }.Concat(payload).ToArray()).Concat(MakeNalu(sei)).Concat(MakeNalu(new byte[] { 65 }.Concat(payload).ToArray()));
            WriteTag(output, 9, 0x01020315, new byte[] { 23, 1, 0, 0, 7 }.Concat(nalus).ToArray());
            WriteTag(output, 9, 0x01020340, new byte[] { 39, 1, 255, 255, 249 }.Concat(MakeNalu(new byte[] { 65 }.Concat(Plain).ToArray())).ToArray());
            WriteTag(output, 9, 0x01020341, new byte[] { 23, 2, 0, 0, 0 });
            WriteTag(output, 8, 0x01020342, new byte[] { 47 }.Concat(Plain).ToArray());
            return output.ToArray();
        }

        private static byte[] MakeNalu(byte[] body)
        {
            using var output = new MemoryStream();
            WriteBigEndian(output, body.Length, 4);
            output.Write(body, 0, body.Length);
            return output.ToArray();
        }

        private static void WriteTag(Stream output, byte type, int timestamp, byte[] body)
        {
            output.WriteByte(type);
            WriteBigEndian(output, body.Length, 3);
            WriteBigEndian(output, timestamp, 3);
            output.WriteByte((byte)(timestamp >> 24));
            WriteBigEndian(output, 0, 3);
            output.Write(body, 0, body.Length);
            WriteBigEndian(output, 11 + body.Length, 4);
        }

        private static void WriteBigEndian(Stream output, int value, int count)
        {
            for (var i = count - 1; i >= 0; i--)
                output.WriteByte((byte)(value >> (i * 8)));
        }

        private static byte[] ReadHex(string value) => Enumerable.Range(0, value.Length / 2).Select(x => Convert.ToByte(value.Substring(x * 2, 2), 16)).ToArray();

        private sealed class ChunkedStream : MemoryStream
        {
            private readonly int readSize;

            public ChunkedStream(byte[] buffer, int readSize) : base(buffer)
            {
                this.readSize = readSize;
            }

            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) => base.ReadAsync(buffer, offset, Math.Min(count, this.readSize), cancellationToken);
        }
    }
}
