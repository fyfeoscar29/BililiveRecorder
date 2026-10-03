using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace BililiveRecorder.Core.Recording
{
    internal sealed class WanwuFlvDecryptStream : Stream
    {
        private const int TagHeaderSize = 11;
        private readonly Stream innerStream;
        private readonly Aes aes;
        private byte[] buffer = new byte[13];
        private int bufferOffset;
        private int bufferLength;
        private bool headerRead;

        public WanwuFlvDecryptStream(Stream innerStream, string additionalParameter)
        {
            this.innerStream = innerStream;
            var parameters = additionalParameter.Split(',').Select(x => x.Split(new[] { '=' }, 2)).ToDictionary(x => x[0].Trim(), x => x[1].Trim());
            if (parameters["encMode"] != "5")
                throw new NotSupportedException("Wanwu only supports encMode=5.");

            var key = DecodeSecret(parameters["encKey"]);
            var iv = DecodeSecret(parameters["encIV"]);
            if (key.Length != 16 || iv.Length != 16)
                throw new CryptographicException("Wanwu AES key and IV must both be 16 bytes.");

            this.aes = Aes.Create();
            this.aes.Mode = CipherMode.CBC;
            this.aes.Padding = PaddingMode.None;
            this.aes.Key = key;
            this.aes.IV = iv;
        }

        public override bool CanRead => this.innerStream.CanRead;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() => this.innerStream.Flush();

#pragma warning disable VSTHRD002 // Stream.Read 必须同步，内部 await 均不捕获同步上下文。
        public override int Read(byte[] buffer, int offset, int count) => this.ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();
#pragma warning restore VSTHRD002

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            if (count == 0)
                return 0;
            if (this.bufferOffset == this.bufferLength && !await this.ReadNextAsync(cancellationToken).ConfigureAwait(false))
                return 0;

            var bytesRead = Math.Min(count, this.bufferLength - this.bufferOffset);
            Buffer.BlockCopy(this.buffer, this.bufferOffset, buffer, offset, bytesRead);
            this.bufferOffset += bytesRead;
            return bytesRead;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.aes.Dispose();
                this.innerStream.Dispose();
            }
            base.Dispose(disposing);
        }

        private async Task<bool> ReadNextAsync(CancellationToken cancellationToken)
        {
            var headerSize = this.headerRead ? TagHeaderSize : 9;
            var bytesRead = await this.innerStream.ReadAsync(this.buffer, 0, headerSize, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
                return false;
            await this.ReadExactlyAsync(bytesRead, headerSize - bytesRead, cancellationToken).ConfigureAwait(false);

            if (!this.headerRead && (this.buffer[0] != 'F' || this.buffer[1] != 'L' || this.buffer[2] != 'V'))
                throw new InvalidDataException("Invalid FLV header.");

            var dataSize = this.headerRead ? this.ReadBigEndian(1, 3) : this.ReadBigEndian(5, 4) - 9;
            this.bufferLength = headerSize + dataSize + 4;
            if (this.buffer.Length < this.bufferLength)
                Array.Resize(ref this.buffer, this.bufferLength);
            await this.ReadExactlyAsync(headerSize, dataSize + 4, cancellationToken).ConfigureAwait(false);

            var previousTagSize = this.headerRead ? TagHeaderSize + dataSize : 0;
            if (this.ReadBigEndian(this.bufferLength - 4, 4) != previousTagSize)
                throw new InvalidDataException("Invalid FLV PreviousTagSize.");
            if (this.headerRead)
                this.TransformTag(dataSize);

            this.headerRead = true;
            this.bufferOffset = 0;
            return true;
        }

        private async Task ReadExactlyAsync(int offset, int count, CancellationToken cancellationToken)
        {
            while (count > 0)
            {
                var bytesRead = await this.innerStream.ReadAsync(this.buffer, offset, count, cancellationToken).ConfigureAwait(false);
                if (bytesRead == 0)
                    throw new EndOfStreamException("Incomplete FLV tag.");
                offset += bytesRead;
                count -= bytesRead;
            }
        }

        private void TransformTag(int dataSize)
        {
            if (this.buffer[0] == 8 && dataSize >= 2 && this.buffer[11] >> 4 == 10 && this.buffer[12] <= 1)
            {
                this.Decrypt(13, dataSize - 2);
            }
            else if (this.buffer[0] == 9 && dataSize >= 5 && (this.buffer[11] & 15) == 7)
            {
                if (this.buffer[12] == 0)
                    this.Decrypt(16, dataSize - 5);
                else if (this.buffer[12] == 1 && this.buffer[11] >> 4 == 1)
                {
                    var offset = 16;
                    var end = TagHeaderSize + dataSize;
                    while (offset < end)
                    {
                        var length = this.ReadBigEndian(offset, 4);
                        offset += 4;
                        if (length <= 0 || length > end - offset)
                            throw new InvalidDataException("Invalid H.264 NAL length.");
                        if ((this.buffer[offset] & 31) != 6)
                            this.Decrypt(offset + 1, length - 1);
                        offset += length;
                    }
                }
            }
        }

        private void Decrypt(int offset, int count)
        {
            // 每次 AAC、AVC 配置或 NAL 变换重置 IV，不足一个 AES 块的尾部保持原样。
            count -= count % 16;
            if (count == 0)
                return;
            using var decryptor = this.aes.CreateDecryptor();
            var decrypted = decryptor.TransformFinalBlock(this.buffer, offset, count);
            Buffer.BlockCopy(decrypted, 0, this.buffer, offset, count);
        }

        private int ReadBigEndian(int offset, int count)
        {
            var value = 0;
            for (var i = 0; i < count; i++)
                value = (value << 8) | this.buffer[offset + i];
            return value;
        }

        private static byte[] DecodeSecret(string value)
        {
            if (value.StartsWith("base64:", StringComparison.Ordinal))
                return Convert.FromBase64String(value.Substring(7));
            if (value.StartsWith("hex:", StringComparison.Ordinal))
                value = value.Substring(4);
            else if (value.Length != 32 || !value.All(Uri.IsHexDigit))
                return Encoding.UTF8.GetBytes(value);

            if (value.Length != 32)
                throw new CryptographicException("Wanwu hex key and IV must both be 32 hex characters.");
            return Enumerable.Range(0, 16).Select(x => Convert.ToByte(value.Substring(x * 2, 2), 16)).ToArray();
        }
    }
}
